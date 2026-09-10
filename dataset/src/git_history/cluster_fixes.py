"""Semantic clustering of fix-commit messages.

Pipeline (see `cluster_fix_messages`):

1. Load the JSON produced by `git_history.fix_commits.collect_fix_commits`.
2. Embed each commit message (subject + first ~200 chars of body) with a
   sentence-transformers model — default ``BAAI/bge-small-en-v1.5`` — and
   L2-normalize the vectors. BGE models need no instruction prefix for
   symmetric semantic similarity, so raw text is encoded as-is.
3. Optionally reduce the embedding dimensionality with UMAP (BERTopic-style:
   a diffuse 384-dim cloud often only shows density structure after being
   squeezed to ~10 dims) — off unless ``reduce_dims=`` is passed.
4. Cluster with `sklearn.cluster.HDBSCAN` (density-based: the caller does
   NOT pick a cluster count).
5. Label each cluster (size >= 2) with its most distinctive TF-IDF terms.
6. Write/return a JSON report.

The embedding step is split from the clustering step so tests (and callers)
can inject a fake/deterministic embedder via ``embedding_model=`` instead of
downloading the real BGE model.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Protocol

import numpy as np
from sklearn.cluster import HDBSCAN
from sklearn.feature_extraction.text import TfidfVectorizer

DEFAULT_MODEL_NAME = "BAAI/bge-small-en-v1.5"

# Text construction.
_BODY_PREFIX_CHARS = 200  # how much of the body to append to the subject

# Sign-off / review trailer lines: metadata, not defect description.
_TRAILER_RE = re.compile(
    r"^(Signed-off-by|Co-authored-by|Reviewed-by|Reported-by|Acked-by|Tested-by|Cc):",
    re.IGNORECASE,
)


def _strip_trailers(body: str) -> str:
    """Drop `Signed-off-by:`-style trailer lines from a commit body."""
    kept = [line for line in body.splitlines() if not _TRAILER_RE.match(line)]
    return "\n".join(kept).strip()

# Report shaping.
_SAMPLE_SUBJECTS = 5  # max subjects echoed per cluster
_LABEL_TERMS = 5  # max distinctive terms in a cluster label
_EPS = 0.05  # smoothing for the in-vs-out TF-IDF contrast ratio

# Commit-message tokens: identifiers, hyphenated words, acronyms (>= 2 chars).
_TOKEN_PATTERN = r"(?u)\b[a-zA-Z][a-zA-Z0-9\-]*\b"

# UMAP defaults (only used when reduce_dims is requested).
_UMAP_NEIGHBORS = 15  # local manifold size; capped at n_samples - 1
_UMAP_MIN_DIST = 0.0  # pack points tightly -> denser clusters for HDBSCAN
_UMAP_SEED = 42  # random_state: disables UMAP parallelism for reproducibility


class EmbeddingModel(Protocol):
    """Minimal interface accepted for ``embedding_model`` (duck-typed).

    Anything with an ``encode(list[str]) -> array-like`` method works, e.g. a
    ``sentence_transformers.SentenceTransformer`` or a test fake.
    """

    def encode(self, sentences: list[str], **kwargs: Any) -> Any: ...


def _load_commits(path: Path) -> list[dict]:
    """Read the collect_fix_commits JSON and return its ``commits`` list."""
    data = json.loads(path.read_text(encoding="utf-8"))
    commits = data.get("commits", []) if isinstance(data, dict) else []
    if not isinstance(commits, list):
        raise ValueError(f"'commits' must be a list in {path}")
    return [c for c in commits if isinstance(c, dict)]


def _commit_text(commit: dict) -> str:
    """Text used for embedding: subject + first ~200 chars of cleaned body.

    Choice: the subject alone is often too terse (``fix: typo``, scopes,
    issue refs), while full bodies carry changelogs/backport footers that
    mostly add noise. The first ~200 chars of the body usually elaborate the
    actual defect, so subject + body-prefix balances signal and noise.
    Sign-off/review trailer lines (``Signed-off-by:`` & co) are stripped
    first — they name people, not defects, and measurably pollute cluster
    labels (e.g. a cluster labelled by committer names).
    """
    subject = str(commit.get("subject") or commit.get("message") or "").strip()
    body = _strip_trailers(str(commit.get("body") or ""))
    if body:
        return f"{subject}\n{body[:_BODY_PREFIX_CHARS]}".strip()
    return subject or f"commit {commit.get('hash', '?')}"


def _load_embedding_model(model_name: str) -> Any:
    """Load a SentenceTransformer, wrapping any failure in RuntimeError."""
    try:
        from sentence_transformers import SentenceTransformer
    except Exception as exc:  # pragma: no cover - import environment issue
        raise RuntimeError(
            f"failed to import sentence-transformers (needed for model '{model_name}'): {exc}"
        ) from exc
    try:
        return SentenceTransformer(model_name)
    except Exception as exc:
        raise RuntimeError(
            f"failed to load/download embedding model '{model_name}': {exc}"
        ) from exc


def _embed_texts(
    texts: list[str],
    *,
    model_name: str = DEFAULT_MODEL_NAME,
    embedding_model: EmbeddingModel | None = None,
) -> np.ndarray:
    """Embed ``texts`` into unit-length rows (L2-normalized, float64).

    BGE models take raw text (no instruction prefix for symmetric similarity)
    and support ``normalize_embeddings=True``; injected fakes may only
    implement ``encode(texts)``, in which case normalization is done here.
    """
    model = embedding_model if embedding_model is not None else _load_embedding_model(model_name)
    try:
        emb = np.asarray(
            model.encode(
                texts,
                normalize_embeddings=True,
                show_progress_bar=False,
                batch_size=64,
            ),
            dtype=np.float64,
        )
    except TypeError:  # minimal duck-typed model without extra kwargs
        emb = np.asarray(model.encode(texts), dtype=np.float64)
    norms = np.linalg.norm(emb, axis=1, keepdims=True)
    norms[norms == 0.0] = 1.0  # guard against all-zero vectors
    return emb / norms


def _reduce_dimensions(
    embeddings: np.ndarray,
    *,
    n_components: int,
    n_neighbors: int = _UMAP_NEIGHBORS,
    random_state: int = _UMAP_SEED,
) -> tuple[np.ndarray, str | None]:
    """Squeeze ``embeddings`` with UMAP; returns ``(data, reduction_label)``.

    BERTopic-style preprocessing before HDBSCAN: sentence embeddings of
    near-homogeneous messages (e.g. NPE fixes) form one diffuse cloud in
    384 dims where HDBSCAN finds a single density blob; UMAP's nonlinear
    manifold projection to ~10 dims tightens the sheet-like structure so
    density clusters can separate.

    ``min_dist=0.0`` packs points as closely as possible (denser clusters);
    ``random_state`` makes the projection reproducible (and single-threaded).

    Returns ``(embeddings, None)`` unchanged when there are too few points
    to reduce (``n <= n_components``) — callers record ``reduction: null``.

    Raises:
        RuntimeError: if ``umap-learn`` is not importable.
    """
    n = embeddings.shape[0]
    if n <= n_components:
        return embeddings, None
    try:
        from umap import UMAP
    except Exception as exc:
        raise RuntimeError(f"failed to import umap-learn (needed for reduce_dims): {exc}") from exc
    neighbors = max(2, min(n_neighbors, n - 1))
    reducer = UMAP(
        n_components=n_components,
        n_neighbors=neighbors,
        min_dist=_UMAP_MIN_DIST,
        metric="euclidean",
        random_state=random_state,
    )
    reduced = np.asarray(reducer.fit_transform(embeddings), dtype=np.float64)
    label = f"umap:{embeddings.shape[1]}d->{n_components}d(n_neighbors={neighbors},seed={random_state})"
    return reduced, label


def _cluster_embeddings(embeddings: np.ndarray, *, min_cluster_size: int = 5) -> np.ndarray:
    """Cluster unit vectors with HDBSCAN; returns one label per row (-1=noise).

    Metric choice: embeddings are L2-normalized, so euclidean distance is a
    strictly monotonic function of cosine distance (d_euc^2 = 2 - 2*cos).
    Clustering with ``metric="euclidean"`` is therefore equivalent to cosine
    on normalized data while allowing HDBSCAN's efficient tree-based
    neighborhood computations (cosine would force brute force). Density-based
    HDBSCAN needs no cluster count from the caller.
    """
    n = len(embeddings)
    if n < 2:  # nothing to cluster; HDBSCAN needs >= 2 samples
        return np.full(n, -1, dtype=int)
    return HDBSCAN(min_cluster_size=min_cluster_size, metric="euclidean").fit_predict(
        embeddings
    )


def _label_clusters(texts: list[str], labels: np.ndarray, *, max_terms: int = _LABEL_TERMS) -> dict[int, str]:
    """Distinctive-term label per cluster: TF-IDF contrast vs the rest.

    Score(term) = mean_in(term) * mean_in(term) / (mean_rest(term) + eps):
    terms must be frequent inside the cluster AND rare outside it, so common
    commit boilerplate ("fix", "issue", ...) never dominates the label.
    English stopwords are excluded by the vectorizer.
    """
    cluster_ids = sorted({int(l) for l in labels if l >= 0})
    if not cluster_ids:
        return {}
    vectorizer = TfidfVectorizer(stop_words="english", token_pattern=_TOKEN_PATTERN)
    matrix = vectorizer.fit_transform(texts).toarray()
    vocab = np.asarray(vectorizer.get_feature_names_out())
    result: dict[int, str] = {}
    for cid in cluster_ids:
        in_mask = labels == cid
        mean_in = matrix[in_mask].mean(axis=0)
        rest = matrix[~in_mask]
        mean_rest = rest.mean(axis=0) if rest.shape[0] else np.zeros_like(mean_in)
        scores = mean_in * mean_in / (mean_rest + _EPS)
        top = np.argsort(-scores)[:max_terms]
        terms = [str(vocab[i]) for i in top if mean_in[i] > 0.0]
        result[cid] = ", ".join(terms) if terms else f"cluster {cid}"
    return result


def _build_report(
    commits: list[dict], texts: list[str], labels: np.ndarray, *, model_name: str
) -> dict:
    """Assemble the JSON-serializable clustering report (clusters sorted by size desc)."""
    noise_hashes = [str(c.get("hash", "")) for c, lab in zip(commits, labels) if lab == -1]
    label_map = _label_clusters(texts, labels)
    clusters = []
    for cid in sorted(label_map):
        members = [c for c, lab in zip(commits, labels) if lab == cid]
        clusters.append(
            {
                "id": cid,
                "label": label_map[cid],
                "size": len(members),
                "hashes": [str(c.get("hash", "")) for c in members],
                "sample_subjects": [
                    str(c.get("subject") or "") for c in members[:_SAMPLE_SUBJECTS]
                ],
            }
        )
    clusters.sort(key=lambda cl: (-cl["size"], cl["id"]))  # size desc, id tiebreak
    return {
        "model": model_name,
        "input_count": len(commits),
        "n_clusters": len(clusters),
        "n_noise": len(noise_hashes),
        "clusters": clusters,
        "noise_hashes": noise_hashes,
    }


def cluster_fix_messages(
    commits_json_path: str | Path,
    output_path: str | Path,
    model_name: str = DEFAULT_MODEL_NAME,
    *,
    embedding_model: EmbeddingModel | None = None,
    min_cluster_size: int = 5,
    reduce_dims: int | None = None,
    umap_n_neighbors: int = _UMAP_NEIGHBORS,
    umap_random_state: int = _UMAP_SEED,
) -> dict:
    """Semantically cluster fix-commit messages and write a JSON report.

    Reads the JSON produced by ``collect_fix_commits`` (shape
    ``{"repo", "count", "commits": [{"hash", "subject", "body", "message"}]}``),
    embeds each commit's message (subject + first ~200 chars of body) with a
    sentence-transformers model, clusters the normalized embeddings with
    density-based HDBSCAN (no cluster count needed), labels each cluster of
    size >= 2 with its most distinctive TF-IDF terms, and writes a report to
    ``output_path`` (parent dirs created).

    Args:
        commits_json_path: input JSON from ``collect_fix_commits``.
        output_path: destination report JSON (overwritten).
        model_name: sentence-transformers model; the default
            ``BAAI/bge-small-en-v1.5`` encodes raw text (no BGE instruction
            prefix needed for symmetric similarity) with normalized output.
        embedding_model: optional pre-built model with an
            ``encode(list[str]) -> array-like`` method. When given, nothing is
            downloaded and ``model_name`` is only recorded in the report —
            this is how tests inject deterministic fake embedders.
        min_cluster_size: HDBSCAN density threshold (smallest grouping kept
            as a cluster); commits not fitting any cluster become "noise".
        reduce_dims: optional UMAP target dimensionality (e.g. 10) applied
            before HDBSCAN; ``None`` (default) keeps the raw embeddings.
            Needs the ``umap-learn`` package.
        umap_n_neighbors: UMAP local manifold size (only with reduce_dims).
        umap_random_state: UMAP seed for a reproducible projection.

    Returns:
        The report dict (same object written to ``output_path``):
        ``{"model", "reduction", "input_count", "n_clusters", "n_noise",
        "clusters": [{"id", "label", "size", "hashes", "sample_subjects"}],
        "noise_hashes"}`` with clusters sorted by size descending;
        ``reduction`` is ``null`` or a UMAP descriptor like
        ``"umap:384d->10d(n_neighbors=15,seed=42)"``.

    Raises:
        RuntimeError: if the embedding model cannot be imported, loaded, or
            downloaded (empty input never touches the model).
    """
    commits = _load_commits(Path(commits_json_path))

    if commits:
        texts = [_commit_text(c) for c in commits]
        embeddings = _embed_texts(texts, model_name=model_name, embedding_model=embedding_model)
        reduced, reduction_label = (
            _reduce_dimensions(
                embeddings, n_components=reduce_dims, n_neighbors=umap_n_neighbors, random_state=umap_random_state
            )
            if reduce_dims
            else (embeddings, None)
        )
        labels = _cluster_embeddings(reduced, min_cluster_size=min_cluster_size)
        report = _build_report(commits, texts, labels, model_name=model_name)
        report["reduction"] = reduction_label
    else:  # robustness: empty input -> empty report, no model load, no error
        report = {
            "model": model_name,
            "reduction": None,
            "input_count": 0,
            "n_clusters": 0,
            "n_noise": 0,
            "clusters": [],
            "noise_hashes": [],
        }

    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report
