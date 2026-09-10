"""Extraction and semantic clustering of null-pointer-exception (NPE) fix commits.

Pipeline (see `cluster_npe_commits`):

1. Load the JSON produced by ``git_history.fix_commits.collect_fix_commits``.
2. Keep only commits whose subject OR body mentions a null-pointer exception
   (see `extract_npe_commits` for the exact matching rules).
3. Embed / cluster / label the survivors with the exact machinery from
   ``git_history.cluster_fixes`` (sentence-transformers embeddings
   + HDBSCAN + TF-IDF contrast labels), so results stay comparable with the
   full fix-commit clustering. NPE commits are a small subset of all fixes,
   hence the smaller default ``min_cluster_size=3``.
4. Write/return a JSON report shaped like the ``cluster_fix_messages`` report
   plus NPE-specific fields (``matched_total`` and ``excluded_count``).

CLI: ``python -m git_history.npe_cluster <commits_json>
<output_json> [--min-cluster-size N]`` prints a human summary.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path

from .cluster_fixes import (
    DEFAULT_MODEL_NAME,
    EmbeddingModel,
    _build_report,
    _cluster_embeddings,
    _commit_text,
    _embed_texts,
    _load_commits,
    _reduce_dimensions,
)

# Explicit NPE spellings (case-insensitive), each mapped to the canonical term
# name reported in "matched_terms". Word boundaries keep ordinary words
# containing the letters "npe" out, and "nullable"/"nullability" never hit
# because they are single words that are not exactly "null".
NPE_TERM_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("NPE", re.compile(r"\bnpe(?:s|es)?\b", re.IGNORECASE)),
    ("null pointer", re.compile(r"\bnull\s+pointers?\b", re.IGNORECASE)),
    ("null-pointer", re.compile(r"\bnull-pointers?\b", re.IGNORECASE)),
    ("NullPointerException", re.compile(r"\bnullpointerexceptions?\b", re.IGNORECASE)),
)

# Canonical name for the contextual bare-"null" match (see _null_in_fix_context).
NULL_CONTEXT_TERM = "null (fix context)"

# Fix-indicating words that may promote a bare "null" to an NPE match when
# they appear within _NULL_WINDOW_WORDS of it in the same sentence.
_FIX_CONTEXT_WORDS = frozenset(
    """
    fix fixes fixed fixing
    avoid avoids avoided avoiding
    prevent prevents prevented preventing
    guard guards guarded guarding
    protect protects protected protecting
    handle handles handled handling
    check checks checked checking
    safe safety
    potential possible possibly
    defensive missing
    crash crashes crashed crashing
    deref dereference dereferences dereferenced dereferencing
    """.split()
)

# How many words on each side of a bare "null" (within its sentence) may still
# count as "adjacent" fix context. 2 keeps the required false positive
# "Align JSON null and empty handling" out (nearest fix word "handling" is 3
# words away from "null") while still catching "fix null check",
# "null safety", and "potential null problem" (distance 1).
_NULL_WINDOW_WORDS = 2

# Sentences are split on . ! ? ; and newlines — NOT on ':' or ',', so the
# conventional-commit prefix "fix: null check" stays a single sentence.
_SENTENCE_SPLIT_RE = re.compile(r"[.!?\n;]")
_WORD_RE = re.compile(r"[A-Za-z']+")

# Report shaping.
_TOP_CLUSTERS_IN_SUMMARY = 5


def _npe_text(commit: dict) -> str:
    """Text searched for NPE mentions: subject + body (message as fallback)."""
    subject = str(commit.get("subject") or "").strip()
    body = str(commit.get("body") or "").strip()
    if subject and body:
        return f"{subject}\n{body}"
    if subject or body:
        return subject or body
    return str(commit.get("message") or "")


def _null_in_fix_context(text: str) -> bool:
    """True if a bare ``null`` sits near fix-indicating context in its sentence.

    The text is split into sentences, each sentence into words; a ``null``
    matches when any word within ``_NULL_WINDOW_WORDS`` positions of it (same
    sentence) is a fix-indicating word (``fix``, ``check``, ``safety``,
    ``potential``, ...). A ``null`` directly followed by "pointer(s)" is
    skipped here because the explicit "null pointer"/"null-pointer" patterns
    already cover (and more precisely name) that occurrence.
    """
    for sentence in _SENTENCE_SPLIT_RE.split(text.lower()):
        words = _WORD_RE.findall(sentence)
        for i, word in enumerate(words):
            if word != "null":
                continue
            if i + 1 < len(words) and words[i + 1] in ("pointer", "pointers"):
                continue  # part of "null pointer" / "null-pointer" — named pattern
            lo = max(0, i - _NULL_WINDOW_WORDS)
            hi = min(len(words), i + _NULL_WINDOW_WORDS + 1)
            if any(w in _FIX_CONTEXT_WORDS for w in words[lo:hi]):
                return True
    return False


def _match_npe_terms(text: str) -> list[str]:
    """Canonical NPE terms found in ``text`` (pattern order, deduplicated)."""
    terms = [name for name, pattern in NPE_TERM_PATTERNS if pattern.search(text)]
    if _null_in_fix_context(text):
        terms.append(NULL_CONTEXT_TERM)
    return terms


def _match_npe_commits(commits: list[dict]) -> list[dict]:
    """Keep commits whose subject/body matches the NPE patterns.

    Returns shallow copies of the matching commit dicts, each annotated with
    ``"matched_terms": [term, ...]`` listing which patterns hit.
    """
    matched: list[dict] = []
    for commit in commits:
        terms = _match_npe_terms(_npe_text(commit))
        if terms:
            item = dict(commit)
            item["matched_terms"] = terms
            matched.append(item)
    return matched


def extract_npe_commits(commits_json_path: str | Path) -> list[dict]:
    """Extract the null-pointer-exception (NPE) commits from a fix-commits JSON.

    Reads the JSON produced by ``collect_fix_commits`` and returns the commits
    whose subject OR body (case-insensitive) matches an NPE pattern.

    Matching rules (see ``NPE_TERM_PATTERNS`` and ``_null_in_fix_context``):

    1. ``NPE`` as a whole word, optionally plural — ``\\bnpe(?:s|es)?\\b``.
    2. ``null pointer`` (any whitespace between the words), optionally plural.
    3. ``null-pointer`` (hyphenated), optionally plural.
    4. ``NullPointerException`` as one word, optionally plural.
    5. A bare ``null`` ONLY when a fix-indicating word (fix/avoid/prevent/
       guard/protect/handle/check/safety/potential/possible/crash/deref/...)
       appears within 2 words of it in the same sentence (sentences split on
       ``. ! ? ;`` and newlines; a ``null`` followed by "pointer" is left to
       rules 2/3).

    Matched subject examples::

        "fix: NPE when config center is absent"      -> ["NPE"]
        "Fix NPEs reported on shutdown"               -> ["NPE"]
        "fix: resolve Null Pointer Exception ..."     -> ["null pointer"]
        "fix null-pointer dereference in URL concat"  -> ["null-pointer"]
        "Fix NullPointerException on lookup"          -> ["NullPointerException"]
        "fix: add null check in getConfig"            -> ["null (fix context)"]
        "null safety in attachment processing"        -> ["null (fix context)"]
        "fix potential null problem on lookup"        -> ["null (fix context)"]

    Unmatched subject examples (false positives that must NOT match)::

        "Align JSON null and empty handling"      # bare null; "handling" is 3 words away
        "fix: rename nullable variable"           # "nullable" is not the word "null"
        "feat: support null literal in exprs"     # bare null without fix context

    Returns:
        The matching commit dicts (input order), each a shallow copy
        annotated with ``"matched_terms"`` listing the canonical terms that
        hit, e.g. ``{"hash", "subject", "body", "message",
        "matched_terms": ["NPE", "null (fix context)"]}``.
    """
    commits = _load_commits(Path(commits_json_path))
    return _match_npe_commits(commits)


def cluster_npe_commits(
    commits_json_path: str | Path,
    output_path: str | Path,
    model_name: str = DEFAULT_MODEL_NAME,
    *,
    embedding_model: EmbeddingModel | None = None,
    min_cluster_size: int = 3,
    reduce_dims: int | None = None,
    umap_n_neighbors: int = 15,
    umap_random_state: int = 42,
) -> dict:
    """Extract NPE commits, cluster them semantically, and write a JSON report.

    Runs `extract_npe_commits` on the input JSON, then embeds (subject +
    first ~200 chars of body), clusters (density-based HDBSCAN), and labels
    (distinctive TF-IDF terms) the matched commits with the same machinery as
    ``cluster_fix_messages``. NPE fixes are a small subset of all fixes, so
    the default ``min_cluster_size`` is 3 instead of 5.

    Args:
        commits_json_path: input JSON from ``collect_fix_commits``.
        output_path: destination report JSON (parent dirs are created).
        model_name: sentence-transformers model; the default
            ``BAAI/bge-small-en-v1.5`` needs no download when cached.
        embedding_model: optional pre-built model with an
            ``encode(list[str]) -> array-like`` method; when given, nothing
            is downloaded and ``model_name`` is only recorded (test hook).
        min_cluster_size: HDBSCAN density threshold; unmatched-commit-tail
            rows become "noise".
        reduce_dims: optional UMAP target dimensionality (e.g. 10) applied
            before HDBSCAN — recommended for NPE subsets, which are few and
            semantically homogeneous, so the raw 384-dim cloud usually
            collapses into one giant cluster; ``None`` disables reduction.
        umap_n_neighbors / umap_random_state: UMAP knobs (only with
            reduce_dims); the seed keeps the projection reproducible.

    Returns:
        The report dict (same object written to ``output_path``): the
        ``cluster_fix_messages`` schema —
        ``{"model", "input_count", "n_clusters", "n_noise",
        "clusters": [{"id", "label", "size", "hashes", "sample_subjects"}],
        "noise_hashes"}`` — where ``input_count`` is the number of *matched*
        commits actually clustered, plus:

        * ``matched_total`` (int): commits matching the NPE patterns.
        * ``excluded_count`` (int): commits that did NOT match.

    Raises:
        RuntimeError: if the embedding model cannot be imported, loaded, or
            downloaded (empty matches never touch the model).
    """
    all_commits = _load_commits(Path(commits_json_path))
    commits = _match_npe_commits(all_commits)
    excluded_count = len(all_commits) - len(commits)

    if commits:
        texts = [_commit_text(c) for c in commits]
        embeddings = _embed_texts(texts, model_name=model_name, embedding_model=embedding_model)
        reduced, reduction_label = (
            _reduce_dimensions(
                embeddings,
                n_components=reduce_dims,
                n_neighbors=umap_n_neighbors,
                random_state=umap_random_state,
            )
            if reduce_dims
            else (embeddings, None)
        )
        labels = _cluster_embeddings(reduced, min_cluster_size=min_cluster_size)
        report = _build_report(commits, texts, labels, model_name=model_name)
        report["reduction"] = reduction_label
    else:  # no NPE commits -> empty report, no model load, no error
        report = {
            "model": model_name,
            "reduction": None,
            "input_count": 0,
            "n_clusters": 0,
            "n_noise": 0,
            "clusters": [],
            "noise_hashes": [],
        }

    report["matched_total"] = len(commits)
    report["excluded_count"] = excluded_count

    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


def main(argv: list[str] | None = None) -> int:
    """CLI: extract + cluster NPE fix commits and print a human summary."""
    parser = argparse.ArgumentParser(
        prog="python -m git_history.npe_cluster",
        description="Extract NPE-related fix commits and cluster them semantically.",
    )
    parser.add_argument("commits_json", help="input JSON produced by collect_fix_commits")
    parser.add_argument("output_json", help="destination report JSON (overwritten)")
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL_NAME,
        help=f"sentence-transformers model name (default: {DEFAULT_MODEL_NAME})",
    )
    parser.add_argument(
        "--min-cluster-size",
        type=int,
        default=3,
        help="HDBSCAN minimum cluster size (default: 3)",
    )
    parser.add_argument(
        "--reduce-dims",
        type=int,
        default=None,
        metavar="N",
        help="UMAP-reduce embeddings to N dims (e.g. 10) before HDBSCAN; "
        "recommended for small homogeneous NPE subsets; needs umap-learn",
    )
    parser.add_argument(
        "--umap-neighbors",
        type=int,
        default=15,
        metavar="K",
        help="UMAP n_neighbors when --reduce-dims is given (default: 15)",
    )
    args = parser.parse_args(argv)

    report = cluster_npe_commits(
        args.commits_json,
        args.output_json,
        model_name=args.model,
        min_cluster_size=args.min_cluster_size,
        reduce_dims=args.reduce_dims,
        umap_n_neighbors=args.umap_neighbors,
    )

    total = report["matched_total"] + report["excluded_count"]
    print("NPE fix-commit clustering summary")
    print(f"  input commits: {total}")
    print(
        f"  NPE-matched:   {report['matched_total']} "
        f"(excluded {report['excluded_count']} non-NPE)"
    )
    print(f"  clusters:      {report['n_clusters']} (noise: {report['n_noise']})")
    if report.get("reduction"):
        print(f"  reduction:     {report['reduction']}")
    top = report["clusters"][:_TOP_CLUSTERS_IN_SUMMARY]
    if top:
        print(f"  top clusters (up to {_TOP_CLUSTERS_IN_SUMMARY}):")
        for rank, cluster in enumerate(top, start=1):
            print(f"    {rank}. size={cluster['size']} | {cluster['label']}")
    else:
        print("  no clusters formed (empty match or all commits are noise)")
    print(f"  report: {args.output_json}")
    return 0


if __name__ == "__main__":  # pragma: no cover - manual CLI use
    raise SystemExit(main())
