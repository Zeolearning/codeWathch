from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

from code_watch.git_history import cluster_npe_commits, extract_npe_commits
from code_watch.git_history import npe_cluster
from code_watch.git_history.cluster_fixes import DEFAULT_MODEL_NAME


class FakeNpeEmbedder:
    """Deterministic stand-in for SentenceTransformer (no network, no download).

    Each text is mapped to one of three fixed orthogonal directions (chosen
    by topic keyword) plus seeded gaussian jitter, mimicking how real
    embeddings of same-topic texts cluster around a direction with natural
    density variation. Rows are L2-normalized like the real BGE pipeline.

    Jitter must NOT be uniform (identical offsets), or HDBSCAN's EOM
    selection sees no density structure and marks everything as noise.
    """

    _KEYS = ("config", "reference", "timeout")

    def __init__(self, dim: int = 16, sigma: float = 0.05, seed: int = 42) -> None:
        self.dim, self.sigma, self.seed = dim, sigma, seed

    def encode(self, sentences, **kwargs) -> np.ndarray:
        rng = np.random.default_rng(self.seed)
        vecs = []
        for text in sentences:
            key = next((k for k in self._KEYS if k in text.lower()), "timeout")
            v = np.zeros(self.dim, dtype=np.float64)
            v[self._KEYS.index(key)] = 1.0
            v += rng.normal(0.0, self.sigma, self.dim)
            vecs.append(v / np.linalg.norm(v))
        return np.array(vecs)


def _write_commits_json(path: Path, commits: list[dict | str]) -> Path:
    """Write a collect_fix_commits-shaped JSON; strings become subject-only commits."""
    normalized = [
        c if isinstance(c, dict) else {"hash": f"{i:040x}", "subject": c, "body": "", "message": c}
        for i, c in enumerate(commits, start=1)
    ]
    path.write_text(
        json.dumps({"repo": "/fake/repo", "count": len(normalized), "commits": normalized}),
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize(
    "subject,expected_terms",
    [
        # 1. "NPE" whole word, any case, optional plural
        ("fix: NPE when config center is absent", ["NPE"]),
        ("Fix NPEs reported on shutdown", ["NPE"]),
        ("fix npe on empty override url", ["NPE"]),
        # 2. "null pointer" with whitespace, optional plural
        ("fix: resolve Null Pointer Exception in RpcContext", ["null pointer"]),
        ("fix null pointers on shutdown", ["null pointer"]),
        # 3. "null-pointer" hyphenated
        ("fix null-pointer dereference in URL concat", ["null-pointer"]),
        # 4. "NullPointerException" as one word
        ("Fix NullPointerException on lookup", ["NullPointerException"]),
        ("fixes nullpointerexceptions in url handler", ["NullPointerException"]),
        # 5. bare "null" adjacent to fix-indicating context in the same sentence
        ("fix: add null check in getConfig", ["null (fix context)"]),
        ("null safety in attachment processing", ["null (fix context)"]),
        ("fix potential null problem on address lookup", ["null (fix context)"]),
        ("fix: guard against null when reference is blank", ["null (fix context)"]),
        # several terms can hit one subject; canonical order is pattern order
        ("fix: null-pointer and NPE hardening", ["NPE", "null-pointer"]),
        # a "null" followed by "pointer" is named by the explicit pattern only
        ("fix null pointer crash on invoke", ["null pointer"]),
    ],
)
def test_extract_npe_commits_matches_spellings(tmp_path, subject, expected_terms):
    """Every required spelling matches and reports exactly the canonical terms."""
    src = _write_commits_json(tmp_path / "fixes.json", [subject])
    matched = extract_npe_commits(src)
    assert len(matched) == 1
    assert matched[0]["subject"] == subject
    assert matched[0]["matched_terms"] == expected_terms


@pytest.mark.parametrize(
    "subject",
    [
        # required false positive: bare null, nearest fix word 3 words away
        "Align JSON null and empty handling",
        # bare null without any fix context nearby
        "feat: support null literal in expressions",
        # "nullable"/"nullability" are single words, not the word "null"
        "fix: rename nullable variable",
        "fix: annotate nullability of optional args",
        # no null/npe mention at all
        "fix: refactor config module",
        "chore: bump dependencies",
    ],
)
def test_extract_npe_commits_rejects_false_positives(tmp_path, subject):
    """Non-NPE subjects (esp. bare 'null' without fix context) never match."""
    src = _write_commits_json(tmp_path / "fixes.json", [subject])
    assert extract_npe_commits(src) == []


def test_extract_npe_commits_matches_body_and_annotates(tmp_path):
    """NPE mention in the BODY alone matches; results keep fields + annotation."""
    commits = [
        {
            "hash": "a" * 40,
            "subject": "fix: improve robustness of lookup",
            "body": "This avoids a NullPointerException when the url is blank.",
            "message": "fix: improve robustness of lookup\n\nThis avoids a ...",
        },
        {"hash": "b" * 40, "subject": "fix: rename nullable variable", "body": "", "message": "x"},
    ]
    src = _write_commits_json(tmp_path / "fixes.json", commits)

    matched = extract_npe_commits(src)
    assert len(matched) == 1
    assert matched[0]["hash"] == "a" * 40
    assert matched[0]["matched_terms"] == ["NullPointerException"]
    # original fields are preserved on the annotated copy
    assert matched[0]["body"].startswith("This avoids a NullPointer")


def test_extract_npe_commits_preserves_order(tmp_path):
    """Matching commits come back in input order with matched_terms attached."""
    subjects = [
        "fix: rename nullable variable",  # excluded
        "fix: NPE when config center is absent",
        "chore: bump dependencies",  # excluded
        "Fix NullPointerException on lookup",
    ]
    src = _write_commits_json(tmp_path / "fixes.json", subjects)
    matched = extract_npe_commits(src)
    assert [c["hash"] for c in matched] == [f"{i:040x}" for i in (2, 4)]
    assert [c["matched_terms"] for c in matched] == [["NPE"], ["NullPointerException"]]


def test_cluster_npe_commits_two_groups_plus_outlier(tmp_path):
    """4 config-NPE + 3 reference-NPE + 1 lone timeout-NPE -> 2 clusters + noise.

    Two extra non-NPE commits verify they are counted in excluded_count and
    never reach the embedder.
    """
    matched_subjects = [
        "fix: NPE when config center is absent",  # config group (4)
        "fix(config): NPE on empty override url",
        "fix: guard NPE in config parsing",
        "fix: NPE while merging config templates",
        "fix: NPE on reference count underflow",  # reference group (3)
        "fix(ref): NPE when reference url is blank",
        "fix: guard NPE in reference cleanup",
        "fix: NPE when timeout expires during invoke",  # lone commit -> noise
    ]
    excluded_subjects = [
        "Align JSON null and empty handling",  # bare null, no fix context
        "fix: rename nullable variable",
    ]
    src = _write_commits_json(tmp_path / "fixes.json", matched_subjects + excluded_subjects)
    out = tmp_path / "out" / "npe_clusters.json"  # parent dir must be created

    report = cluster_npe_commits(
        src,
        out,
        model_name="fake-embedder",
        embedding_model=FakeNpeEmbedder(),
        min_cluster_size=3,
    )

    # file on disk matches the returned report
    assert json.loads(out.read_text(encoding="utf-8")) == report
    assert report["model"] == "fake-embedder"
    assert report["input_count"] == 8  # only matched commits are clustered
    assert report["matched_total"] == 8
    assert report["excluded_count"] == 2
    assert report["n_clusters"] == 2
    assert report["n_noise"] == 1

    # clusters sorted by size descending
    assert [c["size"] for c in report["clusters"]] == [4, 3]

    config = report["clusters"][0]
    assert "config" in config["label"]  # distinctive topic term
    assert "npe" not in config["label"]  # "npe" occurs in every matched commit
    assert config["hashes"] == [f"{i:040x}" for i in range(1, 5)]
    assert config["sample_subjects"] == matched_subjects[:4]
    assert config["matched_terms_sample"] == ["NPE"]

    reference = report["clusters"][1]
    assert "reference" in reference["label"]
    assert reference["hashes"] == [f"{i:040x}" for i in range(5, 8)]
    assert reference["matched_terms_sample"] == ["NPE"]

    # lone timeout commit does not form a cluster
    assert report["noise_hashes"] == [f"{8:040x}"]


def test_cluster_npe_commits_umap_reduce_dims(tmp_path):
    """reduce_dims=5 runs UMAP before HDBSCAN and records it in the report.

    Same 4+3+1 fixture as the plain-clustering test: after a deterministic
    UMAP squeeze to 5 dims the two topic groups must still separate, while
    the lone timeout commit — a known UMAP trait — gets absorbed into the
    nearest group instead of staying noise (packing with min_dist=0 pulls
    outliers in on tiny datasets). "reduction" documents the projection
    (16d -> 5d, faked embedder dim).
    """
    matched_subjects = [
        "fix: NPE when config center is absent",
        "fix(config): NPE on empty override url",
        "fix: guard NPE in config parsing",
        "fix: NPE while merging config templates",
        "fix: NPE on reference count underflow",
        "fix(ref): NPE when reference url is blank",
        "fix: guard NPE in reference cleanup",
        "fix: NPE when timeout expires during invoke",
    ]
    src = _write_commits_json(tmp_path / "fixes.json", matched_subjects)
    out = tmp_path / "npe_clusters_umap.json"

    report = cluster_npe_commits(
        src,
        out,
        model_name="fake-embedder",
        embedding_model=FakeNpeEmbedder(),
        min_cluster_size=3,
        reduce_dims=5,
    )

    assert report["reduction"].startswith("umap:16d->5d(")
    assert "n_neighbors=7" in report["reduction"]  # capped at n_samples - 1
    assert report["n_clusters"] == 2
    assert report["n_noise"] == 0  # timeout outlier absorbed, not noise
    assert [c["size"] for c in report["clusters"]] == [5, 3]
    assert "config" in report["clusters"][0]["label"]
    assert "reference" in report["clusters"][1]["label"]
    assert json.loads(out.read_text(encoding="utf-8")) == report


def test_cluster_npe_commits_no_matches_empty_report(tmp_path):
    """Zero NPE matches -> empty report; the model must never be touched."""
    src = _write_commits_json(
        tmp_path / "fixes.json",
        ["fix: rename nullable variable", "Align JSON null and empty handling"],
    )
    out = tmp_path / "report.json"

    class Boom:
        def encode(self, *args, **kwargs):
            raise AssertionError("must not embed anything when nothing matches")

    report = cluster_npe_commits(src, out, embedding_model=Boom())
    assert report == {
        "model": DEFAULT_MODEL_NAME,
        "reduction": None,
        "input_count": 0,
        "n_clusters": 0,
        "n_noise": 0,
        "clusters": [],
        "noise_hashes": [],
        "matched_total": 0,
        "excluded_count": 2,
    }
    assert json.loads(out.read_text(encoding="utf-8")) == report


def test_main_prints_summary(tmp_path, capsys, monkeypatch):
    """CLI main() runs the full pipeline (fake embedder) and prints a summary."""
    from code_watch.git_history import cluster_fixes

    monkeypatch.setattr(cluster_fixes, "_load_embedding_model", lambda name: FakeNpeEmbedder())

    subjects = [
        "fix: NPE when config center is absent",
        "fix(config): NPE on empty override url",
        "fix: guard NPE in config parsing",
        "fix: NPE while merging config templates",
        "fix: NPE on reference count underflow",
        "fix(ref): NPE when reference url is blank",
        "fix: guard NPE in reference cleanup",
        "Align JSON null and empty handling",  # excluded
    ]
    src = _write_commits_json(tmp_path / "fixes.json", subjects)
    out = tmp_path / "npe_clusters.json"

    rc = npe_cluster.main([str(src), str(out), "--min-cluster-size", "3"])

    assert rc == 0
    stdout = capsys.readouterr().out
    assert "NPE-matched:   7" in stdout
    assert "excluded 1 non-NPE" in stdout
    assert "clusters:      2" in stdout
    assert "config" in stdout  # top-cluster labels are printed
    assert "reference" in stdout
    assert str(out) in stdout
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["matched_total"] == 7 and report["excluded_count"] == 1
