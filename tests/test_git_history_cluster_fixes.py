from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

from code_watch.git_history import cluster_fix_messages
from code_watch.git_history.cluster_fixes import DEFAULT_MODEL_NAME, _commit_text


class FakeEmbedder:
    """Deterministic stand-in for SentenceTransformer (no network, no download).

    Each text is mapped to one of three fixed orthogonal directions (chosen
    by keyword) plus seeded gaussian jitter, mimicking how real embeddings of
    same-topic texts cluster around a direction with natural density
    variation. Rows are L2-normalized like the real BGE pipeline.

    Note: jitter must NOT be uniform (e.g. identical offsets), or HDBSCAN's
    EOM selection sees no density structure and marks everything as noise.
    """

    _KEYS = ("login", "payment", "cache")

    def __init__(self, dim: int = 16, sigma: float = 0.05, seed: int = 42) -> None:
        self.dim, self.sigma, self.seed = dim, sigma, seed

    def encode(self, sentences, **kwargs) -> np.ndarray:
        rng = np.random.default_rng(self.seed)
        vecs = []
        for text in sentences:
            key = next((k for k in self._KEYS if k in text.lower()), "cache")
            v = np.zeros(self.dim, dtype=np.float64)
            v[self._KEYS.index(key)] = 1.0
            v += rng.normal(0.0, self.sigma, self.dim)
            vecs.append(v / np.linalg.norm(v))
        return np.array(vecs)


def _write_commits_json(path: Path, subjects: list[str]) -> Path:
    """Write a collect_fix_commits-shaped JSON file; returns the path."""
    commits = [
        {"hash": f"{i:040x}", "subject": s, "body": "", "message": s}
        for i, s in enumerate(subjects, start=1)
    ]
    path.write_text(
        json.dumps({"repo": "/fake/repo", "count": len(commits), "commits": commits}),
        encoding="utf-8",
    )
    return path


def test_cluster_fix_messages_clusters_and_labels(tmp_path):
    """4 login + 3 payment + 1 lone cache commit -> 2 clusters (size-sorted) + 1 noise."""
    subjects = [
        "fix: login redirect loop",  # login group (4)
        "fix(auth): login token expiry",
        "fix: correct login form validation",
        "fix(ui): login button styling",
        "fix: payment gateway timeout",  # payment group (3)
        "fix(billing): payment retry logic",
        "fix: payment currency rounding",
        "fix: clear stale cache entries",  # lone cache commit -> noise
    ]
    src = _write_commits_json(tmp_path / "fixes.json", subjects)
    out = tmp_path / "out" / "clusters.json"  # parent dir must be created

    report = cluster_fix_messages(
        src,
        out,
        model_name="fake-embedder",
        embedding_model=FakeEmbedder(),
        min_cluster_size=3,
    )

    # file on disk matches the returned report
    assert json.loads(out.read_text(encoding="utf-8")) == report
    assert report["model"] == "fake-embedder"
    assert report["input_count"] == 8
    assert report["n_clusters"] == 2
    assert report["n_noise"] == 1

    # clusters sorted by size descending
    assert [c["size"] for c in report["clusters"]] == [4, 3]

    login = report["clusters"][0]
    assert "login" in login["label"]  # distinctive term, not shared boilerplate
    assert "fix" not in login["label"]  # "fix" occurs in every commit -> not distinctive
    assert login["hashes"] == [f"{i:040x}" for i in range(1, 5)]
    assert login["sample_subjects"] == subjects[:4]  # in input order

    payment = report["clusters"][1]
    assert "payment" in payment["label"]
    assert payment["hashes"] == [f"{i:040x}" for i in range(5, 8)]

    # lone cache commit does not form a cluster
    assert report["noise_hashes"] == [f"{8:040x}"]


def test_cluster_fix_messages_caps_sample_subjects(tmp_path):
    """A 7-member cluster reports at most 5 sample subjects; size sort still holds."""
    subjects = [f"fix: login defect number {i}" for i in range(7)]
    subjects += [f"fix: payment defect number {i}" for i in range(5)]
    src = _write_commits_json(tmp_path / "fixes.json", subjects)
    report = cluster_fix_messages(
        src, tmp_path / "r.json", embedding_model=FakeEmbedder(), min_cluster_size=3
    )
    assert report["n_clusters"] == 2
    assert report["n_noise"] == 0
    assert [c["size"] for c in report["clusters"]] == [7, 5]
    assert report["clusters"][0]["sample_subjects"] == subjects[:5]  # capped at 5
    assert report["clusters"][1]["sample_subjects"] == subjects[7:12]  # <= 5, all of it
    assert report["model"] == DEFAULT_MODEL_NAME


def test_cluster_fix_messages_all_noise(tmp_path):
    """Three mutually orthogonal singletons cannot form clusters -> all noise."""
    subjects = ["fix: login redirect", "fix: payment timeout", "fix: cache eviction"]
    src = _write_commits_json(tmp_path / "fixes.json", subjects)
    report = cluster_fix_messages(
        src, tmp_path / "r.json", embedding_model=FakeEmbedder(), min_cluster_size=3
    )
    assert report["input_count"] == 3
    assert report["n_clusters"] == 0
    assert report["n_noise"] == 3
    assert report["clusters"] == []
    assert sorted(report["noise_hashes"]) == [f"{i:040x}" for i in (1, 2, 3)]


def test_cluster_fix_messages_empty_input(tmp_path):
    """Empty commits list -> empty report; the model must never be touched."""
    src = _write_commits_json(tmp_path / "empty.json", [])
    out = tmp_path / "report.json"

    class Boom:
        def encode(self, *args, **kwargs):
            raise AssertionError("must not embed anything for empty input")

    report = cluster_fix_messages(src, out, embedding_model=Boom())
    assert report == {
        "model": DEFAULT_MODEL_NAME,
        "reduction": None,
        "input_count": 0,
        "n_clusters": 0,
        "n_noise": 0,
        "clusters": [],
        "noise_hashes": [],
    }
    assert json.loads(out.read_text(encoding="utf-8")) == report


def test_cluster_fix_messages_model_failure_raises_runtimeerror(tmp_path, monkeypatch):
    """Any SentenceTransformer load/download failure is wrapped in RuntimeError."""
    import sentence_transformers

    def _boom(name, *args, **kwargs):
        raise OSError(f"cannot download {name}")

    monkeypatch.setattr(sentence_transformers, "SentenceTransformer", _boom)
    src = _write_commits_json(tmp_path / "fixes.json", ["fix: a", "fix: b", "fix: c"])
    with pytest.raises(RuntimeError, match="failed to load/download embedding model"):
        cluster_fix_messages(src, tmp_path / "r.json", model_name="no/such-model")


def test_commit_text_uses_subject_plus_body_prefix():
    commit = {
        "hash": "abc",
        "subject": "fix: crash on start",
        "body": "B" * 500,
        "message": "fix: crash on start\n\n" + "B" * 500,
    }
    text = _commit_text(commit)
    assert text.startswith("fix: crash on start\n")
    assert len(text) == len("fix: crash on start\n") + 200  # body truncated to ~200 chars


def test_commit_text_body_and_subject_fallbacks():
    assert _commit_text({"hash": "h", "subject": "", "body": "", "message": ""}) == "commit h"
    assert _commit_text({"hash": "h", "subject": "", "body": "", "message": "fix: m"}) == "fix: m"
    assert _commit_text({"hash": "h", "subject": "fix: s", "body": "", "message": "x"}) == "fix: s"
    # whitespace-only body is ignored
    assert _commit_text({"hash": "h", "subject": "fix: s", "body": "  \n ", "message": "x"}) == "fix: s"
