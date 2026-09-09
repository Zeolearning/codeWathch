"""Tests for code_watch.git_history.npe_diff_cluster (diff-based NPE clustering)."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import numpy as np

from code_watch.git_history.npe_diff_cluster import (
    _diff_text,
    cluster_npe_diffs,
    collect_npe_diffs,
)


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    )
    return proc.stdout.strip()


def _init_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    _git(path, "init", "-b", "main")
    _git(path, "config", "user.email", "test@example.com")
    _git(path, "config", "user.name", "Test User")
    return path


def _commit_change(repo: Path, message: str, path: str, old: str, new: str) -> str:
    """Stage-free variant: write old, commit, then write new, commit; return 2nd hash."""
    full = repo / path
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text(old, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "chore: base " + path)
    full.write_text(new, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


def _write_commits_json(path: Path, commits: list[dict]) -> Path:
    path.write_text(
        json.dumps({"repo": "unused", "count": len(commits), "commits": commits}),
        encoding="utf-8",
    )
    return path


class FakeNpeDiffEmbedder:
    """One-hot embedding keyed on topic words appearing in the diff text.

    Same jitter scheme as the fake in test_git_history_cluster_fixes: random
    (non-uniform) noise so HDBSCAN sees density structure.
    """

    _KEYS = ("config", "reference", "timeout")

    def __init__(self, dim: int = 16, sigma: float = 0.05, seed: int = 7) -> None:
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


def test_collect_npe_diffs_parses_sides_and_files(tmp_path):
    """Deleted/added lines are stripped of +/- and headers; only globbed files kept."""
    repo = _init_repo(tmp_path / "r")
    h = _commit_change(
        repo,
        "fix: NPE in ConfigService",
        "src/ConfigService.java",
        "old line\n  if (cfg.enabled) {\n",
        "new line\n  if (cfg != null && cfg.enabled) {\n",
    )
    h2 = _commit_change(
        repo,
        "fix: NPE in readme",
        "README.md",
        "before",
        "after",
    )  # non-java -> filtered by pathspec
    src = _write_commits_json(
        tmp_path / "fixes.json",
        [
            {"hash": h, "subject": "fix: NPE in ConfigService", "body": "", "message": "fix: NPE in ConfigService"},
            {"hash": h2, "subject": "fix: NPE in readme", "body": "", "message": "fix: NPE in readme"},
        ],
    )
    out = tmp_path / "diffs.json"

    records = collect_npe_diffs(repo, src, out)

    assert len(records) == 2
    java = records[0]
    assert java["hash"] == h
    assert java["files"] == ["src/ConfigService.java"]
    assert "if (cfg != null && cfg.enabled) {" in java["added"]
    assert "if (cfg.enabled) {" in java["deleted"]
    assert "old line" in java["deleted"] and "new line" in java["added"]
    assert java["matched_terms"] == ["NPE"]

    md = records[1]  # matched by subject, but *.java pathspec filters the diff
    assert md["files"] == []
    assert md["deleted"] == [] and md["added"] == []

    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["count"] == 2
    assert payload["include_globs"] == ["*.java"]
    assert payload["commits"][0]["hash"] == h


def test_diff_text_orders_sides_then_subject():
    text = _diff_text(
        {
            "deleted": ["  if (cfg.enabled) {", ""],
            "added": ["  if (cfg != null) {"],
            "subject": "fix: NPE in config",
        }
    )
    lines = text.splitlines()
    assert lines[0] == "deleted:"
    assert lines[1] == "if (cfg.enabled) {"  # stripped, non-empty only
    assert lines[2] == "added:"
    assert lines[3] == "if (cfg != null) {"
    assert lines[-1] == "message: fix: NPE in config"


def test_cluster_npe_diffs_groups_by_changed_code(tmp_path):
    """4 config + 3 reference NPE fixes (similar code lines) + 1 lone timeout.

    Embedding keys on topic words inside the changed lines, mirroring the
    real setup where the code (not the message wording) carries the signal.
    """
    repo = _init_repo(tmp_path / "r")
    config_fix = (
        "  if (config.getUrl() == null) {\n      return;\n  }\n"
    )
    base_config = "class ConfigService {\n  void start() { load(); }\n}\n"
    fixed_config = (
        "class ConfigService {\n  void start() {\n"
        "      if (config.getUrl() == null) {\n          return;\n      }\n"
        "      load();\n  }\n}\n"
    )
    reference_fix = (
        "  if (reference.getInvoker() == null) {\n      return;\n  }\n"
    )
    base_reference = "class ReferenceInvoker {\n  void invoke() { call(); }\n}\n"
    fixed_reference = (
        "class ReferenceInvoker {\n  void invoke() {\n"
        "      if (reference.getInvoker() == null) {\n          return;\n      }\n"
        "      call();\n  }\n}\n"
    )

    commits = []
    for i, subj in enumerate(
        [
            "fix: NPE when config center is absent",
            "fix(config): NPE on empty override url",
            "fix: guard NPE in config parsing",
            "fix: NPE while merging config templates",
        ]
    ):
        path = f"src/main/java/Config{i}/ConfigService.java"
        # vary surrounding lines so identical fix lines aren't byte-equal
        h = _commit_change(
            repo,
            subj,
            path,
            base_config + f"// v{i}\n",
            fixed_config + f"// v{i}\n",
        )
        commits.append({"hash": h, "subject": subj, "body": "", "message": subj})
    for i, subj in enumerate(
        [
            "fix: NPE on reference count underflow",
            "fix(ref): NPE when reference url is blank",
            "fix: guard NPE in reference cleanup",
        ]
    ):
        path = f"src/main/java/Ref{i}/ReferenceInvoker.java"
        h = _commit_change(
            repo,
            subj,
            path,
            base_reference + f"// v{i}\n",
            fixed_reference + f"// v{i}\n",
        )
        commits.append({"hash": h, "subject": subj, "body": "", "message": subj})
    # lone outlier: timeout code
    h = _commit_change(
        repo,
        "fix: NPE when timeout expires during invoke",
        "src/main/java/TimeoutFilter.java",
        "class TimeoutFilter {\n  void check() { tick(); }\n}\n",
        "class TimeoutFilter {\n  void check() {\n"
        "      if (timeout.remaining() < 0) {\n          return;\n      }\n"
        "      tick();\n  }\n}\n",
    )
    commits.append({"hash": h, "subject": "fix: NPE when timeout expires during invoke", "body": "", "message": "fix: NPE when timeout expires during invoke"})
    # non-NPE noise commits
    commits.append({"hash": "e" * 40, "subject": "feat: add registry", "body": "", "message": "feat: add registry"})
    commits.append({"hash": "f" * 40, "subject": "chore: bump version", "body": "", "message": "chore: bump version"})

    src = _write_commits_json(tmp_path / "fixes.json", commits)
    out = tmp_path / "out" / "diff_clusters.json"

    report = cluster_npe_diffs(
        repo,
        src,
        out,
        model_name="fake-diff-embedder",
        embedding_model=FakeNpeDiffEmbedder(),
        min_cluster_size=3,
    )

    assert json.loads(out.read_text(encoding="utf-8")) == report
    assert report["input_count"] == 8
    assert report["matched_total"] == 8
    assert report["excluded_count"] == 2
    assert report["reduction"] is None
    assert report["n_clusters"] == 2
    assert report["n_noise"] == 1
    assert [c["size"] for c in report["clusters"]] == [4, 3]

    config = report["clusters"][0]
    assert all("Config" in f for f in config["files_sample"])
    assert config["matched_terms_sample"] == ["NPE"]

    reference = report["clusters"][1]
    assert all("Reference" in f for f in reference["files_sample"])

    assert report["noise_hashes"] == [commits[7]["hash"]]


def test_cluster_npe_diffs_no_matches_empty_report(tmp_path):
    """No NPE commits -> empty report without touching git or the model."""
    repo = _init_repo(tmp_path / "r")
    src = _write_commits_json(
        tmp_path / "fixes.json",
        [{"hash": "a" * 40, "subject": "feat: add registry", "body": "", "message": "feat: add registry"}],
    )
    out = tmp_path / "o.json"

    report = cluster_npe_diffs(
        repo,
        src,
        out,
        model_name="fake",
        embedding_model=FakeNpeDiffEmbedder(),
    )
    assert report["matched_total"] == 0
    assert report["excluded_count"] == 1
    assert report["clusters"] == []
    assert json.loads(out.read_text(encoding="utf-8")) == report
