from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

import pytest

from code_watch.git_history import collect_fix_commits
from code_watch.git_history.fix_commits import FIX_SUBJECT_RE


def _git(repo: Path, *args: str, date: int | None = None) -> str:
    """Run git in repo; explicit committer dates keep log order deterministic."""
    env = dict(os.environ)
    if date is not None:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = f"@{date} +0000"
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    return proc.stdout.strip()


def _commit(repo: Path, message: str, *, date: int) -> str:
    """Create an empty commit and return its full hash."""
    _git(repo, "commit", "--allow-empty", "-m", message, date=date)
    return _git(repo, "rev-parse", "HEAD")


def _init_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    _git(path, "init", "-b", "main")
    _git(path, "config", "user.email", "test@example.com")
    _git(path, "config", "user.name", "Test User")
    return path


@pytest.fixture
def mixed_repo(tmp_path: Path) -> dict:
    """Repo mixing fix/feat/chore/plain commits with a fix-subject MERGE commit.

    Dates increase monotonically, so newest-first git-log order is fixed:
    merge(8000), h7(7000), h6(6000), h5(5000), h_ns(4600), fixme(4500), h4(4000),
    h3(3000), h2(2000), h1(1000). Expected fixes: [h6, h5, h_ns, h3, h2].
    """
    repo = _init_repo(tmp_path / "mixed")

    h1 = _commit(repo, "feat: initial feature", date=1000)
    h2 = _commit(
        repo,
        "fix: correct login flow\n\nLine one of the body.\n\nSecond paragraph.",
        date=2000,
    )
    h3 = _commit(repo, "FIX(Parser): handle empty input", date=3000)
    h4 = _commit(repo, "chore: update dependencies", date=4000)
    _commit(repo, "fixme: not a fix type", date=4500)
    h_ns = _commit(repo, "fix:no space after colon", date=4600)
    h5 = _commit(repo, "fix(api)!: breaking API fix", date=5000)

    _git(repo, "checkout", "-b", "topic", date=5100)
    h6 = _commit(repo, "fix(core): branch fix", date=6000)
    _git(repo, "checkout", "main", date=6100)
    h7 = _commit(repo, "feat: diverge main", date=7000)
    merge = _git(
        repo, "merge", "--no-ff", "topic", "-m", "fix(merge): merges are never fixes", date=8000
    )

    return {
        "path": repo,
        "fix_hashes": [h6, h5, h_ns, h3, h2],  # newest first
        "body_fix": h2,
        "upper_fix": h3,
        "nospace_fix": h_ns,
        "merge": merge,
        "non_fix": [h1, h4, h7],
    }


def test_collect_fix_commits_returns_full_hashes(mixed_repo, tmp_path):
    output = tmp_path / "out" / "fix_commits.json"  # parent dir must be created
    hashes = collect_fix_commits(mixed_repo["path"], output)
    assert hashes == mixed_repo["fix_hashes"]
    assert all(re.fullmatch(r"[0-9a-f]{40}", h) for h in hashes)


def test_collect_fix_commits_excludes_merges_and_non_fix(mixed_repo, tmp_path):
    hashes = collect_fix_commits(mixed_repo["path"], tmp_path / "fix_commits.json")
    assert mixed_repo["merge"] not in hashes  # fix-subject merge commit
    assert not set(hashes) & set(mixed_repo["non_fix"])


def test_collect_fix_commits_saves_messages(mixed_repo, tmp_path):
    output = tmp_path / "fix_commits.json"
    hashes = collect_fix_commits(mixed_repo["path"], output)
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["count"] == len(hashes) == 5
    assert [c["hash"] for c in data["commits"]] == hashes
    by_hash = {c["hash"]: c for c in data["commits"]}

    body_fix = by_hash[mixed_repo["body_fix"]]
    assert body_fix["subject"] == "fix: correct login flow"
    assert body_fix["body"] == "Line one of the body.\n\nSecond paragraph."
    assert (
        body_fix["message"]
        == "fix: correct login flow\n\nLine one of the body.\n\nSecond paragraph."
    )
    # case-insensitive match keeps the original subject text
    assert by_hash[mixed_repo["upper_fix"]]["subject"] == "FIX(Parser): handle empty input"
    # colon without a space is accepted too
    assert by_hash[mixed_repo["nospace_fix"]]["subject"] == "fix:no space after colon"
    assert mixed_repo["merge"] not in by_hash


def test_collect_fix_commits_repo_without_fixes(tmp_path):
    repo = _init_repo(tmp_path / "nofix")
    _commit(repo, "feat: only a feature", date=1000)
    output = tmp_path / "fix_commits.json"
    assert collect_fix_commits(repo, output) == []
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["count"] == 0 and data["commits"] == []


def test_collect_fix_commits_rejects_non_git_dir(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(RuntimeError, match="not a git repository"):
        collect_fix_commits(plain, tmp_path / "x.json")


@pytest.mark.parametrize(
    "subject",
    [
        # conventional shapes (previous behavior, kept)
        "fix: correct login flow",
        "FIX: loud uppercase fix",
        "Fix(parser): handle empty input",
        "fix(api)!: breaking API fix",
        # colon with NO space after it
        "fix:no space after colon",
        "fix(api)!:no-space breaking fix",
        # no colon at all: keyword + whitespace (fix/fixes/fixed/fixing)
        "fix the login flow",
        "fixes memory leak",
        "Fixed the bug",
        "fixing the race",
        "FIXING the race",
    ],
)
def test_fix_subject_re_accepts(subject):
    assert FIX_SUBJECT_RE.match(subject), subject


@pytest.mark.parametrize(
    "subject",
    [
        "fixture: add",  # word merely starting with "fix"
        "fixme: xxx",
        "feat: xxx",
        "chore: xxx",
        "style: x",
        "see fix: #123",  # mid-line mention
        "see fixes memory leak",  # mid-line keyword mention
        "fix:",  # empty description
        "fix: ",  # whitespace-only description
        "fix",  # bare keyword without following whitespace
    ],
)
def test_fix_subject_re_rejects(subject):
    assert not FIX_SUBJECT_RE.match(subject), subject


@pytest.fixture
def loose_repo(tmp_path: Path) -> dict:
    """Repo exercising the loosened subject shapes end to end.

    Dates increase monotonically, so newest-first git-log order is fixed:
    loose fixes at 6000..3000, negatives at 2500..2100, initial feat at 1000.
    Expected fixes: [no_space, fixed_kw, fixes_kw, fixing_kw]; the negatives
    (fixture/fixme/style/mid-line) must not be collected.
    """
    repo = _init_repo(tmp_path / "loose")

    _commit(repo, "feat: initial feature", date=1000)
    _commit(repo, "fixture: add more fixtures", date=2100)
    _commit(repo, "fixme: remove this later", date=2200)
    _commit(repo, "style: reformat everything", date=2300)
    _commit(repo, "see fix: #123 for context", date=2500)
    fixing_kw = _commit(repo, "fixing the race condition", date=3000)
    fixes_kw = _commit(repo, "fixes memory leak", date=4000)
    fixed_kw = _commit(repo, "Fixed the bug", date=5000)
    no_space = _commit(repo, "fix(scope)!:no-space description", date=6000)

    return {
        "path": repo,
        "fix_hashes": [no_space, fixed_kw, fixes_kw, fixing_kw],  # newest first
    }


def test_collect_fix_commits_matches_loosened_subjects(loose_repo, tmp_path):
    output = tmp_path / "fix_commits.json"
    hashes = collect_fix_commits(loose_repo["path"], output)
    # exactly the four loose fixes, newest first; negatives are excluded
    assert hashes == loose_repo["fix_hashes"]
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["count"] == 4
    assert [c["subject"] for c in data["commits"]] == [
        "fix(scope)!:no-space description",
        "Fixed the bug",
        "fixes memory leak",
        "fixing the race condition",
    ]
