from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

# Fix subjects (case-insensitive), two accepted shapes:
#   1. Conventional type `fix` with optional scope and optional `!`
#      breaking marker: `fix: xxx`, `Fix(parser): xxx`, `fix:xxx` —
#      whitespace after the colon is optional, description non-empty.
#   2. Bare keyword `fix`/`fixes`/`fixed`/`fixing` followed by whitespace:
#      `Fixed the bug`, `fixing the race` — no colon at all.
# The type/keyword must be exact and start the subject, so `fixme:`,
# `fixture:`, other types (`feat:`), and mid-line mentions (`see fix: #123`)
# never match.
FIX_SUBJECT_RE = re.compile(
    r"^(?:fix(\([^)]*\))?(!)?:\s*\S|(?:fix|fixes|fixed|fixing)\s+\S)",
    re.IGNORECASE,
)

# Comment/doc-only fixes are not code fixes; judged from the subject alone
# (whole words, so "commentary" never hits via "comments" etc. — each
# alternative is a distinct whole word).
COMMENT_ONLY_SUBJECT_RE = re.compile(
    r"\b(javadoc|comments?|documentation|docs?|readme|license|copyright|typos?|spelling)\b",
    re.IGNORECASE,
)

# Separators for git --format output. Both are control chars that cannot occur
# in a full hex hash; %s is always a single line (git folds embedded newlines
# into spaces), so the two-phase parse below stays unambiguous.
_RECORD_SEP = "\x1e"  # between commits (record separator)
_FIELD_SEP = "\x1f"  # between hash and subject (unit separator)


def _git(repo: Path, args: list[str], *, input_text: str | None = None) -> str:
    """Run `git -C repo <args>` and return stdout; raise RuntimeError on failure."""
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        input=input_text,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=600,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"git {args[0]} failed in {repo} (rc={proc.returncode}): {proc.stderr.strip()[:500]}"
        )
    return proc.stdout


def _parse_log_records(out: str) -> list[tuple[str, str, str, str]]:
    """Parse `%H%x1f%ad%x1f%cd%x1f%s` log output into (hash, adate, cdate, subject).

    One output line per commit (%s never contains newlines); splitting each
    line on field separators keeps stray separators inside subjects. Dates
    are ISO-8601 strings (``--date=iso-strict``), which sort correctly as
    plain strings.
    """
    records: list[tuple[str, str, str, str]] = []
    for line in out.splitlines():
        parts = line.split(_FIELD_SEP)
        if len(parts) == 4 and re.fullmatch(r"[0-9a-f]{40,}", parts[0]):
            records.append((parts[0], parts[1], parts[2], parts[3]))
    return records


def _fetch_messages(repo: Path, hashes: list[str]) -> dict[str, str]:
    """Fetch full raw messages (%B) for `hashes` with one batched git call.

    Hashes go in via --stdin (no argv length limits); each record starts with
    the hex hash on its own line, so records can be split safely.
    """
    out = _git(
        repo,
        ["log", "--no-walk=unsorted", "--stdin", f"--format=%x1e%H%n%B"],
        input_text="\n".join(hashes) + "\n",
    )
    messages: dict[str, str] = {}
    for chunk in out.split(_RECORD_SEP):
        chunk = chunk.strip("\n")
        if not chunk:
            continue
        hash_, sep, message = chunk.partition("\n")
        if sep and hash_ in hashes:
            messages[hash_] = message
    return messages


def _split_body(message: str, subject: str) -> str:
    """Body = full message minus the subject line and the blank separator line."""
    prefix = subject + "\n"
    if message.startswith(prefix):
        return message[len(prefix):].lstrip("\n")
    _, _, rest = message.partition("\n\n")  # multi-line subject fallback
    return rest


def collect_fix_commits(repo_path: str | Path, output_path: str | Path) -> list[str]:
    """Collect all "fix" commits of a local git repository.

    A commit qualifies when its subject starts with a fix marker
    (case-insensitive): either the conventional type `fix` with optional
    scope and `!` marker (`fix: xxx`, `Fix(parser): xxx`, `fix:xxx` —
    whitespace after the colon is optional, description non-empty), or a
    bare `fix`/`fixes`/`fixed`/`fixing` keyword followed by whitespace
    (`Fixed the bug`, `fixes memory leak`). The type/keyword must be exact,
    so `fixme:`, `fixture:`, and mid-line mentions (`see fix: #123`) don't
    qualify. Merge commits are always excluded. Fixes whose subject marks
    them as comment/doc-only work (javadoc, comments, docs, readme, license,
    copyright, typos, spelling) are excluded too: they touch no code defect.

    Each saved commit carries ``author_date`` and ``commit_date``
    (ISO-8601), enabling chronological ordering downstream.

    Args:
        repo_path: local git repository (work tree or bare `.git` dir).
        output_path: destination JSON file; parent directories are created.

    Returns:
        Full hashes of the matching commits, newest first (same order as the
        saved file).

    Raises:
        RuntimeError: if git fails (e.g. repo_path is not a git repository).
    """
    repo = Path(repo_path)
    out_path = Path(output_path)

    fix_records = [
        record
        for record in _parse_log_records(
            _git(repo, ["log", "--no-merges", "--date=iso-strict",
                        f"--format=%H{_FIELD_SEP}%ad{_FIELD_SEP}%cd{_FIELD_SEP}%s"])
        )
        if FIX_SUBJECT_RE.match(record[3])
    ]
    excluded_comment_only = sum(
        1 for record in fix_records if COMMENT_ONLY_SUBJECT_RE.search(record[3])
    )
    fix_records = [record for record in fix_records if not COMMENT_ONLY_SUBJECT_RE.search(record[3])]

    messages = (
        _fetch_messages(repo, [record[0] for record in fix_records]) if fix_records else {}
    )
    missing = [record[0] for record in fix_records if record[0] not in messages]
    if missing:
        raise RuntimeError(f"git log did not return messages for {len(missing)} commit(s)")

    commits = [
        {
            "hash": hash_,
            "subject": subject,
            "body": _split_body(messages[hash_], subject),
            "message": messages[hash_],
            "author_date": author_date,
            "commit_date": commit_date,
        }
        for hash_, author_date, commit_date, subject in fix_records
    ]
    payload = {
        "repo": str(repo.resolve()),
        "count": len(commits),
        "excluded_comment_only": excluded_comment_only,
        "commits": commits,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return [record[0] for record in fix_records]
