"""Prefetch missing blobs of a partial clone (`clone --filter=blob:none`).

Diff mining (`git show`) needs file content; partial clones store only
commits+trees and lazy-fetch blobs one HTTP round trip per blob — slow and
fragile through proxies. This module batch-prefetches exactly what diff
mining will need:

1. `git diff-tree -r` lists each fix commit's changed blob oids + paths
   (trees only — no blob content needed for this step);
2. keep blobs under the include globs (e.g. ``*.java``);
3. check which are missing (`git cat-file --batch-check`);
4. `git fetch` the missing oids in chunks (with retries).

No-op on full clones.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

_CHUNK = 200  # oids per fetch request
_ROUNDS = 4  # full fetch + re-scan passes before giving up
_GLOBS = ("*.java",)


def _git(repo: Path, args: list[str], *, input_text: str | None = None, check: bool = True) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        input=input_text,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=600,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(f"git {args[0]} failed in {repo}: {proc.stderr.strip()[:300]}")
    return proc.stdout


def _is_promisor(repo: Path) -> bool:
    return _git(repo, ["config", "--get", "remote.origin.promisor"], check=False).strip() == "true"


def _changed_blobs(repo: Path, hash: str, globs: tuple[str, ...]) -> set[str]:
    """Blob oids changed by ``hash`` under ``globs`` (both sides of the diff).

    Uses `diff-tree -r -z` raw output — reads trees only, so it works even
    when every blob is still missing.
    """
    out = _git(repo, ["diff-tree", "-r", "--no-commit-id", "-z", hash])
    oids: set[str] = []
    fields = out.split("\0")
    i = 0
    while i + 1 < len(fields):
        meta, path = fields[i], fields[i + 1]
        i += 2
        if not meta.startswith(":") or not path:
            continue
        parts = meta[1:].split(" ")
        if len(parts) != 5:
            continue
        src, dst = parts[2], parts[3]
        if not any(path.endswith(g.lstrip("*")) or g == "*" for g in globs):
            continue
        for oid in (src, dst):
            if len(oid) == 40 and oid != "0" * 40:
                oids.append(oid)
    return set(oids)


def _missing(repo: Path, hashes: list[str], wanted: set[str]) -> list[str]:
    """Wanted blobs that are absent locally, WITHOUT triggering lazy fetch.

    ``cat-file --batch-check`` would lazy-fetch every missing oid (one HTTP
    round trip each), so existence is derived from
    ``rev-list --objects --missing=print`` instead, which merely MARKS
    missing objects (``?<oid>``) during traversal. Scoping traversal to the
    fix commits keeps it cheap; intersection with ``wanted`` drops blobs we
    don't need anyway.
    """
    if not wanted:
        return []
    out = _git(
        repo,
        ["rev-list", "--objects", "--no-walk", "--stdin", "--missing=print"],
        input_text="\n".join(hashes) + "\n",
    )
    missing_all = {
        line[1:][:40] for line in out.splitlines() if line.startswith("?")
    }
    return sorted(wanted & missing_all)


def prefetch_blobs(
    repo_path: str | Path,
    hashes: list[str],
    *,
    include_globs: tuple[str, ...] = _GLOBS,
    verbose: bool = False,
) -> int:
    """Batch-fetch missing blobs needed to diff ``hashes``; return fetched count.

    No-op (returns 0) when ``repo`` is not a promisor/partial clone.
    """
    repo = Path(repo_path)
    if not hashes or not _is_promisor(repo):
        return 0

    wanted: set[str] = set()
    for h in hashes:
        wanted |= _changed_blobs(repo, h, include_globs)
    missing = _missing(repo, hashes, wanted)
    if verbose:
        print(f"  prefetch: {len(wanted)} changed blobs under globs, {len(missing)} missing")

    # Fetch-by-oid through proxies is flaky: exit codes lie, some objects in
    # a chunk silently fail. So fetch in chunks ignoring rc, recompute what
    # is still missing (cheap, local rev-list), and repeat a few rounds.
    fetched: set[str] = set()
    for round_no in range(1, _ROUNDS + 1):
        if not missing:
            break
        for start in range(0, len(missing), _CHUNK):
            chunk = missing[start : start + _CHUNK]
            subprocess.run(
                ["git", "-C", str(repo), "fetch", "--no-tags", "origin", *chunk],
                capture_output=True,
                text=True,
                timeout=600,
            )  # rc ignored on purpose; success is verified by re-scan
            fetched.update(chunk)
            if verbose:
                print(f"  prefetch: round {round_no} chunk {start // _CHUNK + 1} sent ({len(fetched)} total)")
        missing = [oid for oid in _missing(repo, hashes, wanted) if oid not in fetched]
        if verbose and missing:
            print(f"  prefetch: round {round_no} done, {len(missing)} still missing")
    if missing:
        raise RuntimeError(
            f"prefetch: {len(missing)} blobs still missing after {_ROUNDS} rounds "
            f"(e.g. {missing[0]}); network/proxy too flaky to backfill"
        )
    return len(fetched)
