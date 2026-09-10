"""Build per-vulnerability-type sub-datasets from a repo's fix commits.

Pipeline (see ``main`` / ``build``):

1. Collect fix commits (``fix_commits.collect_fix_commits``) ->
   ``<root>/commits/<name>/fix_commits.json`` (comment-only fixes excluded,
   ISO dates included).
2. Collect parsed diffs for ALL of them (``npe_diff_cluster.collect_diffs``)
   -> ``<root>/diffs/<name>/diffs.json``.
3. Classify into vulnerability families via the extensible registry
   (``vuln_types``); each commit lands in exactly one family (priority
   order), with ``all_matched_types`` recording every hit.
4. Per family: sort by ``commit_date`` ascending, number ``seq: 1..N``,
   write ``<root>/subsets/<type>/<name>.json``.

The ``seq`` numbering IS the chronological order: train/test splits are
derived downstream by taking a prefix (train) and the rest (test) — no
split file is produced at build time.

CLI: ``python -m git_history.build_dataset <repo_path> <root>
[--name NAME] [--types npe,resource_leak]`` prints a per-family summary.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .cluster_fixes import _load_commits
from .fix_commits import collect_fix_commits
from .npe_diff_cluster import collect_diffs
from .vuln_types import classify_commits, registered_types

_SUBSET_FIELDS = (
    "hash",
    "subject",
    "commit_date",
    "author_date",
    "matched_terms",
    "all_matched_types",
)


def _sort_key(commit: dict) -> tuple[str, str]:
    """Chronological order: commit_date (ISO), author_date as tie-breaker."""
    return (str(commit.get("commit_date") or ""), str(commit.get("author_date") or ""))


def build(
    repo_path: str | Path,
    root: str | Path,
    *,
    name: str | None = None,
    types: list[str] | None = None,
    include_globs: tuple[str, ...] = ("*.java",),
    prefetch: bool = True,
) -> dict[str, Path]:
    """Run the full build; return ``{type_name: subset JSON path}``.

    Steps: collect fix commits -> (partial clones: batch-prefetch the
    missing blobs the diffs need) -> collect diffs -> classify -> sort by
    commit date + seq numbering -> write one subset JSON per family.
    No split file is produced; ``seq`` carries the chronological order.
    """
    repo = Path(repo_path)
    root = Path(root)
    name = name or repo.name

    commits_json = root / "commits" / name / "fix_commits.json"
    diffs_json = root / "diffs" / name / "diffs.json"

    hashes = collect_fix_commits(repo, commits_json)
    if prefetch:
        from .prefetch import prefetch_blobs

        fetched = prefetch_blobs(repo, hashes, include_globs=include_globs, verbose=True)
        if fetched:
            print(f"  prefetched {fetched} missing blobs")
    commits = _load_commits(commits_json)
    records = collect_diffs(repo, commits_json, diffs_json, include_globs=include_globs)
    diffs_by_hash = {str(r["hash"]): r for r in records}

    buckets = classify_commits(commits, diffs_by_hash, types=types)

    subset_paths: dict[str, Path] = {}
    for type_name, items in buckets.items():
        items = sorted(items, key=_sort_key)
        subset = [
            {"seq": i, **{field: item.get(field) for field in _SUBSET_FIELDS}}
            for i, item in enumerate(items, start=1)
        ]
        out = root / "subsets" / type_name / f"{name}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "repo": name,
            "type": type_name,
            "count": len(subset),
            "sorted_by": "commit_date asc",
            "types_available": registered_types(),
            "commits": subset,
        }
        out.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        subset_paths[type_name] = out
    return subset_paths


def main(argv: list[str] | None = None) -> int:
    """CLI entry: build sub-datasets and print a per-family summary."""
    parser = argparse.ArgumentParser(
        prog="python -m git_history.build_dataset",
        description="Build per-vulnerability-type sub-datasets from fix commits.",
    )
    parser.add_argument("repo", help="local git repository to mine")
    parser.add_argument("root", help="dataset root directory (e.g. dataset/)")
    parser.add_argument(
        "--name",
        default=None,
        help="dataset name for the repo (default: repo directory name)",
    )
    parser.add_argument(
        "--types",
        default=None,
        help="comma-separated family names (default: all registered); "
        f"registered: {','.join(registered_types())}",
    )
    parser.add_argument(
        "--include",
        default="*.java",
        help="comma-separated git pathspecs for diffs (default: *.java)",
    )
    parser.add_argument(
        "--no-prefetch",
        action="store_true",
        help="skip the partial-clone blob prefetch step",
    )
    args = parser.parse_args(argv)

    types = [t.strip() for t in args.types.split(",")] if args.types else None
    globs = tuple(g.strip() for g in args.include.split(",") if g.strip())

    subset_paths = build(
        args.repo,
        args.root,
        name=args.name,
        types=types,
        include_globs=globs,
        prefetch=not args.no_prefetch,
    )

    name = args.name or Path(args.repo).name
    total = len(_load_commits(Path(args.root) / "commits" / name / "fix_commits.json"))
    print(f"sub-dataset build summary ({name})")
    print(f"  fix commits collected: {total}")
    for type_name, path in subset_paths.items():
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        commits = payload["commits"]
        first = commits[0]["commit_date"] if commits else "-"
        last = commits[-1]["commit_date"] if commits else "-"
        print(f"  {type_name}: {payload['count']} commits  ({first} .. {last})")
        print(f"    -> {path}")
    return 0


if __name__ == "__main__":  # pragma: no cover - manual CLI use
    raise SystemExit(main())
