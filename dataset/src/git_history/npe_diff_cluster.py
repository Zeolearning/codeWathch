"""Diff-based semantic clustering of null-pointer-exception (NPE) fix commits.

Motivation: commit messages are often too terse to separate real defect
topics ("fix NPE" tells nothing about WHERE the null was dereferenced).
The changed code lines carry that signal, so this module clusters by the
diff instead:

1. Pick the NPE-matched commits with the exact rules from
   ``git_history.npe_cluster`` (``_match_npe_commits``).
2. For each hash, ``git show --unified=0 --format= -- <globs>`` yields a
   context-free diff; parse it into deleted lines, added lines, and the
   changed file list (see ``collect_npe_diffs``). ``--unified=0`` drops
   unchanged context lines so only actual changes are embedded.
3. Build the embedding text as ``deleted lines + added lines + subject``
   (see ``_diff_text``). Subject only — bodies carry Signed-off-by /
   Co-authored-by footers that measurably pollute the embedding.
4. Embed / (optionally UMAP-reduce) / HDBSCAN-cluster / TF-IDF-label with
   the same machinery as ``cluster_fixes``, so reports stay comparable.

CLI: ``python -m git_history.npe_diff_cluster <repo>
<commits_json> <output_json> [--reduce-dims N]`` prints a human summary.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from pathlib import Path

from .cluster_fixes import (
    DEFAULT_MODEL_NAME,
    EmbeddingModel,
    _build_report,
    _cluster_embeddings,
    _embed_texts,
    _load_commits,
    _reduce_dimensions,
)
from .npe_cluster import (
    _match_npe_commits,
)

# Files whose diffs are embedded; a code fix lives in code files.
DEFAULT_INCLUDE_GLOBS: tuple[str, ...] = ("*.java",)

# Diff-side budgets. Embedding models truncate at ~512 tokens anyway; these
# caps keep pathological diffs (generated code, mass renames) from crowding
# out the other side or the subject.
_MAX_LINES_PER_SIDE = 200

# Diff header lines (from `git show --unified=0`) that are not +/- content.
_DIFF_HEADER_RE = re.compile(r"^(diff --git |index |@@ |old mode |new mode |new file mode |deleted file mode |rename |similarity |copy )")

# Report shaping.
_TOP_CLUSTERS_IN_SUMMARY = 5


def _git_diff(repo: Path, hash: str, include_globs: tuple[str, ...], *, retries: int = 3) -> str:
    """Context-free diff of ``hash`` (vs first parent) restricted to globs.

    Retries on transient proxy/TLS failures (partial clones lazy-fetch on
    any missing blob; the flaky proxy intermittently kills those HTTPS
    round trips). Each retry first self-heals by prefetching the commit's
    blobs — a no-op when everything is already local.
    """
    last_err = ""
    for attempt in range(1, retries + 1):
        proc = subprocess.run(
            ["git", "-C", str(repo), "show", "--unified=0", "--format=", hash, "--", *include_globs],
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
        if proc.returncode == 0:
            return proc.stdout
        last_err = proc.stderr.strip()[:500]
        try:  # self-heal then back off
            from .prefetch import prefetch_blobs

            prefetch_blobs(repo, [hash], include_globs=include_globs)
        except Exception:
            pass
        time.sleep(2 * attempt)
    raise RuntimeError(
        f"git show failed in {repo} for {hash[:12]} (rc=128) after {retries} attempts: {last_err}"
    )


def _parse_diff(diff: str) -> tuple[list[str], list[str], list[str]]:
    """Split a unified diff into (files, deleted_lines, added_lines).

    ``---``/``+++`` header lines and hunk headers are excluded, so a deleted
    line means real removed content (``-`` prefix stripped).
    """
    files: list[str] = []
    deleted: list[str] = []
    added: list[str] = []
    for line in diff.splitlines():
        if line.startswith(("+++ ", "--- ")):
            path = line[4:].strip()
            if path.startswith("b/"):  # the "+++ b/<path>" side names the file
                name = path[2:]
                if name != "/dev/null" and name not in files:
                    files.append(name)
            continue
        if _DIFF_HEADER_RE.match(line):
            continue
        if line.startswith("+"):
            added.append(line[1:].strip())
        elif line.startswith("-"):
            deleted.append(line[1:].strip())
    return files, deleted, added


def _diff_text(record: dict) -> str:
    """Text embedded per commit: deleted lines + added lines + subject.

    Order fixed by design: the removed code shows the defect site (where the
    null could flow), the added code shows the fix shape (guard, Optional,
    default value), and the subject anchors the intent. Non-empty lines only
    — blank +/- lines carry no signal but eat the token budget.
    """
    deleted = [ln.strip() for ln in record.get("deleted", []) if ln and ln.strip()]
    added = [ln.strip() for ln in record.get("added", []) if ln and ln.strip()]
    subject = str(record.get("subject") or "").strip()
    parts = ["deleted:", *deleted, "added:", *added]
    if subject:
        parts.append(f"message: {subject}")
    return "\n".join(parts)


def collect_diffs(
    repo_path: str | Path,
    commits_json_path: str | Path,
    output_path: str | Path | None = None,
    *,
    include_globs: tuple[str, ...] = DEFAULT_INCLUDE_GLOBS,
    commits: list[dict] | None = None,
) -> list[dict]:
    """Collect parsed diffs for arbitrary commits (not just NPE) in a repo.

    Args:
        repo_path: local git repository containing the commits.
        commits_json_path: fix-commits JSON from ``collect_fix_commits``
            (ignored when ``commits`` is given directly).
        output_path: optional destination JSON (parent dirs created) shaped
            ``{"repo", "include_globs", "count", "commits": [...]}``.
        include_globs: git pathspecs limiting which files' diffs are read.
        commits: optional in-memory commit list; overrides the JSON input.

    Returns:
        One dict per commit (input order): ``{"hash", "subject", "body",
        "message", "author_date", "commit_date", "files", "deleted",
        "added"}`` where ``deleted``/``added`` are raw code lines capped at
        ``_MAX_LINES_PER_SIDE`` each.

    Raises:
        RuntimeError: if a ``git show`` fails (e.g. hash missing in repo).
    """
    repo = Path(repo_path)
    if commits is None:
        commits = _load_commits(Path(commits_json_path))
    records: list[dict] = []
    for commit in commits:
        files, deleted, added = _parse_diff(_git_diff(repo, str(commit["hash"]), include_globs))
        record = dict(commit)
        record["files"] = files
        record["deleted"] = deleted[:_MAX_LINES_PER_SIDE]
        record["added"] = added[:_MAX_LINES_PER_SIDE]
        records.append(record)
    if output_path is not None:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "repo": str(repo),
            "include_globs": list(include_globs),
            "count": len(records),
            "commits": records,
        }
        out.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return records


def collect_npe_diffs(
    repo_path: str | Path,
    commits_json_path: str | Path,
    output_path: str | Path | None = None,
    *,
    include_globs: tuple[str, ...] = DEFAULT_INCLUDE_GLOBS,
) -> list[dict]:
    """Collect parsed diffs of the NPE-matched commits in a local git repo.

    Thin wrapper over the generic ``collect_diffs`` keeping only commits that
    match the NPE message patterns (see ``npe_cluster._match_npe_commits``).

    Args:
        repo_path: local git repository containing the commits.
        commits_json_path: fix-commits JSON from ``collect_fix_commits``.
        output_path: optional destination JSON (parent dirs created) shaped
            ``{"repo", "include_globs", "count", "commits": [...]}``.
        include_globs: git pathspecs limiting which files' diffs are read.

    Returns:
        One dict per NPE-matched commit (input order): ``{"hash", "subject",
        "body", "message", "matched_terms", "files", "deleted", "added"}``
        where ``deleted``/``added`` are raw code lines capped at
        ``_MAX_LINES_PER_SIDE`` each.

    Raises:
        RuntimeError: if a ``git show`` fails (e.g. hash missing in repo).
    """
    commits = _match_npe_commits(_load_commits(Path(commits_json_path)))
    return collect_diffs(
        repo_path,
        commits_json_path,
        output_path,
        include_globs=include_globs,
        commits=commits,
    )


def cluster_diff_records(
    records: list[dict],
    output_path: str | Path,
    model_name: str = DEFAULT_MODEL_NAME,
    *,
    embedding_model: EmbeddingModel | None = None,
    min_cluster_size: int = 3,
    reduce_dims: int | None = None,
    umap_n_neighbors: int = 15,
    umap_random_state: int = 42,
    excluded_count: int | None = None,
) -> dict:
    """Cluster already-collected diff records (any vulnerability family).

    Same pipeline and report schema as ``cluster_npe_diffs`` (embedding text
    is ``_diff_text``), but takes in-memory records instead of running the
    NPE filter — usable for any subset built by
    ``git_history.vuln_types``/``build_dataset``.
    """
    if records:
        texts = [_diff_text(r) for r in records]
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
        report = _build_report(records, texts, labels, model_name=model_name)
        report["reduction"] = reduction_label
    else:  # empty subset -> empty report, no model load, no error
        report = {
            "model": model_name,
            "reduction": None,
            "input_count": 0,
            "n_clusters": 0,
            "n_noise": 0,
            "clusters": [],
            "noise_hashes": [],
        }

    report["matched_total"] = len(records)
    report["excluded_count"] = 0 if excluded_count is None else excluded_count

    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


def cluster_npe_diffs(
    repo_path: str | Path,
    commits_json_path: str | Path,
    output_path: str | Path,
    model_name: str = DEFAULT_MODEL_NAME,
    *,
    embedding_model: EmbeddingModel | None = None,
    min_cluster_size: int = 3,
    reduce_dims: int | None = None,
    umap_n_neighbors: int = 15,
    umap_random_state: int = 42,
    include_globs: tuple[str, ...] = DEFAULT_INCLUDE_GLOBS,
) -> dict:
    """Collect NPE-commit diffs, cluster them semantically, write a report.

    Same pipeline and report schema as ``cluster_npe_commits`` (including
    ``matched_total``/``excluded_count``/``reduction``), except the embedding
    text is ``_diff_text`` (deleted + added code lines + subject) instead of
    the message alone.

    Commits whose restricted diff is empty (no ``*.java`` changes) are kept;
    their text degenerates to the subject, and they usually land in noise.

    Raises:
        RuntimeError: if ``git show`` or the embedding model fails (empty
            NPE matches never touch git or the model).
    """
    records = collect_npe_diffs(repo_path, commits_json_path, include_globs=include_globs)
    all_count = len(_load_commits(Path(commits_json_path)))
    return cluster_diff_records(
        records,
        output_path,
        model_name=model_name,
        embedding_model=embedding_model,
        min_cluster_size=min_cluster_size,
        reduce_dims=reduce_dims,
        umap_n_neighbors=umap_n_neighbors,
        umap_random_state=umap_random_state,
        excluded_count=all_count - len(records),
    )


def main(argv: list[str] | None = None) -> int:
    """CLI: collect NPE-commit diffs and cluster them semantically."""
    parser = argparse.ArgumentParser(
        prog="python -m git_history.npe_diff_cluster",
        description="Cluster NPE fix commits by their code diffs (deleted+added lines+subject).",
    )
    parser.add_argument("repo", help="local git repository containing the commits")
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
        help="UMAP-reduce embeddings to N dims (e.g. 10) before HDBSCAN; recommended",
    )
    parser.add_argument(
        "--umap-neighbors",
        type=int,
        default=15,
        metavar="K",
        help="UMAP n_neighbors when --reduce-dims is given (default: 15)",
    )
    parser.add_argument(
        "--include",
        default=",".join(DEFAULT_INCLUDE_GLOBS),
        help=f"comma-separated git pathspecs (default: {','.join(DEFAULT_INCLUDE_GLOBS)})",
    )
    args = parser.parse_args(argv)

    report = cluster_npe_diffs(
        args.repo,
        args.commits_json,
        args.output_json,
        model_name=args.model,
        min_cluster_size=args.min_cluster_size,
        reduce_dims=args.reduce_dims,
        umap_n_neighbors=args.umap_neighbors,
        include_globs=tuple(g.strip() for g in args.include.split(",") if g.strip()),
    )

    total = report["matched_total"] + report["excluded_count"]
    print("NPE diff-based clustering summary")
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
