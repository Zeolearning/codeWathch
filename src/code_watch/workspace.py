"""Materialize git-mined cases into vul/fix tree pairs for the rule pipeline.

A "case" is one fix commit from the mined dataset. The rule generation loop
needs the buggy tree (commit's parent) and the fixed tree (the commit) on
disk; instead of checking out the shared clone — global mutable state that
breaks reproducibility and parallel runs — each side is extracted with::

    git archive --format=tar <sha> | tar -x -C <dir>

Read-only on the repo, no locks, parallel-safe. The FULL tree is extracted
(no path filter): bug logic often lives outside the files the fix touched
(helper classes, cross-file call chains), and the analysis agent needs to
follow it. The fix-touched files are still recorded in meta.json/patch.diff.
Workspaces are regenerable by construction; clean the cluster workspace
(see clean_cluster) once the merge stage has synthesized the final rule.

Workspace layout (fixed name, direct overwrite on re-materialize)::

    workspace/<repo>-<vtype>-c<cluster_id>/
      case-<i>/meta.json      # provenance: hashes, files, seq, subject, sample info
      case-<i>/patch.diff     # git diff --unified=0 <parent> <fix> -- <files>
      case-<i>/vul/...        # FULL parent tree snapshot  (buggy)
      case-<i>/fix/...        # FULL fix tree snapshot     (patched)

The ``vul/`` / ``fix/`` directory names intentionally reuse the analysis
agent's existing two-tree convention, so all prompts and tools work unchanged.
"""
from __future__ import annotations

import json
import random
import shutil
import subprocess
import tarfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path

DEFAULT_WORKSPACE_ROOT = Path("workspace")


@dataclass(frozen=True)
class GitCase:
    """One fix commit materialized as a vul(parent)/fix(commit) tree pair."""

    case_id: str            # e.g. "dubbo-npe-c6-1"
    repo: str               # dataset repo name, e.g. "dubbo"
    vtype: str              # vulnerability family, e.g. "npe"
    cluster_id: int
    cluster_label: str
    seq: int                # commit's seq in the type subset (time order)
    fix_hash: str
    parent_hash: str
    subject: str
    files: tuple[str, ...]  # repo-relative java paths the fix touched
    workspace: Path         # case dir: meta.json / patch.diff / vul / fix

    @property
    def meta_path(self) -> Path:
        return self.workspace / "meta.json"

    @property
    def patch_path(self) -> Path:
        return self.workspace / "patch.diff"

    @property
    def vul_dir(self) -> Path:
        return self.workspace / "vul"

    @property
    def fix_dir(self) -> Path:
        return self.workspace / "fix"

    @property
    def patch_src(self) -> str:
        return self.patch_path.read_text(encoding="utf-8")

    @classmethod
    def load(cls, case_dir: str | Path) -> "GitCase":
        """Rehydrate a case from its materialized meta.json."""
        meta = json.loads((Path(case_dir) / "meta.json").read_text(encoding="utf-8"))
        return cls(
            case_id=meta["case_id"],
            repo=meta["repo"],
            vtype=meta["vtype"],
            cluster_id=meta["cluster_id"],
            cluster_label=meta.get("cluster_label", ""),
            seq=meta.get("seq", 0),
            fix_hash=meta["fix_hash"],
            parent_hash=meta["parent_hash"],
            subject=meta.get("subject", ""),
            files=tuple(meta.get("files", [])),
            workspace=Path(case_dir),
        )


def _git(repo_path: Path, args: list[str]) -> bytes:
    proc = subprocess.run(
        ["git", "-C", str(repo_path), *args], capture_output=True, check=False
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args[:2])}... failed in {repo_path} (rc={proc.returncode}): "
            f"{proc.stderr.decode('utf-8', 'replace').strip()[:300]}"
        )
    return proc.stdout


def _archive_to(repo_path: Path, sha: str, dest: Path, *, files: list[str] | None = None) -> None:
    """Extract the tree of `sha` into `dest` (repo-relative paths kept).

    `files` restricts extraction to given paths; None (default) extracts the
    FULL tree.
    """
    args = ["archive", "--format=tar", sha]
    if files is not None:
        args += ["--", *files]
    tar_bytes = _git(repo_path, args)
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=BytesIO(tar_bytes), mode="r:") as tf:
        tf.extractall(dest, filter="data")  # noqa: S202 - paths come from our own repo trees


def resolve_parent(repo_path: Path, fix_hash: str) -> str:
    """First parent of the fix commit (the buggy version). Fails on root commits."""
    proc = subprocess.run(
        ["git", "-C", str(repo_path), "rev-parse", "--verify", f"{fix_hash}^"],
        capture_output=True, check=False, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"no parent for {fix_hash} (root commit?): {proc.stderr.strip()}")
    return proc.stdout.strip()


def materialize_case(
    repo_path: Path,
    *,
    case_id: str,
    repo: str,
    vtype: str,
    cluster_id: int,
    cluster_label: str,
    seq: int,
    fix_hash: str,
    subject: str,
    commit_date: str,
    files: list[str],
    dest: Path,
) -> GitCase:
    """Materialize one case: vul/fix archives + patch.diff + meta.json (overwrites dest)."""
    parent_hash = resolve_parent(repo_path, fix_hash)

    if dest.exists():
        shutil.rmtree(dest)

    _archive_to(repo_path, parent_hash, dest / "vul")   # full buggy tree
    _archive_to(repo_path, fix_hash, dest / "fix")      # full patched tree
    (dest / "patch.diff").write_bytes(
        _git(repo_path, ["diff", "--unified=0", parent_hash, fix_hash, "--", *files])
    )
    case = GitCase(
        case_id=case_id, repo=repo, vtype=vtype, cluster_id=cluster_id,
        cluster_label=cluster_label, seq=seq, fix_hash=fix_hash,
        parent_hash=parent_hash, subject=subject, files=tuple(files), workspace=dest,
    )
    dest.mkdir(parents=True, exist_ok=True)
    case.meta_path.write_text(
        json.dumps(
            {
                **{k: getattr(case, k) for k in (
                    "case_id", "repo", "vtype", "cluster_id", "cluster_label", "seq",
                    "fix_hash", "parent_hash", "subject", "files",
                )},
                "commit_date": commit_date,
            },
            indent=2, ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    return case


def clean_cluster(
    cluster_dir: str | Path, *, workspace_root: str | Path = DEFAULT_WORKSPACE_ROOT
) -> None:
    """Delete one cluster workspace. Called after the merge stage synthesized
    the final rule — trees are regenerable anytime via materialize_cluster."""
    target = Path(cluster_dir)
    if not target.is_absolute():
        target = Path(workspace_root) / cluster_dir
    shutil.rmtree(target, ignore_errors=True)


def materialize_cluster(
    cluster_report_path: str | Path,
    subset_path: str | Path,
    diffs_path: str | Path,
    repo_path: str | Path,
    *,
    cluster_id: int | None = None,
    k: int = 5,
    seed: int = 42,
    workspace_root: str | Path = DEFAULT_WORKSPACE_ROOT,
) -> tuple[list[GitCase], int]:
    """Sample k commits from one cluster and materialize them as cases.

    Cluster selection: explicit `cluster_id`, else the largest cluster in the
    report. Sampling is seeded over the cluster's hash list (which follows the
    subset's commit_date order) — same report + seed => same cases. The
    workspace directory is fixed (`<repo>-<vtype>-c<id>`) and fully rebuilt.

    Returns (cases, cluster_id).
    """
    report = json.loads(Path(cluster_report_path).read_text(encoding="utf-8"))
    subset = json.loads(Path(subset_path).read_text(encoding="utf-8"))
    diffs = json.loads(Path(diffs_path).read_text(encoding="utf-8"))

    clusters = report.get("clusters", [])
    if not clusters:
        raise RuntimeError(f"no clusters in {cluster_report_path}")
    cluster = next((c for c in clusters if c["id"] == cluster_id), None) if cluster_id is not None else None
    if cluster is None:
        cluster = clusters[0]  # report is sorted by size desc
        if cluster_id is not None:
            raise RuntimeError(f"cluster {cluster_id} not found in {cluster_report_path}")
    cluster_id = int(cluster["id"])

    repo = subset.get("repo", Path(repo_path).name)
    vtype = subset.get("type", Path(subset_path).parent.name)
    by_hash = {c["hash"]: c for c in subset.get("commits", [])}
    files_by_hash = {c["hash"]: c.get("files", []) for c in diffs.get("commits", [])}

    members = list(cluster["hashes"])
    sample = random.Random(seed).sample(members, min(k, len(members)))

    ws_dir = Path(workspace_root) / f"{repo}-{vtype}-c{cluster_id}"
    if ws_dir.exists():
        shutil.rmtree(ws_dir)

    cases: list[GitCase] = []
    for i, fix_hash in enumerate(sample, start=1):
        meta = by_hash.get(fix_hash, {})
        cases.append(
            materialize_case(
                Path(repo_path),
                case_id=f"{repo}-{vtype}-c{cluster_id}-{i}",
                repo=repo,
                vtype=vtype,
                cluster_id=cluster_id,
                cluster_label=cluster.get("label", ""),
                seq=int(meta.get("seq", 0)),
                fix_hash=fix_hash,
                subject=str(meta.get("subject", "")),
                commit_date=str(meta.get("commit_date", "")),
                files=list(files_by_hash.get(fix_hash, [])),
                dest=ws_dir / f"case-{i}",
            )
        )
    return cases, cluster_id
