from __future__ import annotations

import csv
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from code_watch.dataset.schema import CaseInfo

# Repo root of the codeWatch project (src/code_watch/dataset/vul4j.py -> parents[3]).
_REPO_ROOT = Path(__file__).resolve().parents[3]

# Local clone of https://github.com/tuhh-softsec/Vul4J (CLI + dataset CSV).
VUL4J_REPO = Path(os.getenv("VUL4J_GIT") or str(_REPO_ROOT / "vul4j"))

DATASET_CSV = VUL4J_REPO / "dataset" / "vul4j_dataset.csv"

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def _parse_case(row: dict[str, str]) -> CaseInfo:
    case_id = row["vul_id"].strip()
    slug = row["repo_slug"].strip()
    patch_url = row["human_patch"].strip()
    return CaseInfo(
        case_id=case_id,
        repo_slug=slug,
        project=slug.rsplit("/", 1)[-1] if "/" in slug else slug,
        cve_id=row.get("cve_id", "").strip(),
        cwe_id=row.get("cwe_id", "").strip(),
        cwe_name=row.get("cwe_name", "").strip(),
        owasp_id=row.get("owasp_id", "").strip(),
        fix_commit_url=patch_url,
        fix_commit=patch_url.rsplit("/", 1)[-1] if patch_url else "",
        build_system=row.get("build_system", "").strip(),
        src_dir=row.get("src", "").strip(),
        test_dir=row.get("test", "").strip(),
        failing_tests=row.get("failing_tests", "").strip(),
        warning=row.get("warning", "").strip(),
        is_pov=not case_id.endswith("-S"),
    )


def load_cases() -> dict[str, CaseInfo]:
    """Parse dataset/vul4j_dataset.csv into {case_id: CaseInfo}."""
    if not DATASET_CSV.is_file():
        raise FileNotFoundError(
            f"Vul4J dataset not found at {DATASET_CSV}. "
            f"Clone https://github.com/tuhh-softsec/Vul4J (gitignored as ./vul4j) or set VUL4J_GIT."
        )
    with open(DATASET_CSV, newline="", encoding="utf-8") as f:
        rows = [r for r in csv.DictReader(f) if r.get("vul_id", "").strip()]
    cases = {_parse_case(r).case_id: _parse_case(r) for r in rows}
    return dict(sorted(cases.items(), key=lambda kv: (len(kv[0]), kv[0])))


def load_case(case_id: str) -> CaseInfo:
    cases = load_cases()
    if case_id not in cases:
        raise KeyError(f"Unknown Vul4J id: {case_id} (dataset has {len(cases)} cases)")
    return cases[case_id]


def resolve_case_ids(spec: str, cases: dict[str, CaseInfo] | None = None) -> list[str]:
    """Resolve a case spec into an ordered list of known case ids.

    Supported forms (comma-separated tokens):
      - "all"    : every case in the dataset
      - "pov"    : VUL4J-1..79 (Proof-of-Vulnerability group)
      - "sb"     : the 50 SpotBugs-only entries (ids ending in -S)
      - exact id : "VUL4J-10", "VUL4J-80-S"
      - bare num : "10" -> "VUL4J-10" (PoV group)
      - range    : "1-10" -> VUL4J-1..VUL4J-10 (numeric, PoV group only)

    Raises ValueError listing unknown ids.
    """
    if cases is None:
        cases = load_cases()

    def _expand(token: str) -> list[str]:
        token = token.strip()
        if not token:
            return []
        if token == "all":
            return list(cases)
        if token == "pov":
            return [cid for cid in cases if cases[cid].is_pov]
        if token == "sb":
            return [cid for cid in cases if not cases[cid].is_pov]
        if token in cases:
            return [token]
        if token.isdigit():
            cid = f"VUL4J-{token}"
            return [cid] if cid in cases else []
        if re.fullmatch(r"\d+-S", token):
            cid = f"VUL4J-{token}"
            return [cid] if cid in cases else []
        m = re.fullmatch(r"(\d+)-(\d+)", token)
        if m:
            lo, hi = int(m.group(1)), int(m.group(2))
            if lo >= 1 and hi >= lo:
                return [f"VUL4J-{i}" for i in range(lo, hi + 1) if f"VUL4J-{i}" in cases]
        raise ValueError(f"Unknown case token '{token}'")

    out: list[str] = []
    seen: set[str] = set()
    for token in spec.split(","):
        for cid in _expand(token):
            if cid not in seen:
                seen.add(cid)
                out.append(cid)
    unknown = [t.strip() for t in spec.split(",") if t.strip() and not _exists(t.strip(), cases)]
    if unknown:
        raise ValueError(
            f"Unknown case ids: {', '.join(unknown)}. "
            f"Dataset has {len(cases)} cases (use 'pov', 'sb', 'all', or explicit ids)."
        )
    if not out:
        raise ValueError(f"No cases resolved from spec '{spec}'")
    return out


def _exists(token: str, cases: dict[str, CaseInfo]) -> bool:
    if token in ("all", "pov", "sb"):
        return True
    if token in cases:
        return True
    if token.isdigit():
        return f"VUL4J-{token}" in cases
    if re.fullmatch(r"\d+-S", token):
        return f"VUL4J-{token}" in cases
    if re.fullmatch(r"\d+-\d+", token):
        return True
    return False


def _run(cmd: list[str], *, timeout: int = 1800) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)


def _vul4j_checkout(case_id: str, workdir: Path) -> None:
    """Run the official `vul4j checkout` CLI into workdir (vulnerable tree)."""
    proc = _run([
        "uv", "run", "--project", str(VUL4J_REPO),
        "vul4j", "checkout", "-i", case_id, "-d", str(workdir),
    ])
    if proc.returncode != 0 or not (workdir / ".git").is_dir():
        raise RuntimeError(
            f"vul4j checkout failed for {case_id} (rc={proc.returncode}):\n"
            f"STDOUT: {proc.stdout[-2000:]}\nSTDERR: {proc.stderr[-2000:]}"
        )


def _strip_vul4j_copies(tree: Path) -> None:
    """Remove the raw VUL4J/vulnerable + VUL4J/human_patch copy dirs the CLI
    leaves inside a checkout.

    The copies are untracked (they never appear in ``git diff HEAD master``),
    but the vulnerable copy inside the fix tree is a false-FP source for the
    differential oracle — a rule matching the bug would legitimately hit it.
    Idempotent, so pre-fix cached checkouts get cleaned on next use too.
    """
    copies = tree / "VUL4J"
    if copies.is_dir():
        shutil.rmtree(copies, ignore_errors=True)


def checkout_pair(
    case_id: str,
    *,
    base_dir: str | None = None,
    refresh: bool = False,
    pair: bool = True,
) -> tuple[Path, Path, Path]:
    """Materialize vulnerable + fixed trees side by side.

    Layout:
        <parent>/vul/   vulnerable tree (vul4j checkout: detached HEAD)
        <parent>/fix/   fixed tree (copy of vul/ with `git checkout master`)

    The vul4j checkout leaves a 2-commit repo: detached HEAD = "vulnerable",
    master = "human_patch". The fix tree is a copy of that repo checked out on
    master, so both trees share one parent dir for path-jailed agents. The raw
    VUL4J/ copy dirs the CLI leaves inside each tree are stripped (see
    _strip_vul4j_copies) so scans never see duplicated vulnerable sources.

    With ``pair=False`` only the vulnerable tree is materialized (rule-scanning
    holdout does not need the fixed tree); the returned fix path may not exist.

    Cached: existing trees are reused unless refresh=True.
    """
    if base_dir is None:
        parent = Path(tempfile.mkdtemp(prefix=f"vul4j-{case_id}-"))
    else:
        parent = Path(base_dir)
    if parent.resolve().is_relative_to(VUL4J_REPO.resolve()):
        raise ValueError(
            f"checkout dir must live outside the Vul4J repo (vul4j cleans its own tree): {parent}"
        )

    vul_dir = parent / "vul"
    fix_dir = parent / "fix"
    parent.mkdir(parents=True, exist_ok=True)

    if refresh or not (vul_dir / ".git").is_dir():
        if vul_dir.exists():
            shutil.rmtree(vul_dir)
        _vul4j_checkout(case_id, vul_dir)
    _strip_vul4j_copies(vul_dir)

    if pair and (refresh or not (fix_dir / ".git").is_dir()):
        if fix_dir.exists():
            shutil.rmtree(fix_dir)
        shutil.copytree(vul_dir, fix_dir, symlinks=True)
        proc = _run(["git", "-C", str(fix_dir), "checkout", "master"])
        if proc.returncode != 0:
            raise RuntimeError(f"git checkout master failed in {fix_dir}: {proc.stderr[-500:]}")
    if pair:
        _strip_vul4j_copies(fix_dir)

    return parent, vul_dir, fix_dir


def compute_patch(vul_dir: Path | str) -> str:
    """Unified diff (U0) of vulnerable -> human_patch, Java sources only.

    `git diff HEAD master` inside the checkout repo; paths carry the usual
    a/ b/ prefixes with no extra directory component.
    """
    proc = _run(["git", "-C", str(vul_dir), "diff", "-U0", "HEAD", "master", "--", "*.java"])
    if proc.returncode != 0:
        raise RuntimeError(f"git diff HEAD master failed in {vul_dir}: {proc.stderr[:300]}")
    return proc.stdout


def expected_from_patch(patch: str) -> dict[str, set[int]]:
    """Parse a `git diff -U0` patch into {file: vulnerable-side line numbers}.

    Logic migrated from rules/holdout.py::parse_diff_expected (buggy_prefix="")
    so the dataset layer stays dependency-free of code_watch.rules. Only the
    deletion side counts: those are the vulnerable lines the fix touched.
    Pure-addition hunks record the insertion point (missing-guard location).
    """
    expected: dict[str, set[int]] = {}
    current_file: str | None = None
    lines = patch.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("--- "):
            p = line[4:].strip()
            nxt = lines[i + 1] if i + 1 < len(lines) else ""
            if not nxt.startswith("+++ "):
                current_file = None
            elif p.startswith("a/"):
                current_file = p[2:]
            else:
                current_file = None
        elif line.startswith("@@") and current_file:
            m = _HUNK_RE.match(line)
            if not m:
                continue
            start = int(m.group(1))
            count = int(m.group(2) or "1")
            if count > 0:
                expected.setdefault(current_file, set()).update(range(start, start + count))
            elif start > 0:
                expected.setdefault(current_file, set()).update({start, start + 1})
            else:
                expected.setdefault(current_file, set()).add(1)
    return expected
