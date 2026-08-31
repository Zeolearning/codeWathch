from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

_SEMGREP = "semgrep"
_SEMGREP_TIMEOUT = 300  # seconds; large Java repos take a while


def validate_rule(rule_yaml: str) -> tuple[bool, str]:
    """Validate a Semgrep YAML rule. Returns (ok, message)."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8"
    ) as f:
        f.write(rule_yaml)
        path = f.name
    try:
        result = subprocess.run(
            [_SEMGREP, "--validate", "--config", path, "-q", "--json"],
            capture_output=True,
            text=True,
            timeout=_SEMGREP_TIMEOUT,
        )
    finally:
        Path(path).unlink(missing_ok=True)

    if result.returncode != 0:
        try:
            data = json.loads(result.stdout) if result.stdout.strip() else {}
        except json.JSONDecodeError:
            data = {}
        if data.get("errors"):
            msgs = "; ".join(e.get("long_msg") or e.get("message", "") for e in data["errors"])
            return False, msgs
        return False, f"semgrep --validate exited {result.returncode}: {result.stderr.strip()}"
    try:
        data = json.loads(result.stdout) if result.stdout.strip() else {}
    except json.JSONDecodeError:
        data = {}
    if data.get("errors"):
        msgs = "; ".join(e.get("long_msg") or e.get("message", "") for e in data["errors"])
        return False, msgs
    return True, ""


def scan_tree(rule_yaml: str, target_dir: Path) -> list[dict[str, Any]]:
    """Run `semgrep scan` on a target directory, return list of hit dicts.

    Each hit: {check_id, path, start_line, end_line, message}. Paths are relative
    to target_dir when possible (else absolute) so they line up with affected_files.
    """
    # Resolve to an absolute path: the subprocess below cds into target_dir
    # (cwd=), so a relative target argument would be resolved by the child
    # against its NEW cwd and point at a nonexistent doubled path.
    target_dir = Path(target_dir).resolve()
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8"
    ) as f:
        f.write(rule_yaml)
        rule_path = f.name
    try:
        result = subprocess.run(
            [_SEMGREP, "scan", "--json", "--config", rule_path, str(target_dir)],
            capture_output=True,
            text=True,
            timeout=_SEMGREP_TIMEOUT,
            cwd=str(target_dir),
        )
    finally:
        Path(rule_path).unlink(missing_ok=True)

    # semgrep exits 0 normally (findings included); non-zero means a config/runtime
    # error. Surface it instead of silently reporting zero hits (which would be
    # miscounted as FN downstream).
    if result.returncode != 0:
        # semgrep reports config errors (e.g. an invalid scanning root) in the
        # stdout JSON, not stderr — include both.
        detail = (result.stderr.strip() or result.stdout.strip())[:500]
        raise RuntimeError(
            f"semgrep scan exited {result.returncode}: {detail}"
        )

    try:
        data = json.loads(result.stdout) if result.stdout.strip() else {}
    except json.JSONDecodeError:
        raise RuntimeError("semgrep scan produced unparseable JSON output") from None

    hits: list[dict[str, Any]] = []
    for r in data.get("results", []):
        p = r.get("path", "")
        try:
            rel = str(Path(p).relative_to(target_dir))
        except ValueError:
            rel = p
        start = r.get("start", {})
        end = r.get("end", {})
        hits.append({
            "check_id": r.get("check_id", ""),
            "path": rel,
            "start_line": start.get("line", 0),
            "end_line": end.get("line", 0),
            "message": r.get("extra", {}).get("message", ""),
        })
    return hits


def hits_as_file_colon_lines(hits: list[dict[str, Any]]) -> list[str]:
    """Format hits as 'file:line' strings (one per hit)."""
    return [f"{h['path']}:{h['start_line']}" for h in hits if h.get("start_line")]
