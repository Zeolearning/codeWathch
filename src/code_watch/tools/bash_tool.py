from __future__ import annotations

import shlex
import subprocess
from pathlib import Path

from langchain_core.tools import tool

from code_watch.context import RepoContext

_ALLOWED_COMMANDS: dict[str, set[str] | None] = {
    # git subcommands that are read-only (no write to refs/objects/index)
    "git": {
        "log", "diff", "show", "status", "branch", "rev-parse", "ls-files",
        "grep", "blame", "annotate", "describe", "shortlog", "whatchanged",
        "name-rev", "ls-tree", "cat-file", "check-attr", "check-ignore",
        "check-mailmap", "help", "version", "for-each-ref", "count-objects",
        "var", "verify-commit", "verify-tag", "hash-object",
    },
    # Content search (use the grep tool instead for most cases)
    "rg": None,
    # File reading and analysis tools (all flags/paths allowed)
    "grep": None,
    "find": None,
    "wc": None,
    "file": None,
    "stat": None,
    "sort": None,
    "uniq": None,
    "cut": None,
    "diff": None,
    "tac": None,
    "nl": None,
    "fold": None,
    "expand": None,
    "unexpand": None,
    "od": None,
    "xxd": None,
    "strings": None,
    "comm": None,
    "iconv": None,
    "basename": None,
    "dirname": None,
    "readlink": None,
    "realpath": None,
    "du": None,
    "which": None,
    "ls": None,
    "pwd": None,
    # Maven read-only goals
    "mvn": {"help", "dependency", "validate"},
}

_FORBIDDEN_METACHARS = set(";|`$()<>{}\n")


def _validate_segment(seg: list[str]) -> tuple[bool, str]:
    """Validate a single command segment (may come from a && chain)."""
    if not seg:
        return False, "empty command segment"
    base = Path(seg[0]).name
    if base not in _ALLOWED_COMMANDS:
        return False, (
            f"command not allowed: {base}. "
            f"Allowed: {sorted(_ALLOWED_COMMANDS)}"
        )
    allowed_sub = _ALLOWED_COMMANDS[base]
    if allowed_sub is None:
        return True, ""
    if len(seg) > 1 and seg[1] not in allowed_sub:
        return False, (
            f"subcommand not allowed for {base}; "
            f"allowed: {sorted(allowed_sub)}"
        )
    return True, ""


def is_safe_command(command: str) -> tuple[bool, str]:
    """Check if the command is read-only and from the allow-list.

    Supports ``git log && git status``-style && chains: every command
    in the chain is validated independently.  Standalone ``&`` (background
    operator) is rejected.
    """
    if not command or not command.strip():
        return False, "empty command"

    # Reject standalone & (background operator) but allow &&
    if "&" in command.replace("&&", ""):
        return False, "standalone '&' not allowed (use && to chain commands)"

    for ch in _FORBIDDEN_METACHARS:
        if ch in command:
            return False, f"shell metacharacter {ch!r} not allowed"

    try:
        parts = shlex.split(command)
    except ValueError as e:
        return False, f"failed to parse command: {e}"
    if not parts:
        return False, "empty command"

    # Split on && to validate each segment in a chain
    segments: list[list[str]] = []
    current: list[str] = []
    for p in parts:
        if p == "&&":
            segments.append(current)
            current = []
        else:
            current.append(p)
    segments.append(current)

    for seg in segments:
        ok, reason = _validate_segment(seg)
        if not ok:
            return False, reason

    return True, ""


def make_bash_tool(ctx: RepoContext):
    @tool
    def bash(
        command: str,
        workdir: str = "",
        timeout: int = 120000,
    ) -> str:
        """Run a read-only shell command.

        Do NOT use this tool for tasks covered by dedicated tools:
        - File search: use glob (NOT find or ls)
        - Content search: use grep (NOT rg from bash)
        - Read files: use read_file (NOT cat/head/tail)

        Commands can be chained with && (each command is validated).
        Standalone & (background) is not allowed.
        Allowed commands: git (various read-only subcommands), rg, grep, find,
        wc, file, stat, sort, uniq, cut, diff, strings, od, xxd, nl, tac,
        fold, expand, unexpand, comm, iconv, basename, dirname, readlink,
        realpath, du, which, ls, pwd, mvn (help|dependency|validate).
        Never modifies state. Use `workdir` instead of `cd <dir> && <command>`.

        Args:
            command: the shell command to run (must be read-only).
            workdir: working directory relative to repo root (default = repo root).
                     Use instead of `cd <dir> && <command>`.
            timeout: timeout in milliseconds (default 120000).
        """
        safe, reason = is_safe_command(command)
        if not safe:
            return f"ERROR: {reason}"

        cwd = str(ctx.repo_root)
        if workdir:
            try:
                cwd = str(ctx.in_repo_path(workdir))
            except PermissionError as e:
                return f"ERROR: {e}"

        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout / 1000,
                cwd=cwd,
            )
            if result.returncode != 0:
                stderr = result.stderr.strip()[:1000]
                return f"Command exited with code {result.returncode}:\n{result.stdout[:2000]}\n{stderr}"
            output = result.stdout.strip()
            if not output:
                return "(no output)"
            limit = 5000
            if len(output) > limit:
                output = output[:limit] + "\n... (output truncated)"
            return output
        except subprocess.TimeoutExpired:
            return f"ERROR: command timed out after {timeout}ms"
        except Exception as e:
            return f"ERROR: {e}"

    return bash
