from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from langchain_core.tools import tool

from code_watch.context import RepoContext


def make_write_file_tool(ctx: RepoContext):
    @tool
    def write_file(path: str, content: str) -> str:
        """Write content to a file inside the repo root (creates parent directories).

        Use this tool ONLY to persist a generated artifact (e.g. the final Semgrep rule
        YAML) to the exact path given in the task. Content overwrites any existing file.

        Args:
            path: relative path from repo root, or absolute path inside the repo.
            content: the full file content to write.
        """
        resolved = ctx.in_repo_path(path)
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(content, encoding="utf-8")
        return f"Wrote {len(content)} bytes to {resolved.relative_to(ctx.repo_root)}"

    return write_file


def make_submit_rule_tool(
    out_path: str,
    validator: Callable[[str], tuple[bool, str]] | None = None,
) -> tuple:
    """Deterministic submission tool with an optional validation hook.

    No path argument: the target is fixed at build time, so the LLM can only
    supply content and cannot write the rule to a wrong/arbitrary filename.

    When `validator` is given it runs as a hook on EVERY submission (e.g.
    `semgrep --validate`): the verdict is returned to the agent as the tool
    result, so a syntactically broken rule gets fixed within the same
    conversation turn instead of via an extra pipeline repair round.

    Returns (tool, validation_state); validation_state mirrors the last hook
    result: {"ok": bool | None, "msg": str} (ok=None before first submission).
    The rejected submission is still written to disk — it is the record of the
    agent's latest output.
    """
    target = Path(out_path)
    validation_state: dict = {"ok": None, "msg": ""}

    @tool
    def submit_rule(content: str) -> str:
        """Submit the final Semgrep rule. The output file path is fixed by the system.

        Every submission is validated with `semgrep --validate` automatically. If the
        tool result reports REJECTED, fix ONLY the reported syntax/schema problem
        (keep the detection semantics unchanged) and call submit_rule again.

        Args:
            content: the complete rule YAML, starting with `rules:`. Overwrites any
                previous submission.
        """
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        if validator is None:
            return f"Rule submitted ({len(content)} bytes)."
        ok, msg = validator(content)
        validation_state["ok"] = ok
        validation_state["msg"] = msg
        if ok:
            return f"Rule accepted — passed semgrep --validate ({len(content)} bytes)."
        return (
            "Rule REJECTED — semgrep --validate failed:\n"
            f"{msg[:2000]}\n"
            "Fix the syntax/schema problem (keep detection semantics unchanged) and "
            "call submit_rule again."
        )

    return submit_rule, validation_state
