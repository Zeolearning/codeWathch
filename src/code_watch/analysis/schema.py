from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class BugAnalysis(BaseModel):
    """Root-cause analysis of ONE Vul4J vulnerability case."""

    bug_id: str = Field(description="Vul4J case identifier, e.g. VUL4J-10")

    root_cause: str = Field(
        description=(
            "A single English sentence explaining the root cause. "
            "Must use propositional logic vocabulary: AND, OR, NOT. "
            "Example: 'DiskFileItem.get() reports a content type derived from "
            "the client-supplied filename AND the filename is not validated, "
            "OR the null byte truncates the name and bypasses the extension check.'"
        )
    )

    affected_files: list[str] = Field(
        description=(
            "List of file:line-range that are part of the root cause, "
            "relative to the vulnerable tree WITHOUT the vul/ prefix "
            "(e.g. src/main/java/org/.../DiskFileItem.java:340-360)."
        )
    )

    patch_src: str = Field(
        default="",
        description=(
            "Developer fix diff (git diff HEAD master -U0 -- '*.java' inside the "
            "vul4j checkout). The strongest signal for rule generation: what "
            "structurally changed to fix the vulnerability. Populated "
            "deterministically by analyze_case, not by the LLM."
        ),
    )

    reasoning_trace: list[Any] = Field(
        default_factory=list,
        description=(
            "Ordered reasoning steps: either dicts {'tool', 'args', 'result'} or plain strings."
        ),
    )

    logical_summary: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Structured breakdown of logical conditions. "
            "Example: {'conditions': [...], 'relation': 'AND/OR/NOT'}"
        ),
    )
