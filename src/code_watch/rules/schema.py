from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class Rule(BaseModel):
    """A Semgrep YAML rule generated from a defect analysis."""

    rule_id: str = Field(description="Unique rule id, e.g. dubbo-npe-c6-1-r1")
    bug_id: str = Field(description="Provenance case id, e.g. dubbo-npe-c6-1")
    language: str = Field(default="java")
    yaml: str = Field(description="Complete Semgrep YAML rule text (rules: [...])")
    message: str = Field(default="", description="Human-readable match message")
    severity: str = Field(default="ERROR")
    mode: str = Field(default="pattern", description='"pattern" | "taint"')
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Generation metadata: model, prompt version, temperature, timestamp",
    )


class MethodPair(BaseModel):
    fqcn: str
    method_signature: str
    buggy_source: str
    fixed_source: str


class ASTNodeDelta(BaseModel):
    node_type: str = Field(description="tree-sitter AST node type")
    buggy_text: Optional[str] = None
    fixed_text: Optional[str] = None
    change: str = Field(
        description=(
            '"added_in_buggy" = node present in buggy, absent in fixed '
            "(the bug pattern — the rule SHOULD match this); "
            '"added_in_fixed" = node present in fixed, absent in buggy '
            "(the fix's addition, e.g. a new guard — the rule should NOT match this); "
            '"changed" = positional mismatch (text differs at same slot)'
        )
    )


class MethodASTDelta(BaseModel):
    method: MethodPair
    deltas: list[ASTNodeDelta] = Field(default_factory=list)


class FixDelta(BaseModel):
    """Aggregated structural delta between buggy and fixed trees."""

    bug_id: str
    method_deltas: list[MethodASTDelta] = Field(default_factory=list)


class RuleEvaluation(BaseModel):
    """Result of testing a rule against buggy/fixed trees."""

    rule_id: str
    bug_id: str
    syntax_ok: bool
    fired_on_buggy: list[str] = Field(default_factory=list, description='"file:line" hits on buggy tree')
    fired_on_fixed: list[str] = Field(default_factory=list, description='"file:line" hits on fixed tree')
    expected: list[str] = Field(default_factory=list, description="affected_files from BugAnalysis")
    precision: float = 0.0
    recall: float = 0.0
    status: str = Field(description='"PASS" | "FP" | "FN" | "SYNTAX_ERROR"')
    validation_msg: str = Field(default="", description="semgrep --validate error detail when syntax_ok is False")
