from __future__ import annotations

from collections import defaultdict
from typing import Any

from code_watch.dataset.vul4j import load_cases
from code_watch.rules.schema import RuleEvaluation


def _project_of(bug_id: str, cases) -> str:
    info = cases.get(bug_id)
    return info.project if info else (bug_id.rsplit("-", 1)[0] if "-" in bug_id else bug_id)


def _cwe_of(bug_id: str, cases) -> str:
    info = cases.get(bug_id)
    return (info.cwe_id or "unknown") if info else "-"


def passk(evals_per_bug: dict[str, list[RuleEvaluation]], k: int = 1) -> float:
    """pass@k: fraction of bugs where at least one of the first k attempts PASSed.

    Mirrors RuleRefiner's scripts/semgrep_view_results.py:8 passk idea: group attempts by
    bug id, success iff any attempt's status == PASS.
    """
    if not evals_per_bug:
        return 0.0
    passed = 0
    for bug_id, attempts in evals_per_bug.items():
        if any(a.status == "PASS" for a in attempts[:k]):
            passed += 1
    return round(passed / len(evals_per_bug), 4)


def _macro(evals: list[RuleEvaluation]) -> tuple[float, float]:
    if not evals:
        return 0.0, 0.0
    p = sum(e.precision for e in evals) / len(evals)
    r = sum(e.recall for e in evals) / len(evals)
    return round(p, 4), round(r, 4)


def _micro(evals: list[RuleEvaluation]) -> tuple[float, float]:
    """Micro = sum(hit_expected)/sum(expected) for recall, sum(hit_expected)/sum(reported) for precision.

    We approximate hit_expected = recall * |expected| and reported = hit_expected/precision when
    precision>0, reconstructing from per-rule aggregates (the raw line sets aren't on the model).
    """
    sum_expected = 0.0
    sum_hit = 0.0
    sum_reported = 0.0
    for e in evals:
        n_exp = len(e.expected)
        hit = e.recall * n_exp
        rep = hit / e.precision if e.precision > 0 else 0.0
        sum_expected += n_exp
        sum_hit += hit
        sum_reported += rep
    micro_p = sum_hit / sum_reported if sum_reported else 0.0
    micro_r = sum_hit / sum_expected if sum_expected else 0.0
    return round(micro_p, 4), round(micro_r, 4)


class BatchReport:
    """Aggregate report over a batch of bug rule-creation runs."""

    def __init__(self, evals: list[RuleEvaluation]):
        self.evals = evals
        try:
            cases = load_cases()
        except Exception:
            cases = {}
        # group by bug_id (one attempt per bug for now), dataset project, and CWE
        self._by_bug: dict[str, list[RuleEvaluation]] = defaultdict(list)
        self._by_project: dict[str, list[RuleEvaluation]] = defaultdict(list)
        self._by_cwe: dict[str, list[RuleEvaluation]] = defaultdict(list)
        for e in evals:
            self._by_bug[e.bug_id].append(e)
            self._by_project[_project_of(e.bug_id, cases)].append(e)
            self._by_cwe[_cwe_of(e.bug_id, cases)].append(e)

    @property
    def total(self) -> int:
        return len(self.evals)

    @property
    def passed(self) -> int:
        return sum(1 for e in self.evals if e.status == "PASS")

    @property
    def pass_at_1(self) -> float:
        return passk(dict(self._by_bug), k=1)

    @property
    def macro_precision(self) -> float:
        p, _ = _macro(self.evals)
        return p

    @property
    def macro_recall(self) -> float:
        _, r = _macro(self.evals)
        return r

    @property
    def micro_precision(self) -> float:
        p, _ = _micro(self.evals)
        return p

    @property
    def micro_recall(self) -> float:
        _, r = _micro(self.evals)
        return r

    def _group_stats(self, evals: list[RuleEvaluation]) -> dict[str, Any]:
        mp, mr = _macro(evals)
        return {
            "count": len(evals),
            "pass": sum(1 for e in evals if e.status == "PASS"),
            "macro_precision": mp,
            "macro_recall": mr,
        }

    def by_project(self) -> dict[str, dict[str, Any]]:
        return {proj: self._group_stats(es) for proj, es in self._by_project.items()}

    def by_cwe(self) -> dict[str, dict[str, Any]]:
        return {cwe: self._group_stats(es) for cwe, es in self._by_cwe.items()}

    def to_markdown(self) -> str:
        lines = [
            "# Rules Batch Report",
            "",
            f"- total bugs: {self.total}",
            f"- passed: {self.passed}",
            f"- pass@1: {self.pass_at_1}",
            f"- macro precision: {self.macro_precision}",
            f"- macro recall: {self.macro_recall}",
            f"- micro precision: {self.micro_precision}",
            f"- micro recall: {self.micro_recall}",
            "",
            "## Per-bug results",
            "",
            "| bug_id | status | precision | recall | fired_buggy | fired_fixed |",
            "|---|---|---|---|---|---|",
        ]
        for e in self.evals:
            lines.append(
                f"| {e.bug_id} | {e.status} | {e.precision} | {e.recall} | "
                f"{len(e.fired_on_buggy)} | {len(e.fired_on_fixed)} |"
            )
        lines += ["", "## Per-project", "", "| project | count | pass | macro_p | macro_r |", "|---|---|---|---|---|"]
        for proj, stats in sorted(self.by_project().items()):
            lines.append(
                f"| {proj} | {stats['count']} | {stats['pass']} | "
                f"{stats['macro_precision']} | {stats['macro_recall']} |"
            )
        lines += ["", "## Per-CWE", "", "| CWE | count | pass | macro_p | macro_r |", "|---|---|---|---|---|"]
        for cwe, stats in sorted(self.by_cwe().items()):
            lines.append(
                f"| {cwe} | {stats['count']} | {stats['pass']} | "
                f"{stats['macro_precision']} | {stats['macro_recall']} |"
            )
        return "\n".join(lines)

    def to_csv(self) -> str:
        lines = ["bug_id,status,precision,recall,fired_buggy,fired_fixed,syntax_ok"]
        for e in self.evals:
            lines.append(
                f"{e.bug_id},{e.status},{e.precision},{e.recall},"
                f"{len(e.fired_on_buggy)},{len(e.fired_on_fixed)},{e.syntax_ok}"
            )
        return "\n".join(lines)
