from __future__ import annotations

import json
from pathlib import Path

from code_watch.rules.evaluator import evaluate_rule
from code_watch.rules.schema import Rule, RuleEvaluation


def _rule() -> Rule:
    return Rule(
        rule_id="d4j-lang-1-r1", bug_id="Lang-1",
        yaml="rules:\n- id: d4j-lang-1-r1\n  languages: [java]\n",
    )


def _hit(path: str, line: int) -> dict:
    return {"check_id": "d4j-lang-1-r1", "path": path, "start_line": line,
            "end_line": line, "message": "m"}


def _patch_scans(monkeypatch, buggy=None, fixed=None):
    calls = []
    monkeypatch.setattr(
        "code_watch.rules.evaluator.validate_rule",
        lambda yaml: (True, ""),
    )

    def _scan(rule_yaml, target):
        calls.append(target.name)
        return {"buggy": buggy or [], "fixed": fixed or []}[target.name]

    monkeypatch.setattr("code_watch.rules.evaluator.scan_tree", _scan)
    return calls


def test_fixed_tree_hit_is_fp(monkeypatch, tmp_path):
    """规则在本 bug 的 fixed 仓库上命中 → FP（即使 buggy 命中真值）。"""
    _patch_scans(
        monkeypatch,
        buggy=[_hit("src/A.java", 10)],
        fixed=[_hit("src/A.java", 10)],
    )
    ev = evaluate_rule(_rule(), Path("buggy"), Path("fixed"), ["src/A.java:10"], verbose=False)
    assert ev.status == "FP"


def test_whole_fixed_repo_is_scanned(monkeypatch, tmp_path):
    """FP 检查扫的是整棵 fixed 树（buggy + fixed 各一次 scan_tree）。"""
    calls = _patch_scans(monkeypatch, buggy=[_hit("src/A.java", 10)], fixed=[])
    ev = evaluate_rule(_rule(), Path("buggy"), Path("fixed"), ["src/A.java:10"], verbose=False)
    assert ev.status == "PASS"
    assert set(calls) == {"buggy", "fixed"}


def test_fixed_silent_but_misses_expected_is_fn(monkeypatch, tmp_path):
    """fixed 静默但没命中真值 → FN。"""
    _patch_scans(monkeypatch, buggy=[_hit("src/Other.java", 3)], fixed=[])
    ev = evaluate_rule(_rule(), Path("buggy"), Path("fixed"), ["src/A.java:10"], verbose=False)
    assert ev.status == "FN"


def test_old_eval_json_with_extra_field_still_loads():
    """旧 eval.json（多出来的字段，如 fired_on_clean）可正常反序列化（pydantic 默认忽略）。"""
    old = {
        "rule_id": "x", "bug_id": "Lang-1", "syntax_ok": True,
        "fired_on_buggy": [], "fired_on_fixed": [], "fired_on_clean": ["a:b:1"],
        "expected": [], "precision": 0.0, "recall": 0.0, "status": "PASS",
    }
    ev = RuleEvaluation.model_validate_json(json.dumps(old))
    assert ev.status == "PASS"
