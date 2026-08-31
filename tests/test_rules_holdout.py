from __future__ import annotations

import tempfile
from pathlib import Path

from code_watch.dataset.vul4j import expected_from_patch
from code_watch.rules import holdout as holdout_mod
from code_watch.rules.holdout import _min_dist, _verdict_from_hits
from code_watch.rules.schema import Rule


def test_verdict_from_hits_three_tiers():
    """三档判定：same-file/near(≤10)/localized(≤3)，不依赖 fixed 树。"""
    expected = {"src/A.java": {100}}
    buggy_by_rule = {
        # 同文件、贴着 bug 行（d=2）：localized（也含于 near/same-file）
        "r-local": [("src/A.java", 102)],
        # 同文件但距离 8 行：same-file + near，但不够 localized
        "r-near": [("src/A.java", 108)],
        # 同文件但距离 50 行：只 same-file
        "r-file": [("src/A.java", 150)],
        # 跨文件命中：三档都不算
        "r-other": [("src/B.java", 5)],
    }

    same_file, near, localized = _verdict_from_hits(
        expected, buggy_by_rule, tolerance=3, near_tolerance=10
    )

    assert same_file == ["r-file", "r-local", "r-near"]
    assert near == ["r-local", "r-near"]
    assert localized == ["r-local"]


def test_verdict_from_hits_returns_sorted():
    _, _, localized = _verdict_from_hits(
        {"src/A.java": {1}}, {"z": [("src/A.java", 1)], "a": [("src/A.java", 1)]},
        tolerance=3, near_tolerance=10,
    )
    assert localized == ["a", "z"]


def test_min_dist_ignores_other_files_and_empty():
    expected = {"src/A.java": {100, 200}}
    assert _min_dist(expected, [("src/A.java", 103)]) == 3
    assert _min_dist(expected, [("src/B.java", 100)]) is None
    assert _min_dist(expected, []) is None


def test_expected_from_patch_deletion_and_pure_addition():
    text = """diff --git a/src/A.java b/src/A.java
--- a/src/A.java
+++ b/src/A.java
@@ -10,2 +10,2 @@
 context
-deleted
+added
@@ -96,0 +97,20 @@
+        if (s == null) {
+            throw new IllegalArgumentException(str);
"""
    assert expected_from_patch(text) == {"src/A.java": {10, 11, 96, 97}}


def test_expected_from_patch_ignores_dev_null_and_unprefixed():
    """/dev/null 与无 a/ 前缀的头不产生 buggy 侧期望。"""
    text = """diff --git src/A.java src/A.java
--- src/A.java
+++ src/A.java
@@ -40,1 +41,1 @@
-old
+new
--- /dev/null
+++ b/src/New.java
@@ -0,0 +1,2 @@
+a
+b
"""
    assert expected_from_patch(text) == {}


_RULE_YAML = """rules:
  - id: vul4j-1-r1
    languages: [java]
    severity: ERROR
    message: test rule
    pattern: "class $C { ... }"
"""


def _fake_rule() -> Rule:
    return Rule(
        rule_id="vul4j-1-r1", bug_id="VUL4J-1", language="java",
        yaml=_RULE_YAML, message="test rule", severity="ERROR", mode="pattern",
    )


def _patched_holdout(monkeypatch, parents: list[Path]):
    """Stub out checkout/patch/scan; record the mkdtemp'd parents for assertions."""
    def fake_checkout_pair(case_id, base_dir=None, refresh=False, pair=True):
        parent = Path(base_dir) if base_dir else Path(tempfile.mkdtemp(prefix=f"holdout-{case_id}-"))
        (parent / "vul").mkdir(parents=True, exist_ok=True)
        parents.append(parent)
        return parent, parent / "vul", parent / "fix"

    monkeypatch.setattr(holdout_mod, "load_train_rules", lambda ids: ([_fake_rule()], []))
    monkeypatch.setattr(holdout_mod, "validate_rule", lambda yaml: (True, ""))
    monkeypatch.setattr(holdout_mod, "checkout_pair", fake_checkout_pair)
    monkeypatch.setattr(holdout_mod, "compute_patch", lambda vul_dir: "diff --git a/x b/x")
    monkeypatch.setattr(holdout_mod, "expected_from_patch", lambda patch: {})
    monkeypatch.setattr(holdout_mod, "scan_tree", lambda merged, vul_dir: [])


def test_holdout_cleans_mkdtemp_parent_without_work_root(monkeypatch):
    """回归：无 work_root 时 checkout_pair 内部 mkdtemp 的目录必须被清掉（修复前泄漏整仓克隆）。"""
    parents: list[Path] = []
    _patched_holdout(monkeypatch, parents)
    report = holdout_mod.evaluate_holdout(["VUL4J-1"], ["VUL4J-2", "VUL4J-3"], verbose=False)
    assert len(report.verdicts) == 2
    assert len(parents) == 2
    assert all(not p.exists() for p in parents)


def test_holdout_keep_work_retains_parent(monkeypatch):
    parents: list[Path] = []
    _patched_holdout(monkeypatch, parents)
    holdout_mod.evaluate_holdout(["VUL4J-1"], ["VUL4J-2"], keep_work=True, verbose=False)
    assert all(p.exists() for p in parents)
