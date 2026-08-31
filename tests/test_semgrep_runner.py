from __future__ import annotations

import pytest

from code_watch.rules.semgrep_runner import scan_tree

_ANY_CLASS_RULE = """rules:
  - id: test-any-class
    languages: [java]
    severity: INFO
    message: found a class declaration
    pattern: "class $C { ... }"
"""


@pytest.fixture
def relative_java_tree(tmp_path, monkeypatch):
    """Reproduce the default pipeline layout: a RELATIVE checkout target.

    run/batch check out into the relative `output/checkouts/<case>/vul` and call
    scan_tree with that relative path while the subprocess cwd is set to the
    target itself — the child then resolves the argument against its new cwd.
    """
    target = tmp_path / "output" / "checkouts" / "VUL4J-1" / "vul"
    (target / "src").mkdir(parents=True)
    (target / "src" / "A.java").write_text(
        "package com.example;\n\npublic class A {\n    int x = 1;\n}\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    return target.relative_to(tmp_path)  # e.g. output/checkouts/VUL4J-1/vul


def test_scan_tree_accepts_relative_target(relative_java_tree):
    """回归：修复前相对 target 会在子进程里解析成不存在的双重路径而 rc=2。"""
    hits = scan_tree(_ANY_CLASS_RULE, relative_java_tree)
    assert any(h["path"].endswith("A.java") for h in hits)


def test_scan_tree_relative_hits_use_repo_relative_paths(relative_java_tree):
    hits = scan_tree(_ANY_CLASS_RULE, relative_java_tree)
    assert hits, "fixture class must be found"
    for h in hits:
        assert not h["path"].startswith("/")
