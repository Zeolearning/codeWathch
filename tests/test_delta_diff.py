from __future__ import annotations

from code_watch.rules.delta import build_fix_delta_from_diff

VUL_SRC = """package com.example;

public class Guard {
    public String process(String input) {
        String name = input;
        return name;
    }

    public int untouched(String input) {
        return input.length();
    }
}
"""

FIX_SRC = """package com.example;

public class Guard {
    public String process(String input) {
        String name = input;
        if (name == null || name.indexOf('\\0') >= 0) {
            throw new IllegalArgumentException("bad name");
        }
        return name;
    }

    public int untouched(String input) {
        return input.length();
    }
}
"""

PATCH = """diff --git a/src/main/java/com/example/Guard.java b/src/main/java/com/example/Guard.java
--- a/src/main/java/com/example/Guard.java
+++ b/src/main/java/com/example/Guard.java
@@ -5,2 +5,6 @@
        String name = input;
+        if (name == null || name.indexOf('\\0') >= 0) {
+            throw new IllegalArgumentException("bad name");
+        }
        return name;
"""

OTHER_VUL = """package com.example;

public class Other {
    public int compute(int x) {
        return x * 2;
    }
}
"""

OTHER_FIX = """package com.example;

public class Other {
    public int compute(int x) {
        return x * 2;
    }
}
"""


def _tree(tmp_path, vul_src: str, fix_src: str) -> tuple:
    rel = "src/main/java/com/example/Guard.java"
    vul = tmp_path / "vul"
    fix = tmp_path / "fix"
    (vul / "src/main/java/com/example").mkdir(parents=True)
    (fix / "src/main/java/com/example").mkdir(parents=True)
    (vul / rel).write_text(vul_src)
    (fix / rel).write_text(fix_src)
    (vul / "src/main/java/com/example/Other.java").write_text(OTHER_VUL)
    (fix / "src/main/java/com/example/Other.java").write_text(OTHER_FIX)
    return vul, fix


def test_fix_delta_from_diff_extracts_touched_method(tmp_path):
    vul, fix = _tree(tmp_path, VUL_SRC, FIX_SRC)
    delta = build_fix_delta_from_diff(vul, fix, PATCH, case_id="VUL4J-X")

    assert delta.bug_id == "VUL4J-X"
    # only the touched method (process) is extracted; untouched/Other excluded
    assert len(delta.method_deltas) == 1
    md = delta.method_deltas[0]
    assert md.method.fqcn == "com.example.Guard"
    assert "process" in md.method.method_signature
    assert "indexOf" not in md.method.buggy_source
    assert "indexOf" in md.method.fixed_source

    # statement-level delta: the fix's additions appear as added_in_fixed
    changes = [d.change for d in md.deltas]
    assert "added_in_fixed" in changes
    for d in md.deltas:
        if d.change == "added_in_fixed":
            assert d.fixed_text and "name == null" in d.fixed_text


def test_fix_delta_empty_when_no_real_change(tmp_path):
    """/patch says touched but sources identical -> no method pairs."""
    vul, fix = _tree(tmp_path, VUL_SRC, VUL_SRC)
    delta = build_fix_delta_from_diff(vul, fix, PATCH, case_id="VUL4J-X")
    assert delta.method_deltas == []


def test_fix_delta_ignores_added_files():
    """/dev/null a-side (file added by the fix) has no method pair."""
    patch = (
        "diff --git a/New.java b/New.java\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/New.java\n"
        "@@ -0,0 +1,3 @@\n"
        "+ class New {}\n"
    )
    # no files on disk needed: the parser drops the file before reading
    from code_watch.rules.delta import _changed_java_files
    assert _changed_java_files(patch) == []
