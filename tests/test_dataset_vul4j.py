from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from code_watch.dataset.vul4j import (
    DATASET_CSV,
    checkout_pair,
    compute_patch,
    expected_from_patch,
    load_case,
    load_cases,
    resolve_case_ids,
)


class TestLoadCases:
    def test_dataset_csv_present(self):
        assert DATASET_CSV.is_file(), "vul4j/ clone missing (see .gitignore)"

    def test_case_count(self):
        cases = load_cases()
        assert len(cases) == 129
        pov = [c for c in cases.values() if c.is_pov]
        sb = [c for c in cases.values() if c.is_spotbugs_only]
        assert len(pov) == 79
        assert len(sb) == 50

    def test_known_case_fields(self):
        c = load_case("VUL4J-10")
        assert c.repo_slug == "apache/commons-fileupload"
        assert c.project == "commons-fileupload"
        assert c.cve_id == "CVE-2013-2186"
        assert c.cwe_id == "CWE-20"
        assert c.is_pov is True
        assert c.fix_commit_url.startswith("https://github.com/")
        assert c.fix_commit and c.fix_commit != c.fix_commit_url

    def test_spotbugs_entry_flag(self):
        c = load_case("VUL4J-80-S")
        assert c.is_pov is False
        assert c.is_spotbugs_only is True

    def test_unknown_id_raises(self):
        with pytest.raises(KeyError):
            load_case("VUL4J-999")


class TestExpectedFromPatch:
    def test_deletion_and_addition(self):
        patch = (
            "diff --git a/Foo.java b/Foo.java\n"
            "--- a/Foo.java\n"
            "+++ b/Foo.java\n"
            "@@ -10,2 +10,3 @@\n"
            " ctx;\n"
            "- check();\n"
            "+ check(input);\n"
            "+ log();\n"
        )
        assert expected_from_patch(patch) == {"Foo.java": {10, 11}}

    def test_pure_addition_records_insertion_point(self):
        patch = (
            "--- a/Bar.java\n"
            "+++ b/Bar.java\n"
            "@@ -42,0 +43,2 @@\n"
            "+ if (x == null) return;\n"
        )
        assert expected_from_patch(patch) == {"Bar.java": {42, 43}}

    def test_added_file_has_no_buggy_side(self):
        patch = (
            "diff --git a/New.java b/New.java\n"
            "new file mode 100644\n"
            "--- /dev/null\n"
            "+++ b/New.java\n"
            "@@ -0,0 +1,5 @@\n"
            "+ class New {}\n"
        )
        assert expected_from_patch(patch) == {}

    def test_removal_line_starting_with_dashes_is_not_header(self):
        patch = (
            "--- a/Baz.java\n"
            "+++ b/Baz.java\n"
            "@@ -7,2 +7,1 @@\n"
            " ctx\n"
            "--- not a header\n"
            "- old();\n"
        )
        assert expected_from_patch(patch) == {"Baz.java": {7, 8}}


class TestResolveCaseIds:
    def test_shortcuts(self):
        cases = load_cases()
        assert resolve_case_ids("all", cases) == list(cases)
        assert len(resolve_case_ids("pov", cases)) == 79
        assert len(resolve_case_ids("sb", cases)) == 50
        assert resolve_case_ids("sb", cases)[0] == "VUL4J-80-S"

    def test_ids_ranges_and_dedup(self):
        cases = load_cases()
        ids = resolve_case_ids("VUL4J-10,10,4-5,VUL4J-4", cases)
        assert ids == ["VUL4J-10", "VUL4J-4", "VUL4J-5"]

    def test_explicit_s_entry(self):
        cases = load_cases()
        assert resolve_case_ids("80-S", cases) == ["VUL4J-80-S"]

    def test_unknown_token_raises(self):
        cases = load_cases()
        with pytest.raises(ValueError, match="Unknown case"):
            resolve_case_ids("VUL4J-999,zzz", cases)

    def test_empty_raises(self):
        cases = load_cases()
        with pytest.raises(ValueError, match="No cases"):
            resolve_case_ids(",", cases)


class TestStripCopies:
    def test_cached_tree_gets_stripped_without_cli(self, tmp_path):
        """缓存命中路径同样剔除 VUL4J/ 副本（幂等清洁旧缓存），不触发 CLI。"""
        parent = tmp_path / "VUL4J-99"
        vul = parent / "vul"
        (vul / "VUL4J" / "vulnerable" / "src").mkdir(parents=True)
        (vul / ".git").mkdir()  # fake cache marker: skips the real checkout
        (vul / "VUL4J" / "vulnerable" / "src" / "A.java").write_text(
            "class A {}\n", encoding="utf-8"
        )

        _, vul_dir, _ = checkout_pair("VUL4J-99", base_dir=str(parent), pair=False)

        assert not (vul_dir / "VUL4J").exists()
        assert (vul_dir / ".git").is_dir()  # cache marker untouched


@pytest.mark.slow
class TestCheckoutPair:
    """Integration: real `vul4j checkout` (network + upstream clone, ~seconds once warm)."""

    def test_pair_and_patch(self, tmp_path):
        parent, vul_dir, fix_dir = checkout_pair("VUL4J-10", base_dir=str(tmp_path))
        assert (vul_dir / ".git").is_dir()
        assert (fix_dir / ".git").is_dir()

        def head(d: Path) -> str:
            return subprocess.run(
                ["git", "-C", str(d), "rev-parse", "--abbrev-ref", "HEAD"],
                capture_output=True, text=True,
            ).stdout.strip()

        assert head(vul_dir) == "HEAD"          # detached = vulnerable
        assert head(fix_dir) == "master"        # human_patch

        # the raw VUL4J/vulnerable + VUL4J/human_patch copy dirs the CLI
        # leaves behind must be stripped from both trees (false-FP source)
        assert not (vul_dir / "VUL4J").exists()
        assert not (fix_dir / "VUL4J").exists()

        patch = compute_patch(vul_dir)
        assert "DiskFileItem.java" in patch
        expected = expected_from_patch(patch)
        assert expected and all(f.endswith(".java") for f in expected)

        # caching: second call is a no-op (dirs untouched)
        before = sorted(p.name for p in vul_dir.iterdir())
        checkout_pair("VUL4J-10", base_dir=str(tmp_path))
        assert sorted(p.name for p in vul_dir.iterdir()) == before

    def test_checkout_inside_vul4j_repo_rejected(self, tmp_path):
        with pytest.raises(ValueError):
            checkout_pair("VUL4J-10", base_dir=str(DATASET_CSV.parent / "bad_target"))
        shutil.rmtree(DATASET_CSV.parent / "bad_target", ignore_errors=True)
