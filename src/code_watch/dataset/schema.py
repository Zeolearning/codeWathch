from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CaseInfo:
    """A single Vul4J dataset entry, normalized for the pipeline.

    Field names map 1:1 onto the columns of vul4j/dataset/vul4j_dataset.csv:
    vul_id -> case_id, repo_slug -> repo_slug/project, human_patch -> fix_commit_url.
    """

    case_id: str            # e.g. "VUL4J-10"; SpotBugs-only entries end with "-S"
    repo_slug: str          # e.g. "apache/commons-fileupload"
    project: str            # slug tail, e.g. "commons-fileupload"
    cve_id: str             # e.g. "CVE-2013-2186" ("" if unassigned)
    cwe_id: str             # e.g. "CWE-20"
    cwe_name: str
    owasp_id: str
    fix_commit_url: str     # GitHub commit URL of the human patch
    fix_commit: str         # sha extracted from fix_commit_url
    build_system: str       # Maven / Gradle / Ant
    src_dir: str            # e.g. "src/main/java"
    test_dir: str           # e.g. "src/test/java"
    failing_tests: str      # PoV failing tests ("-" when absent, raw CSV cell)
    warning: str            # SpotBugs golden warning ("-" for PoV entries)
    is_pov: bool            # True for VUL4J-1..79 (has Proof-of-Vulnerability test)

    @property
    def is_spotbugs_only(self) -> bool:
        return not self.is_pov
