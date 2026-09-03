from __future__ import annotations

import shutil
from collections import Counter
from dataclasses import dataclass, field
from io import StringIO
from pathlib import Path

from ruamel.yaml import YAML

from code_watch.dataset.vul4j import checkout_pair, compute_patch, expected_from_patch
from code_watch.rules.pipeline import out_prefix_for
from code_watch.rules.schema import Rule
from code_watch.rules.semgrep_runner import scan_tree, validate_rule


def load_train_rules(train_case_ids: list[str]) -> tuple[list[Rule], list[str]]:
    """Load canonical best rules produced by the training phase from output/."""
    rules: list[Rule] = []
    missing: list[str] = []
    for case_id in train_case_ids:
        path = Path(f"{out_prefix_for(case_id)}-rule.json")
        if not path.exists():
            missing.append(case_id)
            continue
        rules.append(Rule.model_validate_json(path.read_text(encoding="utf-8")))
    return rules, missing


def merge_rule_yamls(rules: list[Rule]) -> str:
    """Merge multiple `rules:` documents into one semgrep config, ids preserved."""
    yaml = YAML()
    yaml.preserve_quotes = True
    seq = []
    for r in rules:
        doc = yaml.load(r.yaml)
        seq.extend((doc or {}).get("rules") or [])
    out = {"rules": seq}
    stream = StringIO()
    yaml.dump(out, stream)
    return stream.getvalue()


def _ordered_rule_ids(rules: list[Rule]) -> list[str]:
    yaml = YAML()
    ids: list[str] = []
    for r in rules:
        doc = yaml.load(r.yaml)
        for item in (doc or {}).get("rules") or []:
            if isinstance(item, dict) and item.get("id"):
                ids.append(str(item["id"]))
    return ids


def _match_rule_id(check_id: str, known: set[str]) -> str | None:
    """Map a semgrep check_id back to a config rule id, stripping any path prefix.

    When scanning with a single-file config, semgrep prefixes hit ids with the config
    file location (e.g. ``tmp.<rule-id>``); suffix matching recovers the real id.
    """
    if check_id in known:
        return check_id
    for rid in known:
        if check_id.endswith("." + rid):
            return rid
    return None


def _verdict_from_hits(
    expected: dict[str, set[int]],
    buggy_by_rule: dict[str, list[tuple[str, int]]],
    tolerance: int = 3,
    near_tolerance: int = 10,
) -> tuple[list[str], list[str], list[str]]:
    """Classify each rule that fired on the vulnerable tree (timeline-independent tiers).

    All tiers compare a rule's vuln-tree hits against the ground-truth fix-touched
    lines only — no patched-tree silence is required, so bug chronology cannot affect
    the verdict. Returns (same_file, near, localized):
    - same_file:   fired inside a ground-truth bug file (any distance)
    - near:        fired within `near_tolerance` lines of a fix-touched line
    - localized:   fired within `tolerance` lines of a fix-touched line
    """
    same_file: list[str] = []
    near: list[str] = []
    localized: list[str] = []
    for rid, locs in buggy_by_rule.items():
        dist = _min_dist(expected, locs)
        if dist is not None:
            same_file.append(rid)
            if dist <= near_tolerance:
                near.append(rid)
            if dist <= tolerance:
                localized.append(rid)
    return sorted(same_file), sorted(near), sorted(localized)


def _min_dist(expected: dict[str, set[int]], locs: list[tuple[str, int]]) -> int | None:
    """Smallest distance between a hit location and a ground-truth bug line (same file)."""
    best: int | None = None
    for path, line in locs:
        for e in expected.get(path, ()):
            d = abs(line - e)
            if best is None or d < best:
                best = d
    return best


@dataclass
class BugVerdict:
    bug_id: str
    expected_files: list[str] = field(default_factory=list)
    expected_line_count: int = 0
    expected_detail: dict[str, list[int]] = field(default_factory=dict)
    same_file_rule_ids: list[str] = field(default_factory=list)
    near_rule_ids: list[str] = field(default_factory=list)
    localized_rule_ids: list[str] = field(default_factory=list)
    rule_hit_stats: list[dict] = field(default_factory=list)

    @property
    def detected(self) -> bool:
        return bool(self.localized_rule_ids)


@dataclass
class HoldoutReport:
    train_bug_ids: list[str]
    rule_ids: list[str]
    skipped_syntax_error: list[str]
    verdicts: list[BugVerdict]
    tolerance: int = 3
    near_tolerance: int = 10

    @property
    def total(self) -> int:
        return len(self.verdicts)

    @property
    def detected(self) -> int:
        return sum(1 for v in self.verdicts if v.detected)

    def to_dict(self) -> dict:
        return {
            "train_bug_ids": self.train_bug_ids,
            "rule_ids": self.rule_ids,
            "skipped_syntax_error": self.skipped_syntax_error,
            "tolerance": self.tolerance,
            "near_tolerance": self.near_tolerance,
            "verdicts": [v.__dict__ for v in self.verdicts],
            "summary": {
                "total": self.total,
                "detected_same_file": sum(1 for v in self.verdicts if v.same_file_rule_ids),
                "detected_near": sum(1 for v in self.verdicts if v.near_rule_ids),
                "detected_localized": self.detected,
                "per_rule_localized_bugs": dict(
                    Counter(rid for v in self.verdicts for rid in v.localized_rule_ids)
                ),
                "per_rule_near_bugs": dict(
                    Counter(rid for v in self.verdicts for rid in v.near_rule_ids)
                ),
            },
        }

    def to_markdown(self) -> str:
        s = self
        lines = [
            "# Holdout Evaluation",
            "",
            f"- train cases: {', '.join(s.train_bug_ids)}",
            f"- rules: {len(s.rule_ids)} ({len(s.skipped_syntax_error)} skipped: SYNTAX_ERROR)",
            f"- test cases: {s.total}",
            "",
            "Metrics are timeline-independent: each compares a rule's vulnerable-tree hits",
            "against the ground-truth fix-touched lines only (no patched-tree silence).",
            "",
            "## Summary",
            "",
            "| metric | value |",
            "|---|---|",
            f"| same-file (fire inside a fix-touched file) | {sum(1 for v in s.verdicts if v.same_file_rule_ids)}/{s.total} |",
            f"| near (fire within {s.near_tolerance} lines of a fix-touched line) | {sum(1 for v in s.verdicts if v.near_rule_ids)}/{s.total} |",
            f"| localized (fire within {s.tolerance} lines of a fix-touched line) | {sum(1 for v in s.verdicts if v.localized_rule_ids)}/{s.total} |",
            "",
            "## Per test case",
            "",
            "| case | same-file | near≤10 | near≤3 | changed files |",
            "|---|---|---|---|---|",
        ]
        for v in s.verdicts:
            lines.append(
                f"| {v.bug_id} "
                f"| {', '.join(v.same_file_rule_ids) or '-'} "
                f"| {', '.join(v.near_rule_ids) or '-'} "
                f"| {', '.join(v.localized_rule_ids) or '-'} "
                f"| {len(v.expected_files)} ({v.expected_line_count} lines) |"
            )
        lines += [
            "",
            "## Hit detail",
            "",
        ]
        for v in s.verdicts:
            firing = [st for st in v.rule_hit_stats if st["buggy_hits"] > 0]
            silent = len(s.rule_ids) - len(firing)
            lines.append(f"### {v.bug_id}")
            gt = "; ".join(f"`{f}` lines {ls}" for f, ls in v.expected_detail.items())
            lines.append(f"- ground truth: {gt or '(none)'}")
            if not firing:
                lines.append(f"- diagnosis: NO rule fires on the vulnerable tree ({silent} rules silent) — all too narrow")
                lines.append("")
                continue
            if v.localized_rule_ids:
                lines.append(f"- LOCALIZED (within {s.tolerance} lines): {', '.join(v.localized_rule_ids)}")
            elif v.near_rule_ids:
                lines.append(f"- NEAR (within {s.near_tolerance} lines): {', '.join(v.near_rule_ids)}")
            elif v.same_file_rule_ids:
                lines.append(f"- same-file only: {', '.join(v.same_file_rule_ids)}")
            lines += [
                "",
                "| rule | vuln hits | min dist to bug lines | sample vuln hits |",
                "|---|---|---|---|",
            ]
            for st in sorted(firing, key=lambda x: (x["min_dist"] is None, x["min_dist"] or 0, x["rule"])):
                dist = "n/a" if st["min_dist"] is None else str(st["min_dist"])
                lines.append(
                    f"| {st['rule']} | {st['buggy_hits']} | {dist} "
                    f"| {', '.join(st['sample_buggy']) or '-'} |"
                )
            lines.append("")
        lines += [
            "",
            "## Per-rule generalization",
            "",
            "| rule | test cases localized (≤3) | test cases near (≤10) | test cases same-file |",
            "|---|---|---|---|",
        ]
        loc = Counter(rid for v in s.verdicts for rid in v.localized_rule_ids)
        near = Counter(rid for v in s.verdicts for rid in v.near_rule_ids)
        sf = Counter(rid for v in s.verdicts for rid in v.same_file_rule_ids)
        for rid in s.rule_ids:
            lines.append(f"| {rid} | {loc.get(rid, 0)} | {near.get(rid, 0)} | {sf.get(rid, 0)} |")
        return "\n".join(lines) + "\n"


def evaluate_holdout(
    train_case_ids: list[str],
    test_case_ids: list[str],
    *,
    work_root: str | None = None,
    keep_work: bool = False,
    tolerance: int = 3,
    near_tolerance: int = 10,
    verbose: bool = True,
) -> HoldoutReport:
    """Scan held-out test cases with the merged training rule set.

    Ground truth per test case: the vulnerable-side lines the human patch touches
    (from the vul4j checkout's own git history — no separate fixed tree needed).
    """
    rules, missing = load_train_rules(train_case_ids)
    if missing:
        print(
            f"[holdout] WARNING: {len(missing)} train case(s) have no rule on disk, "
            f"continuing without them: {', '.join(missing)}",
            flush=True,
        )
    if not rules:
        raise RuntimeError(
            f"No trained rules loaded for any of {len(train_case_ids)} train case(s). "
            f"Run the training phase first (e.g. code-watch batch --cases ...)."
        )

    ok_rules: list[Rule] = []
    skipped: list[str] = []
    for r in rules:
        ok, _ = validate_rule(r.yaml)
        if ok:
            ok_rules.append(r)
        else:
            skipped.append(r.rule_id)
    if not ok_rules:
        raise RuntimeError("All trained rules failed semgrep --validate; nothing to scan with.")

    merged = merge_rule_yamls(ok_rules)
    ordered_ids = _ordered_rule_ids(ok_rules)
    known_ids = set(ordered_ids)

    verdicts: list[BugVerdict] = []
    for case_id in test_case_ids:
        if verbose:
            print(f"\n[holdout] === {case_id} ===", flush=True)
        base_dir = None
        if work_root:
            base_dir = str(Path(work_root) / f"holdout-{case_id}")
        try:
            # Only the vulnerable tree is needed for scanning.
            parent, vul_dir, _ = checkout_pair(case_id, base_dir=base_dir, pair=False)
            expected = expected_from_patch(compute_patch(vul_dir))

            vul_hits = scan_tree(merged, vul_dir)

            vul_by_rule: dict[str, list[tuple[str, int]]] = {}
            for h in vul_hits:
                rid = _match_rule_id(h["check_id"], known_ids)
                if rid:
                    vul_by_rule.setdefault(rid, []).append((h["path"], h["start_line"]))

            same_file, near, localized = _verdict_from_hits(
                expected, vul_by_rule,
                tolerance=tolerance, near_tolerance=near_tolerance,
            )
            rule_hit_stats = []
            for rid in sorted(vul_by_rule):
                blocs = vul_by_rule[rid]
                rule_hit_stats.append({
                    "rule": rid,
                    "buggy_hits": len(blocs),
                    "sample_buggy": [f"{p}:{l}" for p, l in sorted(blocs)[:3]],
                    "min_dist": _min_dist(expected, blocs),
                })
            verdict = BugVerdict(
                bug_id=case_id,
                expected_files=sorted(expected),
                expected_line_count=sum(len(ls) for ls in expected.values()),
                expected_detail={f: sorted(ls) for f, ls in expected.items()},
                same_file_rule_ids=same_file,
                near_rule_ids=near,
                localized_rule_ids=localized,
                rule_hit_stats=rule_hit_stats,
            )
            verdicts.append(verdict)
            if verbose:
                print(
                    f"[holdout] {case_id}: same_file={same_file or '-'} "
                    f"near(≤{near_tolerance})={near or '-'} "
                    f"localized(≤{tolerance})={localized or '-'}",
                    flush=True,
                )
        finally:
            # Clean the actual checkout parent: with work_root set it equals
            # base_dir, without it checkout_pair created a tempfile.mkdtemp dir
            # that would otherwise leak a full repo clone per test case.
            if not keep_work:
                shutil.rmtree(parent, ignore_errors=True)

    return HoldoutReport(
        train_bug_ids=list(train_case_ids),
        rule_ids=ordered_ids,
        skipped_syntax_error=skipped,
        verdicts=verdicts,
        tolerance=tolerance,
        near_tolerance=near_tolerance,
    )
