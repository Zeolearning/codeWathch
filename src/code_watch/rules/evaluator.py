from __future__ import annotations

from pathlib import Path

from code_watch.rules.schema import Rule, RuleEvaluation
from code_watch.rules.semgrep_runner import hits_as_file_colon_lines, scan_tree, validate_rule

# semgrep 1.172 (OCaml v2 targeting) unconditionally skips directories named
# test/tests while walking a scan root — the builtin default .semgrepignore
# layer has no override in this build (pysemgrep v1 targeting, which honored a
# replacing .semgrepignore, is disabled). Expected bug locations inside test
# files are therefore NOT scanner-visible: filter them out of the oracle here,
# otherwise those cases can never PASS (false FNs at the gate).
_TEST_DIR_COMPONENTS = {"test", "tests"}


def filter_scannable(locations: list[str]) -> tuple[list[str], list[str]]:
    """Split expected 'file:line' locations into (scannable, test-only).

    'Scannable' = path with no test/tests directory component (semgrep will
    actually see those files). Test-only locations are reported separately so
    callers can degrade the gate honestly instead of counting false FNs.
    """
    scannable, test_only = [], []
    for loc in locations:
        path = loc.rpartition(":")[0]
        components = {part.lower() for part in Path(path).parts}
        (test_only if components & _TEST_DIR_COMPONENTS else scannable).append(loc)
    return scannable, test_only


def _parse_locations(locations: list[str]) -> dict[str, set[int]]:
    """Parse 'file:line' or 'file:start-end' into {file: set(lines)}."""
    out: dict[str, set[int]] = {}
    for loc in locations:
        if ":" not in loc:
            continue
        path, _, rest = loc.rpartition(":")
        if "-" in rest:
            s, _, e = rest.partition("-")
            try:
                lines = set(range(int(s), int(e) + 1))
            except ValueError:
                continue
        else:
            try:
                lines = {int(rest)}
            except ValueError:
                continue
        out.setdefault(path, set()).update(lines)
    return out


def _hits_to_line_map(hits: list[dict]) -> dict[str, set[int]]:
    """Convert semgrep scan hits into {file: set(lines)}."""
    out: dict[str, set[int]] = {}
    for h in hits:
        path = h.get("path", "")
        if not path:
            continue
        s = h.get("start_line", 0)
        e = h.get("end_line", s)
        if s <= 0:
            continue
        out.setdefault(path, set()).update(range(s, e + 1))
    return out


def _intersect(a: dict[str, set[int]], b: dict[str, set[int]]) -> set[tuple[str, int]]:
    inter: set[tuple[str, int]] = set()
    for path, lines in a.items():
        if path in b:
            for ln in lines & b[path]:
                inter.add((path, ln))
    return inter


def evaluate_rule(
    rule: Rule,
    buggy_dir: Path,
    fixed_dir: Path,
    expected: list[str],
    *,
    verbose: bool = True,
) -> RuleEvaluation:
    """Run the differential oracle: rule must fire on buggy at expected locations and stay silent on fixed.

    The fixed tree is scanned as a WHOLE repository (the full checkout with this
    bug's fix applied), not just the fixed code fragments. Status priority:
    SYNTAX_ERROR > FP (fires on fixed) > FN (misses bug) > PASS.
    """
    syntax_ok, syntax_msg = validate_rule(rule.yaml)
    if not syntax_ok:
        return RuleEvaluation(
            rule_id=rule.rule_id, bug_id=rule.bug_id, syntax_ok=False,
            fired_on_buggy=[], fired_on_fixed=[], expected=expected,
            status="SYNTAX_ERROR", validation_msg=syntax_msg,
        )

    if verbose:
        print(f"[eval] scanning buggy tree {buggy_dir} ...", flush=True)
    buggy_hits = scan_tree(rule.yaml, buggy_dir)
    if verbose:
        print(f"[eval] scanning fixed tree {fixed_dir} ...", flush=True)
    fixed_hits = scan_tree(rule.yaml, fixed_dir)

    fired_buggy = hits_as_file_colon_lines(buggy_hits)
    fired_fixed = hits_as_file_colon_lines(fixed_hits)

    expected_map = _parse_locations(expected)
    buggy_map = _hits_to_line_map(buggy_hits)
    fixed_map = _hits_to_line_map(fixed_hits)

    hit_expected = _intersect(buggy_map, expected_map)   # bug lines the rule caught
    all_expected = {(p, ln) for p, lns in expected_map.items() for ln in lns}
    reported = {(p, ln) for p, lns in buggy_map.items() for ln in lns}

    recall = len(hit_expected) / len(all_expected) if all_expected else 0.0
    precision = len(hit_expected) / len(reported) if reported else 0.0

    if fixed_map:
        status = "FP"
    elif not hit_expected:
        status = "FN"
    else:
        status = "PASS"

    return RuleEvaluation(
        rule_id=rule.rule_id, bug_id=rule.bug_id, syntax_ok=True,
        fired_on_buggy=fired_buggy, fired_on_fixed=fired_fixed,
        expected=expected, precision=round(precision, 4), recall=round(recall, 4),
        status=status,
    )
