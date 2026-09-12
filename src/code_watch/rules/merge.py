"""Cluster merge loop — FOLD: N single-case rules -> ONE generalized rule.

Workflow (the "loops" over a materialized cluster workspace)::

    materialize (k cases)
        |
        v
    per-case loops (run_git_case_pipeline, cached on disk)  -- N witness rules
        |
        v
    FOLD construction (N-1 small LLM steps):
        seed  = best-quality single-case rule
        step k: LLM(current accumulated rule + next case patch/rule)
                  -> "merge"  (generalize the invariant, absorb the case)
                  |  "exclude" (different defect shape, case leaves with reason)
        coverage accumulates; each case records the step it was merged at
        |
        v
    FINAL gate (re-run, no LLM): merged rule scanned on every case
        - gate A: every COVERED case fires on its buggy tree at expected lines
        - gate B: silent on the FIXED tree of ALL cases (covered AND excluded)
        |
        fail -> attribute: rewind to the fold step of the first failing case,
        redo that step (and the rest) with the failure fed back — per-step
        history is append-only, so the unchanged prefix stays cache-friendly
        pass / best-of-rounds -> artifacts under output/rules/<cluster>/

Excluded cases that still fire on the buggy tree are recorded as bonus recall
(no gate) — the fold may have been too conservative in excluding them.
"""
from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from langchain_core.messages import AIMessage, HumanMessage
from pydantic import BaseModel, Field

from code_watch.config import CodeWatchConfig
from code_watch.llm import get_llm
from code_watch.rules.delta import (
    added_lines_from_patch,
    expected_from_patch,
)
from code_watch.rules.evaluator import (
    _hits_to_line_map,
    _intersect,
    _parse_locations,
    evaluate_rule,
    filter_scannable,
)
from code_watch.rules.pipeline import out_prefix_for, run_git_case_pipeline
from code_watch.rules.prompts import build_fold_retry_prompt, build_fold_step_prompt
from code_watch.rules.schema import Rule, RuleEvaluation
from code_watch.workspace import DEFAULT_WORKSPACE_ROOT, GitCase, clean_cluster, materialize_case


# --- LLM output schemas ------------------------------------------------------ #

class FoldStep(BaseModel):
    """One fold-step decision: absorb the next case or exclude it."""
    action: str = Field(description='"merge" | "exclude"')
    rule_yaml: str = Field(default="", description="complete updated Semgrep YAML (merge only)")
    commonality: str = Field(default="", description="updated one-sentence pattern statement (merge only)")
    message: str = Field(default="", description="human-readable match message (merge only)")
    reason: str = Field(default="", description="one-sentence exclusion reason (exclude only)")


class MergePlan(BaseModel):
    """Final fold result, flattened for artifacts/reporting."""
    covered_cases: list[str] = Field(default_factory=list)
    excluded_cases: list[dict] = Field(default_factory=list)  # {case_id, reason, folded_at_step}
    commonality: str = ""
    rule_id: str = ""
    message: str = ""
    severity: str = "ERROR"
    mode: str = "pattern"
    rule_yaml: str = ""


# --- in-memory result types --------------------------------------------------- #

@dataclass
class CaseResult:
    """One per-case loop outcome: case + witness rule + its evaluation."""
    case: GitCase
    rule: Rule
    evaluation: RuleEvaluation
    expected: list[str] = field(default_factory=list)

    @property
    def cluster(self) -> str:
        return self.case.case_id.rsplit("-", 1)[0]


@dataclass
class MergedVerdict:
    """Merged-rule outcome on ONE case (differential re-run)."""
    case_id: str
    covered: bool
    syntax_ok: bool = True
    validation_msg: str = ""
    hit_expected: bool = False          # fired on buggy tree at expected lines
    fired_on_buggy: list[str] = field(default_factory=list)
    fired_on_fix: list[str] = field(default_factory=list)
    # hits on the fix tree's PATCH-ADDED lines — the only true false positives:
    # newly-written (guarded) code matched by an over-broad rule. Hits elsewhere
    # on a fix tree are inherited-from-history pattern instances (that snapshot
    # predates other members' fixes sharing the same files) and are tolerated.
    fired_on_fix_added: list[str] = field(default_factory=list)
    expected: list[str] = field(default_factory=list)
    bonus_recall: bool = False          # excluded case still fires on buggy tree


@dataclass
class MergeOutcome:
    cluster: str
    plan: MergePlan
    rule: Rule
    verdicts: list[MergedVerdict]
    passed: bool
    rounds: int
    failures: list[str] = field(default_factory=list)


# --- per-case stage (cached) --------------------------------------------------- #

def load_case_result(
    case: GitCase,
    config: CodeWatchConfig | None = None,
    *,
    skip_existing: bool = True,
    refresh_analysis: bool = False,
    max_attempts: int = 3,
    verbose: bool = True,
) -> CaseResult:
    """Run (or reload from disk) the per-case loop for one materialized case."""
    prefix = out_prefix_for(case.case_id)
    rule_path, eval_path = Path(f"{prefix}-rule.json"), Path(f"{prefix}-eval.json")

    by_file = expected_from_patch(case.patch_src)
    locs = sorted(f"{p}:{ln}" for p, lines in by_file.items() for ln in sorted(lines))
    scannable, _test_only = filter_scannable(locs)
    expected = scannable or locs  # all-test patch: keep all rather than gate on nothing

    rule: Rule | None = None
    evaluation: RuleEvaluation | None = None
    if skip_existing and rule_path.exists() and eval_path.exists():
        try:
            rule = Rule.model_validate_json(rule_path.read_text(encoding="utf-8"))
            evaluation = RuleEvaluation.model_validate_json(eval_path.read_text(encoding="utf-8"))
            if verbose:
                print(f"[merge] cached case {case.case_id}: status={evaluation.status}", flush=True)
        except Exception:
            rule, evaluation = None, None

    if rule is None or evaluation is None:
        _, _, rule, evaluation = run_git_case_pipeline(
            case, config,
            refresh_analysis=refresh_analysis, verbose=verbose, max_attempts=max_attempts,
        )

    return CaseResult(case=case, rule=rule, evaluation=evaluation, expected=expected)


# --- fold construction ---------------------------------------------------------- #

@dataclass
class _FoldState:
    acc_rule: Rule
    commonality: str
    covered: list[str]
    excluded: list[dict]            # {case_id, reason, folded_at_step}
    step_of: dict[str, int]         # case_id -> fold step it was merged at
    steps: int                      # total steps executed


def _fold_order(case_results: list[CaseResult]) -> list[CaseResult]:
    """Seed with the best-quality witness (PASS first, then precision+recall),
    fold the rest in subset seq order (deterministic)."""

    def quality(r: CaseResult):
        ev = r.evaluation
        rank = {"PASS": 3, "FP": 2, "FN": 1, "SYNTAX_ERROR": 0}.get(ev.status, -1)
        return (rank, ev.precision + ev.recall)

    seed = max(case_results, key=quality)
    rest = sorted(
        (r for r in case_results if r.case.case_id != seed.case.case_id),
        key=lambda r: r.case.seq,
    )
    return [seed, *rest]


def _rule_from_fold(cluster: str, step_no: int, step: FoldStep, source_ids: list[str]) -> Rule:
    return Rule(
        rule_id=f"{cluster}-m{step_no}",
        bug_id=cluster,
        language="java",
        yaml=step.rule_yaml,
        message=step.message,
        severity="ERROR",
        mode="pattern",
        metadata={"stage": "cluster-fold", "step": step_no, "source_case_rules": source_ids},
    )


def _run_fold(
    order: list[CaseResult],
    llm,
    *,
    feedback_at_step: dict[int, list[str]] | None = None,
    histories: dict[int, list] | None = None,
    verbose: bool = True,
) -> _FoldState:
    """Run fold steps (optionally restarting from `feedback_at_step` keys).

    Steps before a rewind keep their message history (byte-identical prefix ->
    provider prompt cache hits); steps at/after the rewind append the failure
    notes to their history and re-decide.
    """
    feedback_at_step = feedback_at_step or {}
    histories = histories if histories is not None else {}
    cluster = order[0].cluster
    seed = order[0]

    acc_rule = seed.rule.model_copy(update={"rule_id": f"{cluster}-m0", "bug_id": cluster})
    commonality = seed.rule.message or seed.case.subject
    covered = [seed.case.case_id]
    excluded: list[dict] = []
    step_of = {seed.case.case_id: 0}
    steps = 0

    for result in order[1:]:
        steps += 1
        step_no = steps
        prompt = build_fold_step_prompt(
            cluster, step_no, acc_rule, commonality, covered, excluded, result,
        )
        history = histories.get(step_no)
        if history is None or step_no not in feedback_at_step:
            history = [HumanMessage(content=prompt)]
        if step_no in feedback_at_step:
            history.append(HumanMessage(content=build_fold_retry_prompt(feedback_at_step[step_no])))
        histories[step_no] = history

        step: FoldStep | None = None
        for retry in range(2):  # one inline corrective retry for malformed output
            try:
                step = llm.with_structured_output(FoldStep, method="json_mode").invoke(history)
                break
            except Exception as e:
                if verbose:
                    print(f"[merge] step {step_no}: structured output failed ({e}; retry {retry + 1}/2)", flush=True)
                history.append(HumanMessage(content=(
                    "Your previous response was not a valid JSON object with the required "
                    "schema. Respond again as JSON with exactly: action, rule_yaml, "
                    "commonality, message, reason."
                )))
        if step is None or step.action not in ("merge", "exclude") or (
            step.action == "merge" and not step.rule_yaml.strip()
        ):
            excluded.append({
                "case_id": result.case.case_id,
                "reason": (step.reason if step and step.reason else "unusable fold-step response"),
                "folded_at_step": step_no,
            })
            if verbose:
                print(f"[merge] step {step_no}: EXCLUDE {result.case.case_id} (invalid response)", flush=True)
            continue

        if step.action == "exclude":
            excluded.append({
                "case_id": result.case.case_id,
                "reason": step.reason,
                "folded_at_step": step_no,
            })
            if verbose:
                print(f"[merge] step {step_no}: EXCLUDE {result.case.case_id} — {step.reason[:80]}", flush=True)
            continue

        acc_rule = _rule_from_fold(cluster, step_no, step, [c for c in covered])
        if step.commonality:
            commonality = step.commonality
        covered.append(result.case.case_id)
        step_of[result.case.case_id] = step_no
        if verbose:
            print(f"[merge] step {step_no}: MERGE {result.case.case_id} -> {acc_rule.rule_id} "
                  f"(covered={len(covered)})", flush=True)

    return _FoldState(
        acc_rule=acc_rule, commonality=commonality, covered=covered,
        excluded=excluded, step_of=step_of, steps=steps,
    )


# --- gate + attribution ----------------------------------------------------------- #

def _evaluate_merged(rule: Rule, case_results: list[CaseResult], covered: set[str]) -> list[MergedVerdict]:
    """Scoped differential re-run of the merged rule on every case.

    Gate B is scoped to the patch-ADDED lines of each fix tree: cluster members
    often share files, so a member's fix tree legitimately contains still-
    unguarded pattern instances that another member's fix repaired LATER —
    matching those is true recall, not over-breadth.
    """
    verdicts: list[MergedVerdict] = []
    for r in case_results:
        ev = evaluate_rule(rule, r.case.vul_dir, r.case.fix_dir, r.expected, verbose=False)
        added_map = added_lines_from_patch(r.case.patch_src)
        fix_map = _hits_to_line_map([
            {"path": loc.rpartition(":")[0],
             "start_line": int(loc.rpartition(":")[2]),
             "end_line": int(loc.rpartition(":")[2])}
            for loc in ev.fired_on_fixed
        ])
        fp_added = _intersect(fix_map, added_map)
        fired_on_fix_added = sorted(f"{p}:{ln}" for p, ln in fp_added)
        verdicts.append(
            MergedVerdict(
                case_id=r.case.case_id,
                covered=r.case.case_id in covered,
                syntax_ok=ev.syntax_ok,
                validation_msg=ev.validation_msg,
                hit_expected=ev.status in ("PASS", "FP"),  # fired at expected lines
                fired_on_buggy=ev.fired_on_buggy,
                fired_on_fix=ev.fired_on_fixed,
                fired_on_fix_added=fired_on_fix_added,
                expected=r.expected,
                bonus_recall=(r.case.case_id not in covered) and bool(ev.fired_on_buggy),
            )
        )
    return verdicts


def _fix_snippets(verdict: MergedVerdict, result: CaseResult, *, max_locs: int = 3, ctx: int = 2) -> str:
    """Source snippets from the FIXED tree at the rule's false-positive hits,
    so the fold LLM can see the actual (correct, guarded) code it must exclude."""
    locs = verdict.fired_on_fix_added or verdict.fired_on_fix
    out: list[str] = []
    for loc in locs[:max_locs]:
        path, _, line_s = loc.rpartition(":")
        try:
            ln = int(line_s)
        except ValueError:
            continue
        f = result.case.fix_dir / path
        try:
            lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        lo, hi = max(1, ln - ctx), min(len(lines), ln + ctx)
        body = "\n".join(f"{n:>5} {lines[n - 1]}" for n in range(lo, hi + 1))
        out.append(f"  {loc} (fixed tree, correct code):\n```\n{body}\n```")
    return "\n".join(out)


def _gate(verdicts: list[MergedVerdict]) -> list[str]:
    """Gate A (covered fires on buggy at expected) + Gate B' (silent on the
    patch-ADDED lines of every fix tree; legacy hits on shared files are OK)."""
    failures: list[str] = []
    for v in verdicts:
        if not v.syntax_ok:
            failures.append(f"{v.case_id}: SYNTAX_ERROR")
            continue
        if v.covered and not v.hit_expected:
            failures.append(f"{v.case_id}: covered but rule misses its buggy tree")
        if v.fired_on_fix_added:
            tag = "covered" if v.covered else "excluded"
            failures.append(
                f"{v.case_id}: fires on ADDED (fixed) lines of {tag} case at {v.fired_on_fix_added[:5]}"
            )
    return failures


def _rewind_step(verdicts: list[MergedVerdict], state: _FoldState) -> int:
    """Earliest fold step implicated by a gate failure (feedback lands there).

    Step 0 is the seed witness (no LLM step — its rule already PASSed its own
    gate), so it can never be redone: attribute to the earliest REDOABLE step
    among the failures, else the last fold step (the final broadening).
    """
    failed_steps = [
        state.step_of[v.case_id] for v in verdicts
        if v.covered and (not v.syntax_ok or not v.hit_expected or v.fired_on_fix_added)
        and v.case_id in state.step_of and state.step_of[v.case_id] > 0
    ]
    if failed_steps:
        return min(failed_steps)
    # only excluded cases fired on fix (or seed-only failures) -> the latest
    # generalization most likely broadened the rule past the guard class
    merged_steps = [s for s in state.step_of.values() if s > 0]
    return max(merged_steps) if merged_steps else 1


# --- merge loop --------------------------------------------------------------------- #

def merge_rules(
    case_results: list[CaseResult],
    config: CodeWatchConfig | None = None,
    *,
    max_rounds: int = 3,
    verbose: bool = True,
) -> MergeOutcome:
    """The merge loop: FOLD construction -> final gate -> attributed rewind (<= max_rounds)."""
    if config is None:
        config = CodeWatchConfig.from_env()
        config.apply_env()

    llm = get_llm(config)
    order = _fold_order(case_results)
    cluster = case_results[0].cluster

    histories: dict[int, list] = {}
    best: MergeOutcome | None = None
    pending_feedback: dict[int, list[str]] | None = None

    for rnd in range(1, max_rounds + 1):
        state = _run_fold(order, llm, feedback_at_step=pending_feedback or {}, histories=histories, verbose=verbose)

        rule = state.acc_rule.model_copy(
            update={"rule_id": f"{cluster}-merged", "message": state.acc_rule.message}
        )
        verdicts = _evaluate_merged(rule, case_results, set(state.covered))
        failures = _gate(verdicts)
        plan = MergePlan(
            covered_cases=state.covered,
            excluded_cases=state.excluded,
            commonality=state.commonality,
            rule_id=rule.rule_id,
            message=rule.message,
            rule_yaml=rule.yaml,
        )
        outcome = MergeOutcome(
            cluster=cluster, plan=plan, rule=rule, verdicts=verdicts,
            passed=not failures, rounds=rnd, failures=failures,
        )
        if verbose:
            print(f"[merge] round {rnd}/{max_rounds}: covered={len(state.covered)}/{len(case_results)} "
                  f"excluded={len(state.excluded)} failures={len(failures)}"
                  f"{' PASS' if outcome.passed else ''}", flush=True)
        if outcome.passed:
            return outcome
        if best is None or (len(state.covered) - len(failures)) > (len(best.plan.covered_cases) - len(best.failures)):
            best = outcome
        # attribute: rewind to the earliest implicated REDOABLE step; every step
        # from there on gets the failure notes (its accumulated input changes too)
        step = _rewind_step(verdicts, state)
        by_id = {r.case.case_id: r for r in case_results}
        detailed = list(failures)
        for v in verdicts:
            if v.fired_on_fix_added and v.case_id in by_id:
                snip = _fix_snippets(v, by_id[v.case_id])
                if snip:
                    detailed.append(f"Fixed-tree code you are wrongly matching ({v.case_id}):\n{snip}")
        pending_feedback = {s: detailed for s in range(max(step, 1), state.steps + 1)}
        if verbose:
            print(f"[merge] rewinding to fold step {step} with feedback (incl. FP snippets)", flush=True)

    assert best is not None
    return best


# --- generalization: merged rule vs the cluster's unsampled members ---------- #

def evaluate_generalization(
    rule: Rule,
    cluster_report_path: str | Path,
    subset_path: str | Path,
    diffs_path: str | Path,
    repo_path: str | Path,
    *,
    cluster_id: int | None = None,
    exclude_hashes: set[str] | None = None,
    workspace_root: str | Path = DEFAULT_WORKSPACE_ROOT,
    verbose: bool = True,
) -> dict:
    """Scan the merged rule over the cluster's UNSAMPLED members (their vul/fix
    trees materialized on the fly, cleaned per member) and report:
    - recall side: does the rule fire on each member's buggy tree at expected lines?
    - precision side: any hit on the member's patch-ADDED lines (true FP)?
    This is the honest test of whether the fold found a CLUSTER-wide pattern or
    overfit the sampled five."""
    report = json.loads(Path(cluster_report_path).read_text(encoding="utf-8"))
    subset = json.loads(Path(subset_path).read_text(encoding="utf-8"))
    diffs = json.loads(Path(diffs_path).read_text(encoding="utf-8"))

    cluster = next(
        (c for c in report["clusters"] if cluster_id is not None and c["id"] == cluster_id),
        report["clusters"][0],
    )
    cluster_id = int(cluster["id"])
    by_hash = {c["hash"]: c for c in subset.get("commits", [])}
    files_by_hash = {c["hash"]: c.get("files", []) for c in diffs.get("commits", [])}

    exclude_hashes = exclude_hashes or set()
    members = [h for h in cluster["hashes"] if h not in exclude_hashes]
    if verbose:
        print(f"[gen] cluster {cluster_id}: {len(members)} unsampled members", flush=True)

    ws_dir = Path(workspace_root) / f"{subset.get('repo', 'repo')}-{subset.get('type', 'type')}-c{cluster_id}"
    details: list[dict] = []
    for i, fix_hash in enumerate(members, start=1):
        meta = by_hash.get(fix_hash, {})
        try:
            case = materialize_case(
                Path(repo_path),
                case_id=f"{subset.get('repo', 'repo')}-{subset.get('type', 'type')}-c{cluster_id}-g{i}",
                repo=subset.get("repo", ""), vtype=subset.get("type", ""),
                cluster_id=cluster_id, cluster_label=cluster.get("label", ""),
                seq=int(meta.get("seq", 0)), fix_hash=fix_hash,
                subject=str(meta.get("subject", "")), commit_date=str(meta.get("commit_date", "")),
                files=list(files_by_hash.get(fix_hash, [])),
                dest=ws_dir / f"gen-{i}",
            )
            by_file = expected_from_patch(case.patch_src)
            locs = sorted(f"{p}:{ln}" for p, lines in by_file.items() for ln in sorted(lines))
            scannable, _t = filter_scannable(locs)
            expected = scannable or locs
            ev = evaluate_rule(rule, case.vul_dir, case.fix_dir, expected, verbose=False)
            added_map = added_lines_from_patch(case.patch_src)
            fix_map = _hits_to_line_map([
                {"path": l.rpartition(":")[0],
                 "start_line": int(l.rpartition(":")[2]), "end_line": int(l.rpartition(":")[2])}
                for l in ev.fired_on_fixed
            ])
            fp_added = sorted(f"{p}:{ln}" for p, ln in _intersect(fix_map, added_map))
            details.append({
                "case_id": case.case_id, "seq": case.seq, "fix_hash": fix_hash,
                "subject": case.subject,
                "expected_scannable": len(expected),
                "fired_on_buggy": len(ev.fired_on_buggy),
                "hit_expected_lines": sorted(_intersect(
                    _hits_to_line_map([{ "path": l.rpartition(":")[0],
                                         "start_line": int(l.rpartition(":")[2]),
                                         "end_line": int(l.rpartition(":")[2])}
                                        for l in ev.fired_on_buggy]),
                    _parse_locations(expected))),
                "fix_added_fp": fp_added,
                "status": ev.status,
            })
            if verbose:
                d = details[-1]
                print(f"[gen] {d['case_id']} (seq {d['seq']}): buggy命中={d['fired_on_buggy']} "
                      f"期望行命中={len(d['hit_expected_lines'])}/{d['expected_scannable']} "
                      f"fix新增行FP={len(fp_added)}", flush=True)
        except Exception as e:
            details.append({"case_id": f"gen-{i}", "fix_hash": fix_hash, "error": str(e)[:300]})
            if verbose:
                print(f"[gen] gen-{i}: ERROR {str(e)[:120]}", flush=True)
        finally:
            shutil.rmtree(ws_dir / f"gen-{i}", ignore_errors=True)

    ok = [d for d in details if "error" not in d]
    hit = [d for d in ok if d["hit_expected_lines"]]
    summary = {
        "rule_id": rule.rule_id,
        "cluster": cluster_id,
        "members": len(details),
        "evaluated": len(ok),
        "recalled": len(hit),
        "recalled_members": [d["case_id"] for d in hit],
        "fix_added_fp_members": [d["case_id"] for d in ok if d["fix_added_fp"]],
        "details": details,
    }
    return summary


def run_cluster_loop(
    cluster_dir: str | Path,
    config: CodeWatchConfig | None = None,
    *,
    skip_existing: bool = True,
    refresh_analysis: bool = False,
    max_attempts: int = 3,
    max_rounds: int = 3,
    verbose: bool = True,
    clean: bool = False,
) -> MergeOutcome:
    """Full cluster loops: per-case pipelines (cached) -> fold merge -> gate -> artifacts.

    `clean=True` removes the cluster workspace afterwards (trees are
    regenerable via materialize_cluster; artifacts under output/ survive).
    """
    cluster_dir = Path(cluster_dir)
    case_dirs = sorted(
        (d for d in cluster_dir.glob("case-*") if d.is_dir()),
        key=lambda d: int(d.name.rsplit("-", 1)[-1]),
    )
    if not case_dirs:
        raise RuntimeError(f"no case-* dirs under {cluster_dir}")

    if config is None:
        config = CodeWatchConfig.from_env()
        config.apply_env()

    case_results = [
        load_case_result(
            GitCase.load(d), config,
            skip_existing=skip_existing, refresh_analysis=refresh_analysis,
            max_attempts=max_attempts, verbose=verbose,
        )
        for d in case_dirs
    ]

    outcome = merge_rules(case_results, config, max_rounds=max_rounds, verbose=verbose)

    out_prefix = out_prefix_for(outcome.cluster)
    Path(out_prefix).parent.mkdir(parents=True, exist_ok=True)
    Path(f"{out_prefix}-merged-rule.json").write_text(
        outcome.rule.model_dump_json(indent=2), encoding="utf-8"
    )
    Path(f"{out_prefix}-merged-eval.json").write_text(
        json.dumps(
            {
                "cluster": outcome.cluster,
                "passed": outcome.passed,
                "rounds": outcome.rounds,
                "failures": outcome.failures,
                "plan": outcome.plan.model_dump(),
                "verdicts": [v.__dict__ for v in outcome.verdicts],
            },
            indent=2, ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    if verbose:
        print(f"[merge] artifacts: {out_prefix}-merged-rule.json / -merged-eval.json", flush=True)

    if clean:
        clean_cluster(cluster_dir)
        if verbose:
            print(f"[merge] cleaned workspace {cluster_dir}", flush=True)

    return outcome
