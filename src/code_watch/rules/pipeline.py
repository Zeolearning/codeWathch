from __future__ import annotations

from pathlib import Path

from langchain_core.messages import BaseMessage

from code_watch.analysis.analyzer import analyze_case
from code_watch.analysis.batch import analysis_path
from code_watch.analysis.schema import BugAnalysis
from code_watch.config import CodeWatchConfig
from code_watch.dataset.vul4j import checkout_pair, compute_patch, expected_from_patch
from code_watch.rules.delta import build_fix_delta_from_diff, save_fix_delta
from code_watch.rules.evaluator import evaluate_rule
from code_watch.rules.generator import generate_rule, save_rule
from code_watch.rules.prompts import (
    build_generation_prompt,
    build_round_feedback_prompt,
)
from code_watch.rules.schema import FixDelta, Rule, RuleEvaluation

_STATUS_RANK = {"PASS": 3, "FP": 2, "FN": 1, "SYNTAX_ERROR": 0}


def out_prefix_for(case_id: str) -> str:
    return f"output/rules/vul4j-{case_id}/vul4j-{case_id}"


def load_or_analyze(
    case_id: str,
    *,
    base_dir: str | None = None,
    refresh_analysis: bool = False,
    refresh_checkout: bool = False,
    verbose: bool = True,
) -> tuple[BugAnalysis, Path, Path, Path]:
    """Load a persisted analysis (if any) or run the analysis agent; either way return
    the dual checkout (parent, vul_dir, fix_dir) for downstream reuse.

    The checkout defaults to the shared cache ``output/checkouts/<case_id>`` so the
    analysis phase and the rule phase (possibly separate batch runs) reuse one tree.
    """
    if base_dir is None:
        base_dir = f"output/checkouts/{case_id}"

    parent, vul_dir, fix_dir = checkout_pair(
        case_id, base_dir=base_dir, refresh=refresh_checkout
    )

    path = analysis_path(case_id)
    analysis: BugAnalysis | None = None
    if path.exists() and not refresh_analysis:
        try:
            analysis = BugAnalysis.model_validate_json(path.read_text(encoding="utf-8"))
        except Exception:
            analysis = None

    if analysis is None:
        if verbose and path.exists():
            print(f"[pipe] re-analyzing {case_id} (existing JSON unparseable or --refresh-analysis)", flush=True)
        analysis, parent, vul_dir, fix_dir = analyze_case(
            case_id, base_dir=base_dir, refresh=refresh_checkout, verbose=verbose
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(analysis.model_dump_json(indent=2), encoding="utf-8")
    elif not analysis.patch_src:
        # Older/partial JSON: deterministically refresh the patch from the checkout.
        analysis.patch_src = compute_patch(vul_dir)
        path.write_text(analysis.model_dump_json(indent=2), encoding="utf-8")

    return analysis, parent, vul_dir, fix_dir


def _eval_score(ev: RuleEvaluation) -> tuple[int, float]:
    return (_STATUS_RANK.get(ev.status, -1), ev.precision + ev.recall)


def _expected_locations(analysis: BugAnalysis) -> list[str]:
    """Ground-truth 'file:line' locations the rule must fire at on the vulnerable tree.

    Primary source: the developer patch (`patch_src`, deterministic) — the lines the fix
    changed on the vulnerable side. Falls back to the analysis's affected_files when no
    patch is available.
    """
    if analysis.patch_src:
        by_file = expected_from_patch(analysis.patch_src)
        locs = sorted(f"{path}:{ln}" for path, lines in by_file.items() for ln in sorted(lines))
        if locs:
            return locs
    return list(analysis.affected_files)


def _generate_and_refine(
    delta: FixDelta,
    analysis: BugAnalysis,
    config: CodeWatchConfig,
    vul_dir: str,
    fix_dir: str,
    out_prefix: str,
    *,
    max_attempts: int = 3,
    verbose: bool = True,
) -> tuple[Rule, RuleEvaluation]:
    """带修复反馈的"生成→评估"循环（缓存友好的上下文管理）。

    每一轮：LLM 生成规则，`submit_rule` 工具的校验钩子在同轮内完成语法自愈；
    存活下来的规则对两棵树各扫一次；非 PASS 时，评估反馈（FP/FN 命中位置）
    作为下一轮的增量消息。PASS 即提前停止；返回最优轮。

    上下文/缓存策略：
    - 大上下文（root cause、方法源码、schema 速查表）只在第 1 轮生成 prompt
      里出现一次，作为对话历史的不可变前缀；
    - 后续轮只追加小增量消息（评估反馈/提交失败 NOTE），历史逐轮 append、
      绝不改写——每轮请求与上一轮共享字节级相同的前缀，LLM 提供方的前缀
      缓存（prompt caching）可命中全部历史 tokens；
    - 历史里存的是 generate_rule 实际发给 LLM 的真实消息（本轮 prompt +
      agent 的 AIMessage + submit_rule 工具的 ToolMessage），不是合成摘要；
      下一轮 agent 因此能看到之前提交过哪些规则、校验钩子回了什么、收到
      过哪些反馈。

    产物（固定文件名，每轮覆盖；循环结束后落盘的是最优轮）：
    {out_prefix}-gen-rule.yaml（agent 提交的原始 YAML）、
    {out_prefix}-rule.json / -eval.json（结构化 Rule / RuleEvaluation）。
    """
    history: list[BaseMessage] = []
    gen_path = f"{out_prefix}-gen-rule.yaml"
    prompt = build_generation_prompt(delta, analysis, gen_path)
    best: tuple[Rule, RuleEvaluation] | None = None
    expected = _expected_locations(analysis)
    if verbose:
        source = "developer patch" if expected != list(analysis.affected_files) else "affected_files"
        print(f"[pipe] expected locations ({source}): {len(expected)}", flush=True)

    for attempt in range(1, max_attempts + 1):
        try:
            rule = generate_rule(
                delta, analysis, config, verbose=verbose,
                repair_prompt=prompt, attempt=attempt, out_path=gen_path,
                history=history,
                # 只读工具以双树共同父目录为根：agent 可读 vul/... 与 fix/...
                repo_root=str(Path(vul_dir).parent),
            )
        except RuntimeError as e:
            if verbose:
                print(f"[pipe] attempt {attempt}: no rule file written: {e}", flush=True)
            raw = getattr(e, "raw", None)
            detail = f" Your last output was:\n```\n{raw[:500]}\n```" if raw else ""
            prompt = (
                f"You did not submit a rule file in attempt {attempt}.{detail}\n"
                f"Submit the rule now using the `submit_rule` tool."
            )
            continue

        save_rule(rule, f"{out_prefix}-rule.json")
        evaluation = evaluate_rule(rule, Path(vul_dir), Path(fix_dir), expected, verbose=verbose)
        Path(f"{out_prefix}-eval.json").write_text(
            evaluation.model_dump_json(indent=2), encoding="utf-8"
        )
        if verbose:
            print(f"[pipe] attempt {attempt}: status={evaluation.status} "
                  f"precision={evaluation.precision} recall={evaluation.recall}", flush=True)

        if best is None or _eval_score(evaluation) > _eval_score(best[1]):
            best = (rule, evaluation)
        if evaluation.status == "PASS":
            break
        prompt = build_round_feedback_prompt(rule, evaluation, analysis)

    if best is None:
        raise RuntimeError(
            f"All {max_attempts} attempts failed to produce a parseable rule for {analysis.bug_id}."
        )
    rule, evaluation = best
    if evaluation.status != "PASS" and verbose:
        print(f"[pipe] differential criterion (fire on vul, silent on fix) NOT met "
              f"after {max_attempts} attempts; keeping best (status={evaluation.status}, "
              f"precision={evaluation.precision} recall={evaluation.recall})", flush=True)
    save_rule(rule, f"{out_prefix}-rule.json")
    Path(f"{out_prefix}-eval.json").write_text(evaluation.model_dump_json(indent=2), encoding="utf-8")
    return rule, evaluation


def run_case_pipeline(
    case_id: str,
    config: CodeWatchConfig | None = None,
    *,
    base_dir: str | None = None,
    refresh_analysis: bool = False,
    refresh_checkout: bool = False,
    verbose: bool = True,
    max_attempts: int = 3,
) -> tuple[BugAnalysis, FixDelta, Rule, RuleEvaluation]:
    """Full case pipeline: analyze (cached) -> deterministic FixDelta -> generate/evaluate."""
    if config is None:
        config = CodeWatchConfig.from_env()
        config.apply_env()

    out_prefix = out_prefix_for(case_id)
    Path(out_prefix).parent.mkdir(parents=True, exist_ok=True)

    analysis, parent, vul_dir, fix_dir = load_or_analyze(
        case_id, base_dir=base_dir,
        refresh_analysis=refresh_analysis, refresh_checkout=refresh_checkout,
        verbose=verbose,
    )
    if verbose:
        print(f"[pipe] analysis: {len(analysis.patch_src.splitlines())} patch lines, "
              f"root_cause={analysis.root_cause[:80]}...", flush=True)

    delta = build_fix_delta_from_diff(
        vul_dir, fix_dir, analysis.patch_src, case_id=case_id, verbose=verbose
    )
    save_fix_delta(delta, f"{out_prefix}-fixdelta.json")

    rule, evaluation = _generate_and_refine(
        delta, analysis, config, str(vul_dir), str(fix_dir), out_prefix,
        max_attempts=max_attempts, verbose=verbose,
    )
    if verbose:
        print(f"[pipe] Rule saved: {rule.rule_id} (best of {max_attempts})", flush=True)
        print(f"[pipe] Eval: status={evaluation.status} precision={evaluation.precision} "
              f"recall={evaluation.recall}", flush=True)

    return analysis, delta, rule, evaluation
