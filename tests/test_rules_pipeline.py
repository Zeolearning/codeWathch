from __future__ import annotations

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from code_watch.analysis.schema import BugAnalysis
from code_watch.rules.generator import RuleGenError
from code_watch.rules.pipeline import _generate_and_refine
from code_watch.rules.schema import FixDelta, Rule, RuleEvaluation


def _analysis() -> BugAnalysis:
    return BugAnalysis(
        bug_id="VUL4J-1",
        root_cause="rc",
        affected_files=["src/main/java/com/x/Y.java:42"],
        patch_src="",
    )


def _rule(attempt: int, ok: bool = True) -> Rule:
    return Rule(
        rule_id=f"d4j-lang-1-r{attempt}".lower(),
        bug_id="Lang-1",
        yaml=f"rules:\n- id: d4j-lang-1-r{attempt}\n",
        metadata={"validation_ok": ok, "attempt": attempt},
    )


def _eval(status: str, precision: float = 0.0, recall: float = 0.0) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id="x", bug_id="Lang-1", syntax_ok=status != "SYNTAX_ERROR",
        status=status, precision=precision, recall=recall,
    )


def _append_success(history, prompt: str, rule: Rule) -> None:
    """Mirror real generate_rule's in-place history write: prompt + agent's real messages."""
    history.append(HumanMessage(content=prompt))
    history.append(AIMessage(content=f"Here is the rule:\n{rule.yaml}"))
    history.append(ToolMessage(content="Rule accepted", tool_call_id="t1"))


def test_first_round_big_prompt_then_delta_feedback(monkeypatch, tmp_path):
    """第 1 轮发完整生成 prompt（大上下文）；第 2 轮只发增量反馈（不重嵌上下文）。"""
    captured: list[tuple[list, str]] = []

    def fake_generate(delta, analysis, config, *, verbose, repair_prompt, attempt, out_path,
                      history=None, repo_root=None, clean_dirs=None):
        captured.append((list(history or []), repair_prompt))
        rule = _rule(attempt)
        _append_success(history, repair_prompt, rule)
        return rule

    monkeypatch.setattr("code_watch.rules.pipeline.generate_rule", fake_generate)

    def fake_evaluate(rule, b, f, e, verbose=True, clean_dirs=None):
        if rule.metadata["attempt"] == 1:
            return _eval("FP", 0.5, 1.0)
        return _eval("PASS", 1.0, 1.0)

    monkeypatch.setattr("code_watch.rules.pipeline.evaluate_rule", fake_evaluate)
    prefix = str(tmp_path / "d4j-Lang-1")

    rule, evaluation = _generate_and_refine(
        FixDelta(bug_id="Lang-1"), _analysis(), None,
        vul_dir="vul", fix_dir="fix", out_prefix=prefix,
        max_attempts=2, verbose=False,
    )

    assert evaluation.status == "PASS"
    # 第 1 轮：空历史，prompt 是完整生成 prompt（含方法源码等大上下文）
    h1, p1 = captured[0]
    assert h1 == []
    assert "Semgrep schema reference" in p1

    # 第 2 轮：历史 = 第 1 轮的真实消息（prompt + agent 回复 + 工具结果），非合成摘要
    h2, p2 = captured[1]
    assert [type(m).__name__ for m in h2] == ["HumanMessage", "AIMessage", "ToolMessage"]
    assert h2[0].content == p1
    assert "d4j-lang-1-r1" in h2[1].content
    assert "Rule accepted" in h2[2].content
    # 第 2 轮 prompt 是增量反馈：无大上下文重嵌，但含 FP 语义与命中信息
    assert "Semgrep schema reference" not in p2
    assert "Root cause" not in p2
    assert "FALSE POSITIVE" in p2


def test_history_strictly_appends_across_rounds(monkeypatch, tmp_path):
    """三轮均不 PASS：每轮历史 = 上一轮完整输入 + 上一轮提交，严格 append-only
    （这是前缀缓存能命中的根本不变量）。"""
    captured: list[tuple[list, str]] = []

    def fake_generate(delta, analysis, config, *, verbose, repair_prompt, attempt, out_path,
                      history=None, repo_root=None, clean_dirs=None):
        captured.append((list(history or []), repair_prompt))
        rule = _rule(attempt)
        _append_success(history, repair_prompt, rule)
        return rule

    evals = [_eval("FP", 0.5, 1.0), _eval("FN", 0.2, 0.0), _eval("FP", 0.75, 1.0)]
    monkeypatch.setattr("code_watch.rules.pipeline.generate_rule", fake_generate)
    monkeypatch.setattr(
        "code_watch.rules.pipeline.evaluate_rule",
        lambda rule, b, f, e, verbose=True, clean_dirs=None: evals[rule.metadata["attempt"] - 1],
    )
    prefix = str(tmp_path / "d4j-Lang-1")

    _generate_and_refine(
        FixDelta(bug_id="Lang-1"), _analysis(), None,
        vul_dir="vul", fix_dir="fix", out_prefix=prefix,
        max_attempts=3, verbose=False,
    )

    # 第 2 轮 agent 实际输入（历史 + 当轮消息）是第 3 轮历史的严格前缀
    h2, p2 = captured[1]
    h3, p3 = captured[2]
    round2_input = [m.content for m in h2] + [p2]
    round3_hist = [m.content for m in h3]
    assert round3_hist[:4] == round2_input
    assert len(h3) == 6
    # 每轮新消息都是增量（不含大上下文）
    for _, p in captured[1:]:
        assert "Semgrep schema reference" not in p


def test_generation_failure_recorded_and_next_prompt_is_small(monkeypatch, tmp_path):
    """提交失败：本轮真实消息仍入历史（含失败前 agent 的输出）；下一轮 prompt 短。"""
    captured: list[tuple[list, str]] = []

    def fake_generate(delta, analysis, config, *, verbose, repair_prompt, attempt, out_path,
                      history=None, repo_root=None, clean_dirs=None):
        captured.append((list(history or []), repair_prompt))
        if attempt == 1:
            # 真实行为：generate_rule 先就地写回本轮消息，再抛 RuleGenError
            history.append(HumanMessage(content=repair_prompt))
            history.append(AIMessage(content="I refuse to use the tool"))
            raise RuleGenError("Lang-1", "RAW-OUTPUT-A")
        rule = _rule(attempt)
        _append_success(history, repair_prompt, rule)
        return rule

    monkeypatch.setattr("code_watch.rules.pipeline.generate_rule", fake_generate)
    monkeypatch.setattr(
        "code_watch.rules.pipeline.evaluate_rule",
        lambda rule, b, f, e, verbose=True, clean_dirs=None: _eval("PASS", 1.0, 1.0),
    )
    prefix = str(tmp_path / "d4j-Lang-1")

    rule, evaluation = _generate_and_refine(
        FixDelta(bug_id="Lang-1"), _analysis(), None,
        vul_dir="vul", fix_dir="fix", out_prefix=prefix,
        max_attempts=2, verbose=False,
    )
    assert evaluation.status == "PASS"

    h2, p2 = captured[1]
    assert "I refuse to use the tool" in [m.content for m in h2]   # 失败前消息留痕
    assert "submit_rule" in p2                                       # 短 NOTE 指令
    assert "Semgrep schema reference" not in p2                      # 不重嵌大上下文
    assert len(p2) < 500                                             # 且确实"短"
