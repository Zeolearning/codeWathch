from __future__ import annotations

from pathlib import Path

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from code_watch.analysis.schema import BugAnalysis
from code_watch.config import CodeWatchConfig
from code_watch.rules.generator import generate_rule
from code_watch.rules.schema import FixDelta

VALID_YAML = (
    "rules:\n"
    "- id: test-rule\n"
    "  languages: [java]\n"
    "  severity: ERROR\n"
    "  message: test\n"
    "  pattern: Runtime.getRuntime().exec(...)\n"
)
BAD_YAML = VALID_YAML.replace("  pattern:", "  badfield:")


def _analysis() -> BugAnalysis:
    return BugAnalysis(
        bug_id="VUL4J-1",
        root_cause="rc",
        affected_files=["src/main/java/com/x/Y.java:42"],
        patch_src="",
    )


class _SelfFixingAgent:
    """Mimics the LLM: first submits a BAD rule (hook REJECTs it), reads the tool
    result, then resubmits a good rule. Verifies the validation hook wiring."""

    def __init__(self, tools):
        self.tools = tools

    def stream(self, inputs, stream_config):
        submit = self.tools[0]
        reject_result = submit.invoke({"content": BAD_YAML})
        assert "REJECTED" in reject_result
        accept_result = submit.invoke({"content": VALID_YAML})
        assert "accepted" in accept_result.lower()
        yield {"agent": {"messages": [AIMessage(content="rule submitted")]}}


def test_generation_validates_via_submit_hook(monkeypatch, tmp_path):
    """提交即校验：坏规则被钩子拒绝并回传，agent 同轮修复后规则才有效。"""
    def fake_validator(content: str) -> tuple[bool, str]:
        return ("badfield:" not in content), "bad field" if "badfield:" in content else ""

    # 让 validator 成为"钩子"：monkeypatch generator 命名空间里的 validate_rule
    monkeypatch.setattr("code_watch.rules.generator.validate_rule", fake_validator)
    monkeypatch.setattr(
        "code_watch.rules.generator.create_agent",
        lambda model, tools, system_prompt: _SelfFixingAgent(tools),
    )

    out = tmp_path / "gen-rule.yaml"
    rule = generate_rule(
        FixDelta(bug_id="VUL4J-1"), _analysis(),
        CodeWatchConfig(repo_path=str(tmp_path), model="gpt-4o-mini", openai_api_key=""),
        out_path=str(out), verbose=False,
    )
    assert rule.metadata["validation_ok"] is True
    assert rule.yaml == VALID_YAML.strip()


class _StreamingAgent:
    """Realistic agent stream: AIMessage with a tool call, then a tools-node ToolMessage."""

    def __init__(self, tools):
        self.tools = tools

    def stream(self, inputs, stream_config):
        yield {
            "agent": {"messages": [
                AIMessage(
                    content="",
                    tool_calls=[{
                        "name": "submit_rule",
                        "args": {"content": VALID_YAML},
                        "id": "call_1",
                        "type": "tool_call",
                    }],
                )
            ]}
        }
        result = self.tools[0].invoke({"content": VALID_YAML})
        yield {"tools": {"messages": [ToolMessage(content=result, tool_call_id="call_1")]}}
        yield {"agent": {"messages": [AIMessage(content="rule submitted")]}}


def test_history_captures_real_messages(monkeypatch, tmp_path):
    """history 就地记录本轮真实消息：prompt + agent tool_call + 工具结果 + 收尾，按序去重。"""
    monkeypatch.setattr("code_watch.rules.generator.validate_rule",
                        lambda content: (True, ""))
    monkeypatch.setattr(
        "code_watch.rules.generator.create_agent",
        lambda model, tools, system_prompt: _StreamingAgent(tools),
    )

    out = tmp_path / "gen-rule.yaml"
    history: list = []
    generate_rule(
        FixDelta(bug_id="VUL4J-1"), _analysis(),
        CodeWatchConfig(repo_path=str(tmp_path), model="gpt-4o-mini", openai_api_key=""),
        out_path=str(out), verbose=False, history=history,
    )

    assert [type(m).__name__ for m in history] == [
        "HumanMessage", "AIMessage", "ToolMessage", "AIMessage",
    ]
    assert "submit_rule" in history[0].content          # prompt
    assert history[1].tool_calls[0]["name"] == "submit_rule"
    assert "Rule accepted" in history[2].content         # 工具结果（校验钩子回传）
    assert history[3].content == "rule submitted"        # 收尾
    # 与输入 history 一起再跑一轮：前缀严格延续（第 2 轮输入 = 第 1 轮完整消息）
    class _PassThrough:
        def __init__(self, tools):
            self.tools = tools
        def stream(self, inputs, stream_config):
            seen = inputs["messages"]
            assert [type(m).__name__ for m in seen[:4]] == [
                "HumanMessage", "AIMessage", "ToolMessage", "AIMessage",
            ]
            assert seen[4].content == "round two feedback"
            self.tools[0].invoke({"content": VALID_YAML})
            yield {"agent": {"messages": [AIMessage(content="done")]}}

    monkeypatch.setattr(
        "code_watch.rules.generator.create_agent",
        lambda model, tools, system_prompt: _PassThrough(tools),
    )
    generate_rule(
        FixDelta(bug_id="VUL4J-1"), _analysis(),
        CodeWatchConfig(repo_path=str(tmp_path), model="gpt-4o-mini", openai_api_key=""),
        out_path=str(out), verbose=False, history=history,
        repair_prompt="round two feedback",
    )
