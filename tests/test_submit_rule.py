from __future__ import annotations

from pathlib import Path

from code_watch.tools.write_file import make_submit_rule_tool


def _ok_validator(content: str) -> tuple[bool, str]:
    return True, ""


def _bad_validator(content: str) -> tuple[bool, str]:
    return False, "missing languages"


def test_hook_accepts_and_reports_state(tmp_path):
    target = tmp_path / "rule.yaml"
    tool, state = make_submit_rule_tool(str(target), validator=_ok_validator)

    result = tool.invoke({"content": "rules:\n- id: x\n"})
    assert "accepted" in result.lower()
    assert state == {"ok": True, "msg": ""}
    assert target.read_text(encoding="utf-8") == "rules:\n- id: x\n"


def test_hook_rejects_and_returns_error_to_agent(tmp_path):
    target = tmp_path / "rule.yaml"
    tool, state = make_submit_rule_tool(str(target), validator=_bad_validator)

    result = tool.invoke({"content": "rules:\n- id: x\n"})
    assert "REJECTED" in result
    assert "missing languages" in result
    assert state == {"ok": False, "msg": "missing languages"}
    # 被拒的提交仍然落盘（它是 agent 最新输出的记录），供 pipeline 兜底修复
    assert target.exists()


def test_hook_reuses_validation_state_across_submissions(tmp_path):
    """多次提交：state 始终反映最后一次钩子判定。"""
    target = tmp_path / "rule.yaml"
    tool, state = make_submit_rule_tool(str(target), validator=_bad_validator)

    tool.invoke({"content": "bad yaml"})
    assert state["ok"] is False
    # 换成好 validator 重新提交
    ok_tool, ok_state = make_submit_rule_tool(str(target), validator=_ok_validator)
    ok_tool.invoke({"content": "good yaml"})
    assert ok_state["ok"] is True


def test_no_validator_backward_compatible(tmp_path):
    target = tmp_path / "rule.yaml"
    tool, state = make_submit_rule_tool(str(target))

    result = tool.invoke({"content": "rules:\n- id: x\n"})
    assert "submitted" in result.lower()
    assert state == {"ok": None, "msg": ""}
    assert target.read_text(encoding="utf-8") == "rules:\n- id: x\n"
