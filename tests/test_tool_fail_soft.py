from __future__ import annotations

from code_watch.config import CodeWatchConfig
from code_watch.context import RepoContext
from code_watch.tools import build_tools


def _tools(tmp_path):
    ctx = RepoContext(repo_root=str(tmp_path), config=CodeWatchConfig(repo_path=str(tmp_path)))
    return {t.name: t for t in build_tools(ctx)}


def test_tool_errors_are_returned_not_raised(tmp_path):
    """工具异常必须以错误文本回传 agent，而不是炸穿整个运行。"""
    tools = _tools(tmp_path)
    result = tools["read_file"].invoke({"path": "/etc/passwd"})
    assert result.startswith("ERROR: PermissionError")
    assert "path escapes repo root" in result


def test_fail_soft_preserves_tool_metadata(tmp_path):
    tools = _tools(tmp_path)
    assert "read_file" in tools
    assert list(tools["read_file"].args_schema.model_fields) == ["path", "offset", "limit"]


def test_read_file_still_works_inside_jail(tmp_path):
    (tmp_path / "buggy" / "src").mkdir(parents=True)
    (tmp_path / "buggy" / "src" / "A.java").write_text("class A {}\n", encoding="utf-8")
    tools = _tools(tmp_path)
    result = tools["read_file"].invoke({"path": "buggy/src/A.java"})
    assert "class A" in result
