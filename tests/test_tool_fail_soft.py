from __future__ import annotations

from pathlib import Path

import pytest

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


def test_absolute_path_with_dotdot_cannot_escape_jail(tmp_path):
    """绝对路径携带 .. 时必须先归一化再做过牢检查。

    回归：resolve_path 旧实现对绝对路径直接返回（未 resolve），而
    ensure_inside 的 relative_to 是纯词法比较，不展开 `..`，导致
    /root/vul/../../etc/passwd 这类路径能通过检查并读出根外文件。
    """
    (tmp_path / "vul").mkdir()
    ctx = RepoContext(repo_root=str(tmp_path))
    sneaky = str(tmp_path / "vul" / ".." / ".." / "etc" / "passwd")
    with pytest.raises(PermissionError):
        ctx.in_repo_path(sneaky)
    tools = _tools(tmp_path)
    result = tools["read_file"].invoke({"path": sneaky})
    assert result.startswith("ERROR: PermissionError")
    assert "path escapes repo root" in result


def test_absolute_path_inside_root_with_dotdot_is_allowed(tmp_path):
    """.. 归一化后仍落在根内的绝对路径必须放行，且等价于规范路径。"""
    (tmp_path / "A.java").write_text("class A {}\n", encoding="utf-8")
    (tmp_path / "vul").mkdir()
    ctx = RepoContext(repo_root=str(tmp_path))
    inside = str(tmp_path / "vul" / ".." / "A.java")
    assert ctx.in_repo_path(inside) == (tmp_path / "A.java").resolve()
    tools = _tools(tmp_path)
    assert "class A" in tools["read_file"].invoke({"path": inside})
