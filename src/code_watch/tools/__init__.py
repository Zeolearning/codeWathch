from __future__ import annotations

from typing import TYPE_CHECKING, Sequence

from langchain_core.tools import BaseTool, StructuredTool

from code_watch.context import RepoContext
from code_watch.tools.bash_tool import make_bash_tool
from code_watch.tools.glob_tool import make_glob_tool
from code_watch.tools.grep_tool import make_grep_tool
from code_watch.tools.java_index import make_java_index_tool
from code_watch.tools.java_symbols import make_java_symbols_tool
from code_watch.tools.list_dir import make_list_dir_tool
from code_watch.tools.read_file import make_read_file_tool

if TYPE_CHECKING:
    pass


def _fail_soft(t: BaseTool) -> BaseTool:
    """Wrap a tool so exceptions become error-text results instead of crashing the agent.

    E.g. read_file on a path outside the repo jail raises PermissionError; unwrapped it
    propagates and kills the whole run. Wrapped, the agent gets
    "ERROR: PermissionError: path escapes repo root: ..." and can recover (retry with
    a relative path, or move on).
    """

    def guarded(**kwargs):
        try:
            return t.invoke(kwargs)
        except Exception as e:
            return f"ERROR: {type(e).__name__}: {e}"

    return StructuredTool.from_function(
        func=guarded,
        name=t.name,
        description=t.description,
        args_schema=t.args_schema,
    )


def build_tools(ctx: RepoContext) -> Sequence[BaseTool]:
    return [
        _fail_soft(make_read_file_tool(ctx)),
        _fail_soft(make_glob_tool(ctx)),
        _fail_soft(make_grep_tool(ctx)),
        _fail_soft(make_list_dir_tool(ctx)),
        _fail_soft(make_java_symbols_tool(ctx)),
        _fail_soft(make_java_index_tool(ctx)),
        _fail_soft(make_bash_tool(ctx)),
    ]
