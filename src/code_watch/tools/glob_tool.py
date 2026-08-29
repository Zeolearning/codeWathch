from __future__ import annotations

from pathlib import Path

from langchain_core.tools import tool

from code_watch.context import RepoContext


def make_glob_tool(ctx: RepoContext):
    @tool
    def glob(pattern: str, subpath: str = "") -> str:
        """Find files matching a glob pattern. Use instead of `bash find` or `ls`.

        Args:
            pattern: glob pattern, e.g. "**/*.java", "src/main/**/Controller*.java"
            subpath: optional subdirectory within the repo to scope the search.
                     Empty string means search from repo root.
        """
        search_root = ctx.repo_root
        if subpath:
            search_root = ctx.in_repo_path(subpath)
        matches = sorted(search_root.rglob(pattern))
        if not matches:
            return "No files matched."
        result = []
        for m in matches:
            try:
                rel = m.relative_to(ctx.repo_root)
                result.append(str(rel))
            except ValueError:
                result.append(str(m))
        limit = 200
        if len(result) > limit:
            result = result[:limit]
            result.append(f"... and {len(matches) - limit} more (use a more specific pattern)")
        return "\n".join(result)

    return glob
