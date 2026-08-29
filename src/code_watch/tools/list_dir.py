from __future__ import annotations

from langchain_core.tools import tool

from code_watch.context import RepoContext


def make_list_dir_tool(ctx: RepoContext):
    @tool
    def list_dir(path: str = "") -> str:
        """List the contents of a directory.
        Args:
            path: relative path from repo root (empty string = repo root itself).
        """
        resolved = ctx.repo_root if not path else ctx.in_repo_path(path)
        if not resolved.is_dir():
            return f"ERROR: not a directory: {path}"

        entries = []
        for entry in sorted(resolved.iterdir(), key=lambda x: (not x.is_dir(), x.name)):
            suffix = "/" if entry.is_dir() else ""
            try:
                rel = entry.relative_to(ctx.repo_root)
                entries.append(f"{rel}{suffix}")
            except ValueError:
                entries.append(f"{entry.name}{suffix}")
        limit = 500
        if len(entries) > limit:
            entries = entries[:limit]
            entries.append(f"... and {len(list(resolved.iterdir())) - limit} more entries")
        return "\n".join(entries) if entries else "(empty directory)"

    return list_dir
