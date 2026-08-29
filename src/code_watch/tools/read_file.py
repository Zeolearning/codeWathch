from __future__ import annotations

from pathlib import Path

from langchain_core.tools import tool

from code_watch.context import RepoContext


def make_read_file_tool(ctx: RepoContext):
    @tool
    def read_file(path: str, offset: int = 1, limit: int = 1000) -> str:
        """Read the content of a file. Each line is prefixed with its 1-indexed
        line number as `N: <content>` so you can cite exact `file:line` positions.
        Use grep to find specific content in large files before reading.
        Call this tool in parallel when you know there are multiple files to read.
        Avoid tiny repeated slices (30 line chunks) — read a larger window instead.

        Args:
            path: relative path from repo root, or absolute path inside the repo.
            offset: 1-indexed line number to start reading from (default 1).
            limit: maximum number of lines to return (default 1000, max 5000).
        """
        resolved = ctx.in_repo_path(path)
        if limit > 5000:
            limit = 5000
        if offset < 1:
            offset = 1
        if not resolved.is_file():
            base_stem = resolved.stem.lower()
            parent = resolved.parent
            candidates = []
            if parent.is_dir():
                for entry in sorted(parent.iterdir()):
                    if not entry.is_file():
                        continue
                    en_stem = entry.stem.lower()
                    if base_stem in en_stem or en_stem in base_stem:
                        if entry.name != resolved.name:
                            try:
                                candidates.append(str(entry.relative_to(ctx.repo_root)))
                            except ValueError:
                                candidates.append(entry.name)
                            if len(candidates) >= 3:
                                break
            msg = f"ERROR: file not found: {path}"
            if candidates:
                msg += "\n\nDid you mean one of these?\n" + "\n".join(candidates)
            return msg

        text = resolved.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines(keepends=True)
        total = len(lines)
        if total == 0:
            return "(End of file - total 0 lines)"
        if offset > total:
            return f"ERROR: offset {offset} > total lines {total}"

        start_idx = offset - 1
        chunk = lines[start_idx: start_idx + limit]

        output_lines = []
        byte_used = 0
        byte_cap = ctx.config.max_read_bytes
        truncated_by_bytes = False

        for i, line in enumerate(chunk):
            line_num = offset + i
            line_str = f"{line_num}: {line}"
            if not line_str.endswith("\n"):
                line_str += "\n"
            line_bytes = len(line_str.encode("utf-8"))
            if byte_used + line_bytes > byte_cap and byte_used > 0:
                truncated_by_bytes = True
                break
            output_lines.append(line_str)
            byte_used += line_bytes

        result = "".join(output_lines)
        actual_end = offset + len(output_lines) - 1

        if actual_end >= total:
            result += f"(End of file - total {total} lines)"
        elif truncated_by_bytes:
            next_offset = actual_end + 1
            kb = byte_cap // 1024
            result += (
                f"(Output capped at {kb} KB. "
                f"Showing lines {offset}-{actual_end}. "
                f"Use offset={next_offset} to continue.)"
            )
        else:
            next_offset = actual_end + 1
            result += (
                f"(Showing lines {offset}-{actual_end} of {total}. "
                f"Use offset={next_offset} to continue.)"
            )

        return result

    return read_file
