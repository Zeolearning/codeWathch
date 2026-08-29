from __future__ import annotations

import subprocess
from pathlib import Path

from langchain_core.tools import tool

from code_watch.context import RepoContext

_GREP_CAP = 200


def _format_grouped(matches: list[tuple[str, int, str]]) -> str:
    if not matches:
        return "No matches found."

    total_found = len(matches)
    truncated = total_found > _GREP_CAP
    if truncated:
        matches = matches[:_GREP_CAP]

    groups: dict[str, list[tuple[int, str]]] = {}
    for file_path, line_no, content in matches:
        groups.setdefault(file_path, []).append((line_no, content))

    lines = []
    header = f"Found {total_found} matches"
    if truncated:
        header += " (more matches available)"
    lines.append(header)
    lines.append("")

    items = list(groups.items())
    for i, (file_path, file_matches) in enumerate(items):
        lines.append(f"{file_path}:")
        for line_no, content in file_matches:
            lines.append(f"  Line {line_no}: {content}")
        if i < len(items) - 1:
            lines.append("")

    if truncated:
        lines.append("(Results truncated. Use a more specific subpath or pattern.)")

    return "\n".join(lines)


def _rg_search(
    search_root: Path, repo_root: Path, pattern: str, include: str
) -> list[tuple[str, int, str]]:
    # --with-filename forces a `file:line:content` prefix even when
    # search_root is a single file (rg otherwise drops the file prefix).
    cmd = [
        "rg", "-n", "--with-filename", "--no-heading", "--color", "never",
        "-g", include, pattern, str(search_root),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if result.returncode == 1 and not result.stdout:
        return []
    if result.returncode > 1:
        raise RuntimeError(
            f"rg error (rc={result.returncode}): {result.stderr[:500]}"
        )

    matches: list[tuple[str, int, str]] = []
    for rg_line in result.stdout.splitlines():
        parts = rg_line.split(":", 2)
        if len(parts) != 3:
            continue
        abs_path, line_str, content = parts
        try:
            line_no = int(line_str)
        except ValueError:
            continue
        try:
            rel = str(Path(abs_path).relative_to(repo_root))
        except ValueError:
            rel = abs_path
        matches.append((rel, line_no, content))
    return matches


def _py_search(
    search_root: Path, repo_root: Path, pattern: str, include: str
) -> list[tuple[str, int, str]]:
    import re

    file_pattern = include.replace(".", r"\.").replace("*", ".*")
    matches: list[tuple[str, int, str]] = []
    max_file_bytes = 1_048_576

    # rglob on a file path returns nothing; handle the single-file case.
    if search_root.is_file():
        candidates = [search_root]
    else:
        candidates = search_root.rglob("*")

    for p in candidates:
        if not p.is_file():
            continue
        if not re.match(file_pattern, p.name):
            continue
        try:
            if p.stat().st_size > max_file_bytes:
                continue
            raw = p.read_bytes()
        except Exception:
            continue
        if b"\x00" in raw:
            continue
        text = raw.decode("utf-8", errors="replace")
        for i, line in enumerate(text.splitlines(), 1):
            if re.search(pattern, line):
                try:
                    rel = str(p.relative_to(repo_root))
                except ValueError:
                    rel = str(p)
                matches.append((rel, i, line))
    return matches


def make_grep_tool(ctx: RepoContext):
    @tool
    def grep(
        pattern: str,
        include: str = "*.java",
        subpath: str = "",
    ) -> str:
        """Search file contents using a regular expression. Returns matches
        grouped by file with `Line <n>: <content>` so you can cite exact
        `file:line` positions.

        Use instead of `bash` with rg. For structural queries
        (class/method/annotation names) prefer java_index (100x faster).

        Args:
            pattern: regex pattern to search for.
            include: glob pattern limiting which files to search
                     (default "*.java").
            subpath: optional file or subdirectory within the repo to scope
                     the search (empty string = repo root).
        """
        search_root = ctx.repo_root
        if subpath:
            try:
                search_root = ctx.in_repo_path(subpath)
            except PermissionError as e:
                return f"ERROR: {e}"

        try:
            matches = _rg_search(search_root, ctx.repo_root, pattern, include)
        except FileNotFoundError:
            matches = _py_search(search_root, ctx.repo_root, pattern, include)
        except RuntimeError as e:
            return str(e)
        except subprocess.TimeoutExpired:
            return "rg error: timeout after 30s"

        return _format_grouped(matches)

    return grep
