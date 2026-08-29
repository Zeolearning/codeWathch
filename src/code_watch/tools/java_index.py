from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Optional

from langchain_core.tools import tool

from code_watch.context import RepoContext

try:
    from code_watch.tools.java_symbols import JAVA_LANGUAGE, _parse_file

    JAVA_AVAILABLE = JAVA_LANGUAGE is not None
except Exception:
    JAVA_AVAILABLE = False

# Bump when the on-disk index layout changes; older caches are rebuilt.
_INDEX_SCHEMA_VERSION = 3


def _get_java_mtimes(repo_root: Path) -> dict[str, list[float]]:
    """Return {rel_path: [mtime, size]} for every .java file under repo_root."""
    mtimes: dict[str, list[float]] = {}
    for p in sorted(repo_root.rglob("*.java")):
        try:
            st = p.stat()
            mtimes[str(p.relative_to(repo_root))] = [st.st_mtime, st.st_size]
        except Exception:
            pass
    return mtimes


def _build_index(repo_root: Path, index_file: Path) -> list[dict]:
    index = []
    files_scanned = 0
    errors = 0

    for p in sorted(repo_root.rglob("*.java")):
        try:
            source = p.read_bytes()
            parsed = _parse_file(source)
            _collect_entries(p, repo_root, parsed, index)
            files_scanned += 1
        except Exception:
            errors += 1

    index.sort(key=lambda e: (e.get("kind", ""), e.get("name", "")))

    os.makedirs(index_file.parent, exist_ok=True)
    mtimes = _get_java_mtimes(repo_root)
    index_file.write_text(json.dumps({
        "meta": {
            "schema_version": _INDEX_SCHEMA_VERSION,
            "scanned_files": files_scanned,
            "errors": errors,
            "entries": len(index),
            "timestamp": time.time(),
            "file_mtimes": mtimes,
        },
        "entries": index,
    }, indent=2, ensure_ascii=False))

    return index


def _collect_entries(file_path: Path, repo_root: Path, parsed: dict, index: list) -> None:
    try:
        rel = str(file_path.relative_to(repo_root))
    except ValueError:
        rel = str(file_path)
    pkg = parsed.get("package", "")

    for imp in parsed.get("imports", []):
        index.append({
            "kind": "import",
            "name": imp,
            "file": rel,
            "package": pkg,
        })

    for cls in parsed.get("classes", []):
        _collect_class(cls, index, rel, pkg)


def _collect_class(cls: dict, index: list, file: str, pkg: str) -> None:
    entry = {
        "kind": cls.get("kind", "class"),
        "name": cls.get("name", "?"),
        "file": file,
        "package": pkg,
        "annotations": [a.get("name", "") for a in cls.get("annotations", [])],
        "extends": cls.get("extends", []),
        "implements": cls.get("implements", []),
        "methods": [m.get("name", "?") for m in cls.get("methods", [])],
        "fields": [f.get("name", "?") for f in cls.get("fields", [])],
        "start_line": cls.get("start_line", 0),
        "end_line": cls.get("end_line", 0),
    }
    index.append(entry)

    for m in cls.get("methods", []):
        index.append({
            "kind": "method",
            "name": m.get("name", "?"),
            "file": file,
            "package": pkg,
            "container_class": cls.get("name", "?"),
            "annotations": [a.get("name", "") for a in m.get("annotations", [])],
            "signature": m.get("signature", ""),
            "start_line": m.get("start_line", 0),
            "end_line": m.get("end_line", 0),
        })

    for inner in cls.get("inner_classes", []):
        _collect_class(inner, index, file, pkg)


def _load_or_build(repo_root: Path, index_cache_dir: str) -> list[dict]:
    index_file = Path(index_cache_dir) / "index.json" if index_cache_dir else repo_root / ".code_watch" / "index.json"
    if index_file.exists():
        try:
            data = json.loads(index_file.read_text())
            meta = data.get("meta", {})
            if meta.get("schema_version") == _INDEX_SCHEMA_VERSION:
                cached_mtimes = meta.get("file_mtimes", {})
                current_mtimes = _get_java_mtimes(repo_root)
                if cached_mtimes == current_mtimes:
                    return data.get("entries", [])
        except Exception:
            pass
    return _build_index(repo_root, index_file)


def make_java_index_tool(ctx: RepoContext):
    _loaded_entries: Optional[list[dict]] = None

    @tool
    def java_index(
        kind: Optional[str] = None,
        annotation: Optional[str] = None,
        name_contains: Optional[str] = None,
        file_contains: Optional[str] = None,
    ) -> str:
        """USE THIS FIRST for any Java structural query (finding classes, methods,
        their file:line locations, annotations, parent classes). Results come
        from a pre-built cache and are 100x faster than grep.

        Only fall back to grep when you need to match variable names, string
        literals, or other source-level patterns not in the symbol index.

        Filters (all optional):
          kind=class|method|interface|enum|import|field — narrow to a symbol type
          name_contains=... — search by symbol name (substring, case-insensitive)
          annotation=... — find symbols with a given annotation
          file_contains=... — restrict to files matching a path substring
        """
        nonlocal _loaded_entries
        cache_dir = ctx.config.index_cache_dir or str(ctx.repo_root / ".code_watch")
        if _loaded_entries is None:
            _loaded_entries = _load_or_build(ctx.repo_root, cache_dir)

        entries = _loaded_entries
        stats = {"total": len(entries)}
        if kind:
            entries = [e for e in entries if e.get("kind") == kind]
        if annotation:
            entries = [e for e in entries if any(annotation in a for a in e.get("annotations", []))]
        if name_contains:
            entries = [e for e in entries if name_contains.lower() in e.get("name", "").lower()]
        if file_contains:
            entries = [e for e in entries if file_contains in e.get("file", "")]

        stats["matched"] = len(entries)
        if not entries:
            return json.dumps({"stats": stats, "entries": []}, indent=2, ensure_ascii=False)

        limit = 100
        shown = entries[:limit]
        extra = len(entries) - limit

        result = {"stats": stats, "entries": shown}
        if extra > 0:
            result["note"] = f"Showing {limit} of {len(entries)}. Use more specific filters."
        return json.dumps(result, indent=2, ensure_ascii=False)

    return java_index
