from __future__ import annotations

import re
from pathlib import Path

from code_watch.rules.ast_diff import diff_method_pair
from code_watch.rules.schema import FixDelta, MethodPair
from code_watch.tools.java_symbols import PARSER, _parse_file


# --- Deterministic FixDelta: patch diff -> method pairs, no agent ----------------------

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def expected_from_patch(patch: str) -> dict[str, set[int]]:
    """Parse a `git diff -U0` patch into {file: vulnerable-side line numbers}.

    Only the deletion side counts: those are the vulnerable lines the fix
    touched. Pure-addition hunks record the insertion point (missing-guard
    location).
    """
    expected: dict[str, set[int]] = {}
    current_file: str | None = None
    lines = patch.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("--- "):
            p = line[4:].strip()
            nxt = lines[i + 1] if i + 1 < len(lines) else ""
            if not nxt.startswith("+++ "):
                current_file = None
            elif p.startswith("a/"):
                current_file = p[2:]
            else:
                current_file = None
        elif line.startswith("@@") and current_file:
            m = _HUNK_RE.match(line)
            if not m:
                continue
            start = int(m.group(1))
            count = int(m.group(2) or "1")
            if count > 0:
                expected.setdefault(current_file, set()).update(range(start, start + count))
            elif start > 0:
                expected.setdefault(current_file, set()).update({start, start + 1})
            else:
                expected.setdefault(current_file, set()).add(1)
    return expected


def added_lines_from_patch(patch: str) -> dict[str, set[int]]:
    """Parse a `git diff -U0` patch into {file: fixed-side (added) line numbers}.

    Dual of expected_from_patch: the newly-written lines of the fix tree — the
    only places where a hit counts as a false positive of an over-broad rule.
    """
    added: dict[str, set[int]] = {}
    current_file: str | None = None
    lines = patch.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("--- "):
            p = line[4:].strip()
            nxt = lines[i + 1] if i + 1 < len(lines) else ""
            if not nxt.startswith("+++ "):
                current_file = None
            elif p.startswith("a/"):
                current_file = p[2:]
            else:
                current_file = None
        elif line.startswith("@@") and current_file:
            m = _HUNK_RE.match(line)
            if not m:
                continue
            new_start = int(m.group(3))
            new_count = int(m.group(4) or "1")
            if new_count > 0:
                added.setdefault(current_file, set()).update(
                    range(new_start, new_start + new_count)
                )
    return added


def _changed_java_files(patch: str) -> list[str]:
    """Files from a unified diff that exist on BOTH sides (a/ and b/ headers pair up).

    Added (/dev/null on the a-side) and deleted (/dev/null on the b-side) files have
    no method pair to extract and are skipped.
    """
    files: list[str] = []
    seen: set[str] = set()
    lines = patch.splitlines()
    for i, line in enumerate(lines):
        if not line.startswith("--- "):
            continue
        p = line[4:].strip()
        nxt = lines[i + 1] if i + 1 < len(lines) else ""
        if not nxt.startswith("+++ "):
            continue
        a_path = p[2:] if p.startswith("a/") else None
        b_path = nxt[4:].strip()
        b_path = b_path[2:] if b_path.startswith("b/") else None
        if a_path and b_path and a_path == b_path and a_path not in seen:
            seen.add(a_path)
            files.append(a_path)
    return files


def _flatten_methods(parsed: dict, class_prefix: str = "") -> list[dict]:
    """Flatten a _parse_file result into [{fqcn, signature, start_line, end_line}].

    Inner classes chain with '.' (pkg.Outer.Inner). Package is joined once at the top.
    """
    package = parsed.get("package", "")
    out: list[dict] = []

    def _walk(classes: list[dict], prefix: str) -> None:
        for cls in classes:
            fq = f"{prefix}{cls['name']}"
            for m in cls.get("methods", []):
                out.append({
                    "fqcn": f"{package}.{fq}" if package else fq,
                    "signature": m["signature"],
                    "start_line": m["start_line"],
                    "end_line": m["end_line"],
                })
            _walk(cls.get("inner_classes", []), fq + ".")

    _walk(parsed.get("classes", []), class_prefix)
    return out


def _method_source(file_lines: list[str], start_line: int, end_line: int) -> str:
    return "\n".join(file_lines[start_line - 1:end_line])


def _normalize_sig(signature: str) -> str:
    return " ".join(signature.split())


def build_fix_delta_from_diff(
    vul_dir: Path | str,
    fix_dir: Path | str,
    patch: str,
    *,
    case_id: str = "",
    verbose: bool = False,
) -> FixDelta:
    """Deterministically build a FixDelta from the vulnerable->fixed patch.

    Replaces the former prep agent: the changed files come straight from the diff,
    method pairs are aligned by (fqcn, normalized signature) across the two trees,
    and only methods actually touched by the patch (source differs) survive.
    """
    vul_dir, fix_dir = Path(vul_dir), Path(fix_dir)
    method_deltas = []

    if PARSER is None:
        raise RuntimeError("tree-sitter-java parser unavailable; cannot build FixDelta")

    touched = expected_from_patch(patch)  # {file: vulnerable-side changed lines}
    files = _changed_java_files(patch)

    for path in files:
        vul_file = vul_dir / path
        fix_file = fix_dir / path
        if not (vul_file.is_file() and fix_file.is_file()):
            continue

        vul_lines = vul_file.read_text(encoding="utf-8", errors="replace").splitlines()
        fix_lines = fix_file.read_text(encoding="utf-8", errors="replace").splitlines()
        vul_methods = {
            (m["fqcn"], _normalize_sig(m["signature"])): m
            for m in _flatten_methods(_parse_file("\n".join(vul_lines).encode("utf-8")))
        }
        fix_methods = {
            (m["fqcn"], _normalize_sig(m["signature"])): m
            for m in _flatten_methods(_parse_file("\n".join(fix_lines).encode("utf-8")))
        }

        touched_lines = touched.get(path, set())
        for key, vm in vul_methods.items():
            fm = fix_methods.get(key)
            if fm is None:
                continue
            # Only methods the patch actually touches (line overlap with the diff hunks).
            if touched_lines and not (touched_lines & set(range(vm["start_line"], vm["end_line"] + 1))):
                continue
            buggy_src = _method_source(vul_lines, vm["start_line"], vm["end_line"])
            fixed_src = _method_source(fix_lines, fm["start_line"], fm["end_line"])
            if buggy_src.strip() == fixed_src.strip():
                continue
            pair = MethodPair(
                fqcn=vm["fqcn"],
                method_signature=vm["signature"],
                buggy_source=buggy_src,
                fixed_source=fixed_src,
            )
            method_deltas.append(diff_method_pair(pair))

    if verbose:
        print(f"[delta] FixDelta: {len(files)} changed files -> {len(method_deltas)} method deltas", flush=True)
    return FixDelta(bug_id=case_id, method_deltas=method_deltas)


def save_fix_delta(delta: FixDelta, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(delta.model_dump_json(indent=2), encoding="utf-8")
    return path


def load_fix_delta(path: str | Path) -> FixDelta:
    return FixDelta.model_validate_json(Path(path).read_text(encoding="utf-8"))
