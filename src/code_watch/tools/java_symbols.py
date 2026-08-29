from __future__ import annotations

import json
from typing import Any, Optional

from langchain_core.tools import tool
from tree_sitter import Language as _TSLanguage, Parser, Node

from code_watch.context import RepoContext

try:
    import tree_sitter_java

    JAVA_LANGUAGE = _TSLanguage(tree_sitter_java.language())
    PARSER = Parser(JAVA_LANGUAGE)
except Exception:
    JAVA_LANGUAGE = None
    PARSER = None


_CLASS_NODE_KINDS = {
    "class_declaration": "class",
    "interface_declaration": "interface",
    "enum_declaration": "enum",
    "record_declaration": "record",
    "annotation_type_declaration": "@interface",
}


def _text(node: Optional[Node], source: bytes) -> str:
    if node is None:
        return ""
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _children(node: Node) -> list[Node]:
    return [node.child(i) for i in range(node.child_count)]


def _find_child(node: Node, *types: str) -> Optional[Node]:
    for child in _children(node):
        if child.type in types:
            return child
    return None


def _find_children(node: Node, *types: str) -> list[Node]:
    return [child for child in _children(node) if child.type in types]


def _extract_annotations(node: Node, source: bytes) -> list[dict]:
    mods = _find_child(node, "modifiers")
    if not mods:
        return []
    anns = []
    for child in _children(mods):
        if child.type == "marker_annotation":
            name = _find_child(child, "identifier", "scoped_identifier", "scoped_type_identifier")
            anns.append({"name": _text(name, source) if name else _text(child, source), "args": None})
        elif child.type == "annotation":
            name = _find_child(child, "identifier", "scoped_identifier", "scoped_type_identifier")
            args = _find_child(child, "annotation_argument_list")
            anns.append({
                "name": _text(name, source) if name else _text(child, source),
                "args": _text(args, source) if args else None,
            })
    return anns


def _extract_modifiers(node: Node, source: bytes) -> list[str]:
    mods = _find_child(node, "modifiers")
    if not mods:
        return []
    return [
        _text(child, source)
        for child in _children(mods)
        if child.type not in ("marker_annotation", "annotation")
    ]


def _parse_parameters(params_node: Node, source: bytes) -> list[dict]:
    if not params_node:
        return []
    params = []
    for p in _children(params_node):
        if p.type == "formal_parameter":
            p_name = _find_child(p, "identifier")
            p_type = _find_child(p, "type_identifier", "scoped_type_identifier", "array_type", "generic_type")
            params.append({
                "name": _text(p_name, source) if p_name else "",
                "type": _text(p_type, source) if p_type else "",
            })
    return params


def _make_signature(node: Node, source: bytes) -> str:
    body = _find_child(node, "block", "class_body")
    if body:
        return source[node.start_byte:body.start_byte].decode("utf-8", errors="replace").strip()
    return _text(node, source)


def _parse_method(node: Node, source: bytes) -> dict:
    name_node = _find_child(node, "identifier")
    params_node = _find_child(node, "formal_parameters")
    return_type_node = _find_child(
        node, "type_identifier", "scoped_type_identifier", "array_type", "generic_type", "void_type"
    )
    return {
        "name": _text(name_node, source) if name_node else "<anonymous>",
        "signature": _make_signature(node, source),
        "annotations": _extract_annotations(node, source),
        "modifiers": _extract_modifiers(node, source),
        "return_type": _text(return_type_node, source) if return_type_node else "",
        "parameters": _parse_parameters(params_node, source),
        "start_line": node.start_point[0] + 1,
        "end_line": node.end_point[0] + 1,
    }


def _parse_field(node: Node, source: bytes) -> dict:
    declarators = _find_children(node, "variable_declarator")
    type_node = _find_child(
        node, "type_identifier", "scoped_type_identifier", "array_type", "generic_type"
    )
    if declarators:
        name = _text(_find_child(declarators[0], "identifier"), source)
    else:
        name = ""
    return {
        "name": name,
        "type": _text(type_node, source) if type_node else "",
        "annotations": _extract_annotations(node, source),
        "modifiers": _extract_modifiers(node, source),
        "start_line": node.start_point[0] + 1,
        "end_line": node.end_point[0] + 1,
    }


def _parse_type_list(node: Optional[Node], source: bytes) -> list[str]:
    if not node:
        return []
    return [
        _text(c, source)
        for c in _children(node)
        if c.type in ("type_identifier", "scoped_type_identifier")
    ]


def _parse_class(node: Node, source: bytes) -> dict:
    name_node = _find_child(node, "identifier")
    super_node = _find_child(node, "superclass")
    interfaces_node = _find_child(node, "super_interfaces")
    kind_name = _find_child(node, "class", "interface", "enum", "record", "@")
    kind_text = _text(kind_name, source) if kind_name else node.type

    cls_info = {
        "name": _text(name_node, source) if name_node else "<anonymous>",
        "kind": _CLASS_NODE_KINDS.get(kind_text) or _CLASS_NODE_KINDS.get(node.type, node.type),
        "annotations": _extract_annotations(node, source),
        "modifiers": _extract_modifiers(node, source),
        "extends": _parse_type_list(super_node, source),
        "implements": _parse_type_list(interfaces_node, source),
        "fields": [],
        "methods": [],
        "inner_classes": [],
        "start_line": node.start_point[0] + 1,
        "end_line": node.end_point[0] + 1,
    }

    body = _find_child(node, "class_body", "interface_body", "enum_body", "annotation_type_body", "record_body")
    if not body:
        return cls_info

    for child in _children(body):
        if child.type == "method_declaration":
            cls_info["methods"].append(_parse_method(child, source))
        elif child.type == "field_declaration":
            cls_info["fields"].append(_parse_field(child, source))
        elif child.type in _CLASS_NODE_KINDS:
            cls_info["inner_classes"].append(_parse_class(child, source))

    return cls_info


def _find_all_children(node: Node, target_type: str) -> list[Node]:
    result = []
    for i in range(node.child_count):
        child = node.child(i)
        if child.type == target_type:
            result.append(child)
        result.extend(_find_all_children(child, target_type))
    return result


def _parse_file(source: bytes) -> dict:
    tree = PARSER.parse(source)
    root = tree.root_node

    result = {
        "package": "",
        "imports": [],
        "classes": [],
    }

    for child in _children(root):
        if child.type == "package_declaration":
            scoped_node = _find_child(child, "scoped_identifier")
            if scoped_node:
                result["package"] = _text(scoped_node, source)
        elif child.type == "import_declaration":
            scoped_node = _find_child(child, "scoped_identifier")
            if scoped_node:
                result["imports"].append(_text(scoped_node, source))
            else:
                result["imports"].append(_text(child, source))
        elif child.type in _CLASS_NODE_KINDS:
            result["classes"].append(_parse_class(child, source))

    return result


def make_java_symbols_tool(ctx: RepoContext):
    @tool
    def java_symbols(file: str) -> str:
        """Use instead of read_file when you need to understand a Java file's structure. Returns JSON with package, imports, classes, methods with signatures+line numbers, fields, and annotations. More efficient than reading raw source when you want to find method locations, see what annotations are used, or get an overview before diving into specific methods with read_file.
        Args:
            file: relative path from repo root to a .java file.
        """
        resolved = ctx.in_repo_path(file)
        if not resolved.is_file() or resolved.suffix != ".java":
            return f"ERROR: not a .java file: {file}"
        if JAVA_LANGUAGE is None:
            return "ERROR: tree-sitter-java not available. Install tree-sitter-java package."

        source = resolved.read_bytes()
        try:
            parsed = _parse_file(source)
        except Exception as e:
            return f"ERROR: parse failed: {e}"

        def _clean(obj: Any) -> Any:
            if isinstance(obj, dict):
                return {k: _clean(v) for k, v in obj.items() if v is not None and v != []}
            if isinstance(obj, list):
                return [_clean(i) for i in obj if i is not None and i != []]
            return obj

        parsed = _clean(parsed)
        return json.dumps(parsed, indent=2, ensure_ascii=False)

    return java_symbols
