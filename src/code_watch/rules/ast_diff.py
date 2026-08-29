from __future__ import annotations

import difflib
from typing import Optional

from tree_sitter import Node

from code_watch.rules.schema import ASTNodeDelta, MethodASTDelta, MethodPair
from code_watch.tools.java_symbols import PARSER, _find_all_children, _find_child, _text

# tree-sitter-java node types that are method-like declarations we can diff.
_METHOD_NODE_TYPES = ("method_declaration", "constructor_declaration")


def _wrap_as_class(method_source: str) -> str:
    """Wrap a full method snippet in a dummy class so tree-sitter-java can parse it."""
    return f"class _DiffDummy {{\n{method_source}\n}}\n"


def _wrap_as_body(method_source: str) -> str:
    """Wrap a body/fragment snippet as the body of a dummy method.

    Used when the snippet isn't a full method_declaration (the prep agent often returns
    just the changed block, e.g. an if-statement). A bare if/for/return inside a class body
    is not valid Java and tree-sitter mis-parses it (e.g. `if(x)` as a constructor call),
    so we wrap it: ``class _Dummy { void _m() { <snippet> } }`` and extract _m's body block.
    """
    return f"class _DiffDummy {{\nvoid _m() {{\n{method_source}\n}}\n}}\n"


def _parse_method_block(method_source: str) -> tuple[Optional[Node], Optional[bytes]]:
    """Return (body_block_node, source_bytes) for the method body, or (None, None).

    Tries two wrappings: (1) snippet is a full method_declaration, (2) snippet is a body
    fragment wrapped in a dummy method. Picks the first that yields a `block` node.
    """
    if PARSER is None:
        return None, None

    for wrapper in (_wrap_as_class, _wrap_as_body):
        wrapped = wrapper(method_source)
        source = wrapped.encode("utf-8")
        try:
            tree = PARSER.parse(source)
        except Exception:
            continue
        for mtype in _METHOD_NODE_TYPES:
            for node in _find_all_children(tree.root_node, mtype):
                body = _find_child(node, "block")
                if body is not None:
                    return body, source
    return None, None


def _normalize(text: str) -> str:
    return " ".join(text.split())


def _signature(node: Node, source: bytes) -> tuple[str, str]:
    return (node.type, _normalize(_text(node, source)))


def _statement_sequence(block: Optional[Node], source: bytes) -> list[tuple[tuple[str, str], Node]]:
    """Flatten a block node's direct named statement children into (signature, node) pairs.

    Direct children of the block are the statement granularity we diff at; deeper sub-nodes
    would be redundant with their parent statement's text. This matches what a Semgrep pattern
    targets (whole statements/expressions), so the delta maps cleanly to rule-generation hints.
    """
    if block is None:
        return []

    seq: list[tuple[tuple[str, str], Node]] = []
    for i in range(block.child_count):
        child = block.child(i)
        if not child.is_named:
            continue
        if child.type in ("line_comment", "block_comment"):
            continue
        seq.append((_signature(child, source), child))
    return seq


def diff_method_pair(method: MethodPair) -> MethodASTDelta:
    """Diff one method pair's buggy vs fixed source into a MethodASTDelta.

    Uses difflib.SequenceMatcher on statement signatures — the same sequence-alignment +
    intersection idea as RuleRefiner's graph.diff (graph.py:29), adapted from "two execution
    paths through one rule graph" to "two statement sequences from buggy/fixed source trees".
    Presence replaces truth-value as the discriminating signal.
    """
    buggy_block, buggy_src = _parse_method_block(method.buggy_source)
    fixed_block, fixed_src = _parse_method_block(method.fixed_source)

    deltas: list[ASTNodeDelta] = []

    if buggy_block is None or fixed_block is None:
        # Parse failure: degrade to a single "changed" delta over the whole text so the
        # generator still gets a signal. Better than dropping the method silently.
        if method.buggy_source.strip() != method.fixed_source.strip():
            deltas.append(ASTNodeDelta(
                node_type="<unparseable>",
                buggy_text=method.buggy_source or None,
                fixed_text=method.fixed_source or None,
                change="changed",
            ))
        return MethodASTDelta(method=method, deltas=deltas)

    buggy_seq = _statement_sequence(buggy_block, buggy_src)
    fixed_seq = _statement_sequence(fixed_block, fixed_src)
    buggy_sigs = [sig for sig, _ in buggy_seq]
    fixed_sigs = [sig for sig, _ in fixed_seq]

    sm = difflib.SequenceMatcher(a=buggy_sigs, b=fixed_sigs, autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        if tag == "delete":
            # present in buggy, absent in fixed → the bug pattern (rule should match)
            for i in range(i1, i2):
                deltas.append(ASTNodeDelta(
                    node_type=buggy_seq[i][0][0],
                    buggy_text=_text(buggy_seq[i][1], buggy_src),
                    fixed_text=None,
                    change="added_in_buggy",
                ))
        elif tag == "insert":
            # present in fixed, absent in buggy → the fix's addition (rule should avoid)
            for j in range(j1, j2):
                deltas.append(ASTNodeDelta(
                    node_type=fixed_seq[j][0][0],
                    buggy_text=None,
                    fixed_text=_text(fixed_seq[j][1], fixed_src),
                    change="added_in_fixed",
                ))
        elif tag == "replace":
            for i in range(i1, i2):
                buggy_text = _text(buggy_seq[i][1], buggy_src)
                fixed_text = _text(fixed_seq[j1 + (i - i1)][1], fixed_src) if (j1 + (i - i1)) < j2 else None
                deltas.append(ASTNodeDelta(
                    node_type=buggy_seq[i][0][0],
                    buggy_text=buggy_text,
                    fixed_text=fixed_text,
                    change="changed",
                ))

    return MethodASTDelta(method=method, deltas=deltas)
