"""Extensible vulnerability-type registry for fix-commit classification.

Each vulnerability family (NPE, resource leak, ...) is a *matcher function*
registered under a canonical name. A matcher receives a commit dict and an
optional parsed diff record (from ``npe_diff_cluster.collect_diffs``) and
returns the list of canonical terms that hit; an empty list means no match.
Registering a new family is one decorated function — no other code changes.

Assignment is EXCLUSIVE by priority: a commit lands in exactly one
sub-dataset (the first matching type in priority order); every type that
hit is still recorded in ``all_matched_types`` for auditability.

CLI helpers:

* ``registered_types()`` — names in registration order.
* ``types_by_priority()`` — names in assignment-priority order.
* ``classify_commits(commits, diffs_by_hash, types=None)`` — assign commits
  to per-type buckets.

Current families:

* ``npe`` — message-based, the exact rules from ``npe_cluster``
  (NPE / null pointer / NullPointerException / bare "null" in fix context).
* ``resource_leak`` — strong message signals (leak/unclosed/not closed)
  alone, or weak signals (close/stream/...) confirmed by the diff adding
  ``.close()`` / try-with-resources / ``closeQuietly``.
"""

from __future__ import annotations

import re
from collections.abc import Callable

# A matcher inspects (commit, diff_record_or_None) -> matched terms.
# `diff_record` carries "files"/"deleted"/"added" keys; it is None when no
# diff was collected for the commit.
Matcher = Callable[[dict, dict | None], list[str]]


class TypeSpec:
    """Registered family: name + matcher + assignment priority (lower first)."""

    __slots__ = ("name", "matcher", "priority")

    def __init__(self, name: str, matcher: Matcher, priority: int) -> None:
        self.name = name
        self.matcher = matcher
        self.priority = priority


_REGISTRY: dict[str, TypeSpec] = {}


def register_type(name: str, *, priority: int = 100) -> Callable[[Matcher], Matcher]:
    """Decorator: add a matcher to the registry under ``name``."""

    def deco(fn: Matcher) -> Matcher:
        if name in _REGISTRY:
            raise ValueError(f"vulnerability type already registered: {name!r}")
        _REGISTRY[name] = TypeSpec(name, fn, priority)
        return fn

    return deco


def registered_types() -> list[str]:
    """All registered family names (registration order)."""
    return list(_REGISTRY)


def types_by_priority() -> list[str]:
    """Registered family names sorted by assignment priority (lower first)."""
    return [spec.name for spec in sorted(_REGISTRY.values(), key=lambda s: (s.priority, s.name))]


def _diff_added_text(diff_record: dict | None) -> str:
    """Added lines of a diff record joined for regex scanning ('' if absent)."""
    if not diff_record:
        return ""
    return "\n".join(str(ln) for ln in diff_record.get("added", []))


# --------------------------------------------------------------------------- #
# npe — message-based only, exactly the rules from npe_cluster (kept stable so
# subset counts stay comparable with earlier NPE runs).
# --------------------------------------------------------------------------- #
@register_type("npe", priority=10)
def _match_npe(commit: dict, diff_record: dict | None) -> list[str]:
    from .npe_cluster import _match_npe_terms, _npe_text

    return _match_npe_terms(_npe_text(commit))


# --------------------------------------------------------------------------- #
# resource_leak — strong message words only (leak / unclosed / not closed).
#
# A weaker variant (close/stream words + diff adding .close()) was tried and
# dropped: regular fixes whose diff incidentally adds a context.close() in
# tests sailed through and polluted the sub-dataset. Precision first: if the
# message doesn't say "leak", we don't claim leak.
# --------------------------------------------------------------------------- #
_LEAK_MSG_STRONG: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("leak", re.compile(r"\bleaks?\b", re.IGNORECASE)),
    ("unclosed", re.compile(r"\bunclosed\b", re.IGNORECASE)),
    ("not closed", re.compile(r"\b(?:not|never)\s+closed?\b", re.IGNORECASE)),
    ("mem leak (variant)", re.compile(r"\bmem\s+leaks?\b", re.IGNORECASE)),
)


@register_type("resource_leak", priority=20)
def _match_resource_leak(commit: dict, diff_record: dict | None) -> list[str]:
    from .npe_cluster import _npe_text

    text = _npe_text(commit)
    return [name for name, pattern in _LEAK_MSG_STRONG if pattern.search(text)]


# --------------------------------------------------------------------------- #
# Assignment
# --------------------------------------------------------------------------- #
def classify_commits(
    commits: list[dict],
    diffs_by_hash: dict[str, dict] | None = None,
    types: list[str] | None = None,
) -> dict[str, list[dict]]:
    """Assign commits to per-type buckets, exclusively by priority.

    Args:
        commits: commit dicts (from ``collect_fix_commits`` JSON).
        diffs_by_hash: optional ``hash -> diff record`` map from
            ``collect_diffs``; matchers receive ``None`` when absent.
        types: restrict to these family names (default: all, by priority).

    Returns:
        ``{type_name: [commit dicts]}`` in input order per bucket. Each
        record is a shallow copy annotated with:

        * ``matched_terms``: the assigned type's hit terms,
        * ``all_matched_types``: every family whose matcher hit this commit
          (sorted) — the audit trail for the exclusive assignment.
    """
    diffs_by_hash = diffs_by_hash or {}
    selected = [t for t in types_by_priority() if types is None or t in set(types)]
    unknown = set(types or []) - set(_REGISTRY)
    if unknown:
        raise KeyError(f"unknown vulnerability types: {sorted(unknown)}")

    buckets: dict[str, list[dict]] = {t: [] for t in selected}
    for commit in commits:
        diff_record = diffs_by_hash.get(str(commit.get("hash")))
        hits: dict[str, list[str]] = {}
        for type_name in selected:
            terms = _REGISTRY[type_name].matcher(commit, diff_record)
            if terms:
                hits[type_name] = terms
        if not hits:
            continue
        primary = next(t for t in selected if t in hits)  # priority order
        item = dict(commit)
        item["matched_terms"] = hits[primary]
        item["all_matched_types"] = sorted(hits)
        buckets[primary].append(item)
    return buckets
