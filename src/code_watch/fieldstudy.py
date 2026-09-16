"""Per-case nullable-accessor field study, cached on disk.

The fold merge needs to know WHICH accessors/APIs in a case's tree are
nullable — not only the ones the patch happens to touch. A field study is a
small read-only agent session over the case workspace that enumerates
candidate nullable accessors (conditionally-set fields, no-arg getters
returning possibly-null values, lookups that can return null) with
file:line evidence, plus the guard forms used in this tree.

The result is a property of the tree snapshot, so it is computed once per
case and cached at ``output/fieldstudy/<case_id>.json`` — fold rounds,
re-runs and later experiments reuse it for free.

Leakage note: a field study reads the case's OWN code (unlabeled). Using it
to widen accessor sets is semi-supervised (transductive); holdout *labels*
(defect lines) are never touched here.
"""
from __future__ import annotations

import json
import hashlib
import re
import time
from pathlib import Path

from langchain.agents import create_agent
from langchain_core.messages import AIMessage, HumanMessage
from pydantic import BaseModel, Field

from code_watch.config import CodeWatchConfig
from code_watch.context import RepoContext
from code_watch.llm import get_llm
from code_watch.tools import build_tools
from code_watch.workspace import GitCase

STUDY_SYSTEM_PROMPT = """You are a Java nullability surveyor. You explore ONE project snapshot \
(under vul/, the buggy tree) with read-only tools and enumerate values that can be null and \
are dereferenced without a guard nearby.

Method:
1. Read the patch context first (the field/method named by the user) to learn the defect trait.
2. Use grep/java_symbols to find SIBLING candidates with the same trait: fields that are \
conditionally assigned or injected via optional setters, no-arg getters returning such fields, \
lookup methods that can return null (map/config/registry lookups).
3. For each candidate record: name, kind (field|getter|lookup), file:line evidence (the code \
that proves nullability, e.g. a conditional assignment or a return-null path).
4. Also record the guard forms this codebase uses (if-null-return, ternary, requireNonNull...).

Be precise: only list candidates whose nullability you can EVIDENCE from code. Do not guess.
Answer in plain text with a bullet list; cite file:line for every claim."""


class AccessorFact(BaseModel):
    name: str = Field(description="accessor/field/API name, e.g. getAddress or getServiceInfo")
    kind: str = Field(default="getter", description='"field" | "getter" | "lookup"')
    file: str = Field(default="", description="evidence file path (repo-relative)")
    evidence: str = Field(default="", description="why this can be null, one sentence")


class FieldStudy(BaseModel):
    case_id: str
    nullable_accessors: list[AccessorFact] = Field(default_factory=list)
    guard_forms: list[str] = Field(default_factory=list, description="guard forms used in this tree")
    notes: str = ""


def study_path(case_id: str) -> Path:
    return Path(f"output/fieldstudy/{case_id}.json")


def load_field_study(case_id: str) -> FieldStudy | None:
    p = study_path(case_id)
    if not p.exists():
        return None
    try:
        return FieldStudy.model_validate_json(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def study_case(
    case: GitCase,
    config: CodeWatchConfig | None = None,
    *,
    focus: str = "",
    verbose: bool = True,
) -> FieldStudy:
    """Run the survey agent over the case's vul tree (read-only tools)."""
    case_id = case.case_id
    if config is None:
        config = CodeWatchConfig.from_env(repo_path=str(case.workspace))
    config.apply_env()

    ctx = RepoContext(repo_root=str(case.workspace), config=config)
    agent = create_agent(
        model=get_llm(config),
        tools=build_tools(ctx),
        system_prompt=STUDY_SYSTEM_PROMPT,
    )

    prompt = (
        f"Survey the buggy tree vul/ for nullable-accessor candidates related to this fix.\n"
        f"Fix subject: {case.subject}\n"
        f"Fix touched: {', '.join(case.files)}\n"
        f"Defect focus: {focus or 'a possibly-null value dereferenced without a guard'}\n\n"
        f"Enumerate sibling nullable accessors with evidence, and the guard forms in use."
    )

    run_config = {
        "run_name": f"fieldstudy-{case_id}-{int(time.time())}",
        "metadata": {"case": case_id},
        "recursion_limit": 40,
        "configurable": {"thread_id": f"fieldstudy-{case_id}"},
    }
    t0 = time.time()
    last_text = ""
    try:
        for chunk in agent.stream({"messages": [HumanMessage(content=prompt)]}, run_config):
            if not isinstance(chunk, dict):
                continue
            for node_output in chunk.values():
                if not (isinstance(node_output, dict) and "messages" in node_output):
                    continue
                for msg in node_output["messages"]:
                    if isinstance(msg, AIMessage) and not getattr(msg, "tool_calls", None) and msg.content:
                        last_text = msg.content
    except Exception as e:
        if verbose:
            print(f"[study] {case_id}: agent stopped early ({type(e).__name__})", flush=True)

    if verbose:
        print(f"[study] {case_id}: agent done in {time.time() - t0:.0f}s", flush=True)

    # structured extraction with plain-JSON fallback
    schema_hint = (
        'Respond ONLY as JSON: {"nullable_accessors": [{"name","kind","file","evidence"}], '
        '"guard_forms": ["..."], "notes": ""}'
    )
    study: FieldStudy | None = None
    try:
        study = (
            _llm(config)
            .with_structured_output(FieldStudy, method="json_mode")
            .invoke(
                f"Survey result:\n{last_text}\n\nPatch:\n{case.patch_src[:2000]}\n\n{schema_hint}\n"
                f"case_id must be '{case_id}'."
            )
        )
    except Exception:
        pass
    if study is None:
        try:
            text = _llm(config).invoke(f"{schema_hint}\n\nSurvey result:\n{last_text}").content
            m = re.search(r"\{.*\}", str(text), re.DOTALL)
            if m:
                study = FieldStudy.model_validate_json(m.group(0))
        except Exception:
            study = None
    if study is None:
        study = FieldStudy(case_id=case_id)
    study.case_id = case_id
    return study


def _llm(config: CodeWatchConfig):
    return get_llm(config)


def load_or_study(
    case: GitCase,
    config: CodeWatchConfig | None = None,
    *,
    refresh: bool = False,
    focus: str = "",
    verbose: bool = True,
) -> FieldStudy:
    """Cached field study: computed once per case, reused forever."""
    if not refresh:
        cached = load_field_study(case.case_id)
        if cached is not None:
            if verbose:
                print(f"[study] cached {case.case_id}: "
                      f"{len(cached.nullable_accessors)} accessors", flush=True)
            return cached
    study = study_case(case, config, focus=focus, verbose=verbose)
    p = study_path(case.case_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(study.model_dump_json(indent=2), encoding="utf-8")
    return study


# --- repo-wide candidate discovery (two-stage funnel) ------------------------ #
# Stage 1: deterministic text scan (no LLM) — methods with a `return null` path
#          and no-arg getters, cached per tree.
# Stage 2: LLM batch-judges which candidates are applicable to the rule family
#          (unlabeled code only — no defect lines involved).

def enumerate_repo_candidates(tree_root: str | Path, *, limit: int = 600) -> list[dict]:
    """Whole-repo structural scan for nullability smells (heuristic, no LLM).

    Signals: method containing `return null;` (strong), no-arg getter shape
    (weak). Pure text pass — fast, deterministic, cached per tree root.
    """
    import hashlib
    root = Path(tree_root)
    cache = Path("output/candidates") / (
        hashlib.sha1(str(root.resolve()).encode()).hexdigest()[:12] + ".json"
    )
    if cache.exists():
        return json.loads(cache.read_text(encoding="utf-8"))["candidates"]

    decl_re = re.compile(
        r"^\s*(?:public|protected|private|static|final|synchronized).*\)\s*"
        r"(?:throws [\w.,\s]+)?\{?\s*$"
    )
    getter_re = re.compile(r"\b(?:get|is)\w+\s*\(\s*\)")
    candidates: dict[tuple, dict] = {}
    files = 0
    for jp in root.rglob("*.java"):
        rel = jp.relative_to(root).as_posix()
        if "/test/" in rel or "/tests/" in rel:
            continue
        try:
            text = jp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        files += 1
        last_sig, last_line = "", 0
        for ln, line in enumerate(text.splitlines(), start=1):
            if decl_re.match(line) and "(" in line:
                last_sig, last_line = line.strip(), ln
            stripped = line.strip()
            if "return null;" not in stripped and not getter_re.search(stripped):
                continue
            sig = last_sig or stripped
            key = (rel, sig)
            entry = candidates.setdefault(
                key,
                {"signature": sig, "file": rel, "line": last_line or ln,
                 "return_null": False, "getter": False, "score": 0},
            )
            if "return null;" in stripped and not entry["return_null"]:
                entry["return_null"] = True
                entry["score"] += 2
                entry["line"] = last_line or entry["line"]
            if getter_re.search(stripped) and not entry["getter"]:
                entry["getter"] = True
                entry["score"] += 1
    out = sorted(candidates.values(), key=lambda c: -c["score"])[:limit]
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps({"files": files, "candidates": out}, ensure_ascii=False), encoding="utf-8")
    return out


class CandidateJudgments(BaseModel):
    applicable: list[int] = Field(default_factory=list, description="0-based indices into the listed batch")


def judge_candidates(
    llm,
    candidates: list[dict],
    rule_desc: str,
    *,
    batch: int = 60,
    verbose: bool = True,
) -> list[dict]:
    """Stage 2: LLM batch-judges which candidates fit the rule family."""
    applicable: list[dict] = []
    total = (len(candidates) + batch - 1) // batch
    for bi in range(0, len(candidates), batch):
        chunk = candidates[bi : bi + batch]
        listing = "\n".join(
            f"{j}. {c['signature']}  [{c['file']}:{c['line']}]"
            for j, c in enumerate(chunk)
        )
        prompt = (
            f"A Semgrep rule family targets: {rule_desc}\n\n"
            f"Java methods:\n{listing}\n\n"
            "Judge WHICH of these methods can return/produce NULL such that an UNGUARDED "
            "dereference of the result is a real NPE risk within this rule's scope. "
            "Exclude methods whose null-return is always handled by callers inside the same "
            "class, and exclude test helpers.\n"
            "Respond ONLY as JSON: {\"applicable\": [0-based indices]}. Use the word json in your reply."
        )
        try:
            judged = llm.with_structured_output(CandidateJudgments, method="json_mode").invoke(prompt)
            for idx in judged.applicable if judged else []:
                if 0 <= idx < len(chunk):
                    applicable.append(chunk[idx])
        except Exception as e:
            if verbose:
                print(f"[gen-candidates] batch {bi // batch + 1}/{total} failed: {str(e)[:120]}", flush=True)
        if verbose:
            print(f"[gen-candidates] batch {bi // batch + 1}/{total}: "
                  f"{len(judged.applicable) if judged else '?'}/{len(chunk)} applicable", flush=True)
    return applicable


def repo_candidate_study(
    tree_root: str | Path,
    rule_desc: str,
    config: CodeWatchConfig | None = None,
    *,
    refresh: bool = False,
    limit: int = 600,
    verbose: bool = True,
) -> dict:
    """Both stages combined, cached per (tree, rule_desc)."""
    import hashlib
    key = hashlib.sha1(
        (str(Path(tree_root).resolve()) + "|" + rule_desc).encode()
    ).hexdigest()[:12]
    cache = Path("output/fieldstudy") / f"repo-{key}.json"
    if cache.exists() and not refresh:
        out = json.loads(cache.read_text(encoding="utf-8"))
        if verbose:
            print(f"[gen-candidates] cached: {out['n_applicable']} applicable "
                  f"(from {out['n_candidates']} candidates)", flush=True)
        return out

    cands = enumerate_repo_candidates(tree_root, limit=limit)
    if config is None:
        config = CodeWatchConfig.from_env()
        config.apply_env()
    applicable = judge_candidates(get_llm(config), cands, rule_desc, verbose=verbose)
    out = {
        "tree": str(tree_root),
        "rule_desc": rule_desc,
        "n_candidates": len(cands),
        "n_applicable": len(applicable),
        "applicable": applicable,
    }
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return out
