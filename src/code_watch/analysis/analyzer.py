from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from langchain.agents import create_agent
from langchain_core.messages import AIMessage, HumanMessage

from code_watch.analysis.prompts import SYSTEM_PROMPT, build_analysis_prompt
from code_watch.analysis.schema import BugAnalysis
from code_watch.config import CodeWatchConfig
from code_watch.context import RepoContext
from code_watch.llm import get_llm
from code_watch.tools import build_tools
from code_watch.tracing import get_run_url_for_name
from code_watch.workspace import GitCase


def _llm(config: CodeWatchConfig):
    return get_llm(config)


def _build_analysis_agent(config: CodeWatchConfig, ctx: RepoContext):
    return create_agent(
        model=_llm(config),
        tools=build_tools(ctx),
        system_prompt=SYSTEM_PROMPT,
    )


def _extract_analysis(config: CodeWatchConfig, extraction_prompt: str, fallback: BugAnalysis) -> BugAnalysis:
    """Structured extraction with a degradation chain:
    json_mode -> plain-JSON parse -> deterministic fallback (pipeline must survive).
    """
    # 1) json_mode structured output
    try:
        out = _llm(config).with_structured_output(BugAnalysis, method="json_mode").invoke(extraction_prompt)
        if out is not None:
            return out
        print("[analyze] json_mode returned null, falling back to plain JSON", flush=True)
    except Exception as e:
        print(f"[analyze] json_mode extraction failed ({type(e).__name__}), falling back to plain JSON", flush=True)

    # 2) plain completion, extract the first {...} JSON block
    try:
        text = _llm(config).invoke(
            extraction_prompt
            + "\n\nIMPORTANT: respond with ONLY the JSON object, no prose, no code fences."
        ).content
        m = re.search(r"\{.*\}", str(text), re.DOTALL)
        if m:
            return BugAnalysis.model_validate_json(m.group(0))
    except Exception as e:
        print(f"[analyze] plain-JSON extraction failed ({type(e).__name__}), using deterministic fallback", flush=True)

    # 3) deterministic fallback: never block the pipeline on the analyzer
    print("[analyze] using deterministic fallback BugAnalysis (root_cause=subject)", flush=True)
    return fallback


def analyze_git_case(
    case: GitCase,
    *,
    verbose: bool = True,
) -> BugAnalysis:
    """Analyze one git-mined case over its materialized vul/ + fix/ trees.

    The case workspace is self-contained (patch.diff + vul/ + fix/), so the
    analysis agent never touches the source repository.
    """
    case_id = case.case_id
    patch = case.patch_src
    if verbose:
        print(f"[1/3] Case {case_id}: {len(patch.splitlines())} patch lines", flush=True)
        print(f"      workspace: {case.workspace}", flush=True)

    config = CodeWatchConfig.from_env(repo_path=str(case.workspace))
    config.apply_env()

    ctx = RepoContext(repo_root=str(case.workspace), config=config)
    agent = _build_analysis_agent(config, ctx)
    prompt = build_analysis_prompt(case, patch)

    run_name = f"analyze-{case_id}-{int(time.time())}"
    stream_config = {
        "run_name": run_name,
        "metadata": {"bug": case_id},
        "recursion_limit": 100,  # full trees invite deep exploration; 50 was hit in practice
        "configurable": {"thread_id": f"analysis-{case_id}"},
    }

    if verbose:
        print(f"[3/3] Invoking agent (recursion_limit=100) ...", flush=True)
    t0 = time.time()

    last_text = ""
    tool_trace: list[dict] = []
    recursion_hit = False
    try:
        for chunk in agent.stream(
            {"messages": [HumanMessage(content=prompt)]},
            stream_config,
        ):
            if not isinstance(chunk, dict):
                continue
            for node_name, node_output in chunk.items():
                if not (isinstance(node_output, dict) and "messages" in node_output):
                    continue
                for msg in node_output["messages"]:
                    if not isinstance(msg, AIMessage):
                        continue
                    if getattr(msg, "tool_calls", None):
                        for tc in msg.tool_calls:
                            tool_trace.append({"tool": tc["name"], "args": tc["args"]})
                            if verbose:
                                elapsed = time.time() - t0
                                args_preview = json.dumps(tc["args"], ensure_ascii=False)[:150]
                                print(f"  [{elapsed:.0f}s] ▶ {tc['name']}({args_preview})", flush=True)
                    elif msg.content:
                        last_text = msg.content
                if node_name == "tools":
                    try:
                        tool_result = node_output.get("messages", [])
                        if tool_trace and tool_result:
                            preview = str(getattr(tool_result[-1], "content", ""))[:200]
                            tool_trace[-1]["result"] = preview
                    except Exception:
                        pass
                    if verbose:
                        elapsed = time.time() - t0
                        print(f"  [{elapsed:.0f}s] ◀ tool result", flush=True)
    except Exception as e:  # e.g. GraphRecursionError: keep the partial trace
        recursion_hit = True
        if verbose:
            print(f"[3/3] agent stopped early ({type(e).__name__}); using partial trace "
                  f"({len(tool_trace)} tool calls)", flush=True)

    if verbose:
        elapsed = time.time() - t0
        print(f"Agent done in {elapsed:.1f}s", flush=True)

    if verbose and os.getenv("LANGSMITH_API_KEY") and str(os.getenv("LANGSMITH_TRACING", "")).lower() in ("true", "1", "yes"):
        url = get_run_url_for_name(config.langsmith_project, run_name)
        if url:
            print(f"LangSmith trace: {url}", flush=True)

    if verbose:
        print("Extracting structured output...", flush=True)

    extraction_prompt = (
        f"Bug fix under analysis: {case_id}\n"
        f"Fix subject: {case.subject}\n"
        f"Patch:\n{patch}\n\n"
        f"Agent tool calls:\n{json.dumps(tool_trace, ensure_ascii=False)}\n\n"
        f"Agent analysis:\n{last_text}\n\n"
        + ("NOTE: the exploration agent hit its step budget before finishing; "
           "base the analysis on the tool calls and their results above.\n\n" if recursion_hit else "")
        + f"Produce a BugAnalysis (respond in JSON). Requirements:\n"
        f"- bug_id: '{case_id}'.\n"
        f"- root_cause: a single English sentence using AND/OR/NOT propositional logic.\n"
        f"- affected_files: list of 'file:line' or 'file:line-range' IN THE BUGGY TREE "
        f"WITHOUT the vul/ prefix, part of the root cause.\n"
        f"- reasoning_trace: an ordered list reproducing the reasoning steps above; "
        f"each entry is either a dict {{'tool','args','result'}} or a plain string."
    )

    fallback = BugAnalysis(
        bug_id=case_id,
        root_cause=f"Bug fixed by commit: {case.subject}",
        affected_files=list(case.files),
        patch_src=patch,
    )
    final = _extract_analysis(config, extraction_prompt, fallback)

    # Deterministically thread the fix signal into the persisted analysis so the
    # rule pipeline can consume it without re-reading the case workspace.
    final.bug_id = case_id
    final.patch_src = patch

    if verbose:
        print("Done.", flush=True)

    return final
