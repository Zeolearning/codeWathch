from __future__ import annotations

import json
import os
import time
from pathlib import Path

from langchain.agents import create_agent
from langchain_core.messages import AIMessage, HumanMessage

from code_watch.analysis.prompts import SYSTEM_PROMPT, build_analysis_prompt
from code_watch.analysis.schema import BugAnalysis
from code_watch.config import CodeWatchConfig
from code_watch.context import RepoContext
from code_watch.dataset.vul4j import checkout_pair, compute_patch, load_case
from code_watch.llm import get_llm
from code_watch.tools import build_tools
from code_watch.tracing import get_run_url_for_name


def _llm(config: CodeWatchConfig):
    return get_llm(config)


def _build_analysis_agent(config: CodeWatchConfig, ctx: RepoContext):
    return create_agent(
        model=_llm(config),
        tools=build_tools(ctx),
        system_prompt=SYSTEM_PROMPT,
    )


def analyze_case(
    case_id: str,
    *,
    base_dir: str | None = None,
    refresh: bool = False,
    verbose: bool = True,
) -> tuple[BugAnalysis, Path, Path, Path]:
    """Analyze one Vul4J case over the dual checkout (vul/ + fix/).

    Returns (analysis, parent, vul_dir, fix_dir) so the rule pipeline reuses the
    same trees instead of re-checking-out.
    """
    case = load_case(case_id)

    if verbose:
        print(f"[1/3] Checking out {case_id} ({case.project}, {case.cwe_id})...", flush=True)
    parent, vul_dir, fix_dir = checkout_pair(case_id, base_dir=base_dir, refresh=refresh)
    if verbose:
        print(f"      workdir: {parent}", flush=True)

    patch = compute_patch(vul_dir)
    if verbose:
        print(f"[2/3] Patch: {len(patch.splitlines())} diff lines", flush=True)

    config = CodeWatchConfig.from_env(repo_path=str(parent))
    config.apply_env()

    ctx = RepoContext(repo_root=str(parent), config=config)
    agent = _build_analysis_agent(config, ctx)
    prompt = build_analysis_prompt(case, patch)

    run_name = f"analyze-{case_id}-{int(time.time())}"
    stream_config = {
        "run_name": run_name,
        "metadata": {"bug": case_id},
        "recursion_limit": 50,
        "configurable": {"thread_id": f"analysis-{case_id}"},
    }

    if verbose:
        print(f"[3/3] Invoking agent (recursion_limit=50) ...", flush=True)
    t0 = time.time()

    last_text = ""
    tool_trace: list[dict] = []
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
        f"Vulnerability: {case_id}\n"
        f"CWE: {case.cwe_id} {case.cwe_name}\n"
        f"Patch:\n{patch}\n\n"
        f"Agent tool calls:\n{json.dumps(tool_trace, ensure_ascii=False)}\n\n"
        f"Agent analysis:\n{last_text}\n\n"
        f"Produce a BugAnalysis (respond in JSON). Requirements:\n"
        f"- bug_id: '{case_id}'.\n"
        f"- root_cause: a single English sentence using AND/OR/NOT propositional logic.\n"
        f"- affected_files: list of 'file:line' or 'file:line-range' IN THE VULNERABLE TREE "
        f"WITHOUT the vul/ prefix, part of the root cause.\n"
        f"- reasoning_trace: an ordered list reproducing the reasoning steps above; "
        f"each entry is either a dict {{'tool','args','result'}} or a plain string."
    )

    final = _llm(config).with_structured_output(BugAnalysis, method="json_mode").invoke(extraction_prompt)

    # Deterministically thread the fix signal into the persisted analysis so the
    # rule pipeline can consume it without re-reading the dataset checkout.
    final.bug_id = case_id
    final.patch_src = patch

    if verbose:
        print("Done.", flush=True)

    return final, parent, vul_dir, fix_dir
