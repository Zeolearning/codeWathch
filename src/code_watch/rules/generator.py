from __future__ import annotations

import json
import os
import time
from io import StringIO
from pathlib import Path

from langchain.agents import create_agent
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage
from ruamel.yaml import YAML

from code_watch.analysis.schema import BugAnalysis
from code_watch.config import CodeWatchConfig
from code_watch.context import RepoContext
from code_watch.llm import get_llm
from code_watch.rules.prompts import GEN_SYSTEM_PROMPT, build_generation_prompt
from code_watch.rules.schema import FixDelta, Rule
from code_watch.rules.semgrep_runner import validate_rule
from code_watch.tools import build_tools
from code_watch.tools.write_file import make_submit_rule_tool
from code_watch.tracing import get_run_url_for_name


class RuleGenError(RuntimeError):
    """Raised when the rule-generation agent produced no usable rule file.

    Carries the agent's last message text + tool events (`raw`) so the repair loop
    can feed it back into the next attempt instead of only the truncated message.
    """

    def __init__(self, bug_id: str, raw: str):
        self.raw = raw
        super().__init__(
            f"LLM agent did not write a rule yaml file for {bug_id}.\n"
            f"Agent output:\n{raw[:1000]}"
        )


def _extract_rule_fields(yaml_text: str) -> tuple[str, str, str]:
    """Return (message, severity, mode) parsed from the rule YAML. Defaults on failure."""
    message, severity, mode = "", "ERROR", "pattern"
    try:
        y = YAML()
        y.preserve_quotes = True
        data = y.load(StringIO(yaml_text))
        rule = (data.get("rules") or [{}])[0] if data else {}
        message = str(rule.get("message") or "")
        severity = str(rule.get("severity") or "ERROR")
        mode = "taint" if rule.get("mode") == "taint" else "pattern"
    except Exception:
        pass
    return message, severity, mode


def _print_trace_url(config: CodeWatchConfig, run_name: str, verbose: bool) -> None:
    """Print the LangSmith trace URL for a rule-gen run."""
    if not verbose:
        return
    if os.getenv("LANGSMITH_API_KEY") and str(os.getenv("LANGSMITH_TRACING", "")).lower() in ("true", "1", "yes"):
        url = get_run_url_for_name(config.langsmith_project, run_name)
        if url:
            print(f"[gen] LangSmith trace: {url}", flush=True)


def generate_rule(
    fix_delta: FixDelta,
    analysis: BugAnalysis,
    config: CodeWatchConfig,
    *,
    verbose: bool = True,
    repair_prompt: str | None = None,
    attempt: int = 1,
    out_path: str | None = None,
    history: list[BaseMessage] | None = None,
    repo_root: str | None = None,
) -> Rule:
    """Generate a Semgrep YAML rule from a FixDelta + BugAnalysis.

    Pipeline: an agent whose tools are `submit_rule(content)` (a validation hook runs
    `semgrep --validate` on every submission and returns the verdict to the agent, so
    a broken rule is fixed in the same turn) plus a set of read-only tools
    (read_file/glob/grep/list_dir/java_symbols/java_index/bash) rooted at `repo_root`
    so the agent can inspect the buggy/fixed source trees before writing the rule.
    The rule YAML is saved to a code-fixed out_path -> read back -> validate (reusing
    the hook's verdict) -> Rule. `repair_prompt` is the message for this round: the
    full generation prompt on round 1, a small delta feedback message (evaluation
    result / semgrep error) on later rounds.

    Context/caching: `history` is the running conversation. This round's request is
    `history + [HumanMessage(repair_prompt)]`; after the run, this round's REAL
    messages (the prompt plus every AIMessage/ToolMessage the agent produced) are
    appended to the SAME list in place — so the next round's request is this one plus
    a small new tail, and the provider's prefix cache reuses everything except that
    tail. Raises RuleGenError if the agent submitted no rule.
    """
    if out_path is None:
        out_path = f"output/rules/vul4j-{analysis.bug_id}/vul4j-{analysis.bug_id}-gen-rule.yaml"
    prompt = repair_prompt if repair_prompt is not None else build_generation_prompt(fix_delta, analysis, out_path)

    # Fresh write target: a stale file from a previous run must not be mistaken for output.
    yaml_path = Path(out_path)
    yaml_path.parent.mkdir(parents=True, exist_ok=True)
    if yaml_path.exists():
        yaml_path.unlink()

    # Validation hook: every submit_rule call runs `semgrep --validate` inside the
    # tool; the agent sees the verdict as the tool result and self-corrects within
    # the same conversation turn. validation_state carries the last verdict out.
    submit_tool, validation_state = make_submit_rule_tool(str(yaml_path), validator=validate_rule)

    # Read-only inspection tools so the agent can look at the buggy/fixed trees
    # (e.g. confirm the exact code around a delta before writing the pattern).
    ctx = RepoContext(repo_root=repo_root or config.repo_path or str(Path.cwd()), config=config)
    agent = create_agent(
        model=get_llm(config),
        tools=[submit_tool, *build_tools(ctx)],
        system_prompt=GEN_SYSTEM_PROMPT,
    )

    if verbose:
        print(f"[gen] Generating rule for {analysis.bug_id} (attempt {attempt}) ...", flush=True)
    t0 = time.time()
    run_name = f"rulegen-{analysis.bug_id}-{int(time.time())}"
    stream_config = {
        "run_name": run_name,
        "metadata": {"bug": analysis.bug_id, "phase": "rule-gen", "attempt": attempt},
        # Budget headroom for in-turn resubmissions after a REJECTED validation.
        "recursion_limit": 40,
        "configurable": {"thread_id": f"rulegen-{analysis.bug_id}"},
    }

    last_text = ""
    tool_events: list[str] = []
    # Round messages actually exchanged with the LLM: agent AIMessages and tool
    # ToolMessages, in stream order, deduplicated by object identity. These become
    # the exact cached prefix for the next round (appended to history), NOT a
    # synthetic summary.
    round_messages: list[BaseMessage] = []
    seen_messages: set[int] = set()
    messages = list(history or []) + [HumanMessage(content=prompt)]
    if verbose and history:
        print(f"[gen] Replaying {len(history)} history messages from previous rounds", flush=True)
    for chunk in agent.stream({"messages": messages}, stream_config):
        if not isinstance(chunk, dict):
            continue
        for node_name, node_output in chunk.items():
            if not (isinstance(node_output, dict) and "messages" in node_output):
                continue
            for msg in node_output["messages"]:
                # Record every real exchanged message (agent + tool) in stream order,
                # deduplicated by identity — these become the cached prefix.
                if isinstance(msg, (AIMessage, ToolMessage)) and id(msg) not in seen_messages:
                    seen_messages.add(id(msg))
                    round_messages.append(msg)
                if not isinstance(msg, AIMessage):
                    continue
                tool_calls = getattr(msg, "tool_calls", None) or []
                if tool_calls:
                    for tc in tool_calls:
                        args = json.dumps(tc.get("args", {}), ensure_ascii=False)
                        tool_events.append(f"{tc.get('name', '?')}({args})")
                        if verbose:
                            print(f"  [{time.time() - t0:.0f}s] ▶ {tc.get('name', '?')}({args[:150]})", flush=True)
                elif msg.content:
                    last_text = msg.content
            if node_name == "tools" and tool_events:
                msgs = node_output.get("messages") or []
                if msgs:
                    result = str(getattr(msgs[-1], "content", ""))[:300]
                    tool_events[-1] += f" -> {result}"

    # Append this round's REAL messages to history (in place): the exact same bytes
    # the LLM saw, so the next round's request is this one + a small tail.
    if history is not None:
        history.append(HumanMessage(content=prompt))
        history.extend(round_messages)
        if verbose:
            print(f"[gen] history: +{len(round_messages) + 1} messages "
                  f"(total {len(history)})", flush=True)

    if not yaml_path.is_file():
        _print_trace_url(config, run_name, verbose)
        raw = (last_text + "\n" + "\n".join(tool_events)).strip()
        raise RuleGenError(analysis.bug_id, raw)
    yaml_text = yaml_path.read_text(encoding="utf-8").strip()

    # The validation hook already ran on the last submission inside the tool; reuse
    # its verdict instead of re-running semgrep. Fall back to a fresh validate only
    # if the agent somehow produced a file without a hook verdict.
    ok = validation_state["ok"]
    msg = validation_state["msg"]
    if ok is None:
        ok, msg = validate_rule(yaml_text)
    if verbose:
        print(f"[gen] LLM done in {time.time() - t0:.1f}s; semgrep --validate: {'ok' if ok else 'FAIL'}", flush=True)
        if not ok:
            print(f"[gen] validate msg: {msg[:300]}", flush=True)
        _print_trace_url(config, run_name, verbose)

    message, severity, mode = _extract_rule_fields(yaml_text)
    rule = Rule(
        rule_id=f"{analysis.bug_id}-r{attempt}".lower(),
        bug_id=analysis.bug_id,
        language="java",
        yaml=yaml_text,
        message=message,
        severity=severity,
        mode=mode,
        metadata={
            "generated_at": time.time(),
            "model": config.model,
            "attempt": attempt,
            "explanation": last_text[:2000],
            "validation_ok": ok,
            "validation_msg": msg if not ok else "",
        },
    )
    return rule


def save_rule(rule: Rule, path: str) -> str:
    """Persist a Rule to JSON. Returns the path written."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(rule.model_dump_json(indent=2), encoding="utf-8")
    return str(p)
