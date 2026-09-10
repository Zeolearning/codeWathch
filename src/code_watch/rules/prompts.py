from __future__ import annotations

from code_watch.analysis.schema import BugAnalysis

# --- Rule generation (Module 2) -----------------------------------------------

_SEMGREP_SCHEMA_CHEATSHEET = """Semgrep YAML rule schema (Java). Top-level: `rules:` is a list.

Two matching modes — pick based on the bug:

1. SYNTACTIC (pattern mode) — grammar-tree matching. Use for missing guards, unsafe calls, \
specific code shapes. Top-level key: `pattern` / `patterns` / `pattern-either` / `pattern-regex`.
   - `pattern: <expr>` — single pattern, match = report.
   - `patterns: [ ... ]` — AND: every sub-pattern must hold in the same scope.
   - `pattern-either: [ ... ]` — OR: any sub-pattern matches.
   Sub-operators inside `patterns:`:
     - pattern                    must match
     - pattern-inside             only match within this context block
     - pattern-not-inside         exclude matches inside this context (reduce false positives)
     - pattern-not                exclude this match
     - metavariable-regex         constrain a metavariable by regex
     - metavariable-comparison    constrain a metavariable by Python comparison
     - focus-metavariable: $X     report only $X's location, not the whole match
   Syntactic example:
     rules:
     - id: ex
       languages: [java]
       severity: ERROR
       message: ...
       patterns:
       - pattern-either:
         - pattern: SAXParserFactory.newInstance()
         - pattern: $SPF = SAXParserFactory.newInstance()
       - pattern-not-inside: |
           $RET $M(...) { ... $SPF.setFeature("...", true); ... }

2. TAINT (dataflow) — a tainted VALUE flows to a dangerous sink. Use when the bug is about a \
value traveling: user input reaching exec/query/URL/File (injection), a nullable/unchecked \
return being dereferenced, a resource acquired but never released. The engine tracks def-use \
flow (assignments, arguments, returns, field writes) inside a method; your patterns only \
decide WHERE to seed, stop, and report taint. Top-level: `mode: taint` + `pattern-sources` \
/ `pattern-sinks` / `pattern-sanitizers` (+ optional `pattern-propagators` to model a value \
surviving a specific through-call). Each source/sink/sanitizer is a bare `pattern`, a \
`pattern-either`, or a `{patterns: [...], focus-metavariable: $X}` formula.
   Taint example (nullable getter dereferenced without a null guard):
     rules:
     - id: ex-taint
       languages: [java]
       mode: taint
       severity: ERROR
       message: value from a nullable getter is dereferenced without a null guard
       pattern-sources:
       - pattern-either:                 # the dangerous ORIGIN — specific APIs only
         - pattern: getChannel(...)
         - pattern: $OBJ.getDynamicConfiguration(...)
       pattern-sinks:
       - pattern: $X.$M(...)            # any method call ON the tainted value = dereference
       pattern-sanitizers:
       - patterns:                       # null-guarded block: uses of the SAME $X
         - pattern: $X
         - pattern-inside: |
             if (<... $X != null ...>) {
               ...
             }
       - pattern-either:                 # Optional wrap cleans the value
         - pattern: Optional.ofNullable(...)
         - pattern: java.util.Optional.ofNullable(...)
   Taint mechanics (each item matters for correctness):
     - Engine, not patterns, computes the flow: taint survives assignments, argument passing, \
and branch joins (may-analysis: ANY path carrying taint counts, so joins are conservative).
     - Analysis is intra-procedural by default; use `pattern-propagators` to model a value \
flowing through a specific helper call when needed.
     - `$X` appearing in BOTH a sanitizer's `pattern` and its `pattern-inside` is UNIFIED: the \
sanitizer covers only uses of the SAME expression the guard checked — a `d != null` guard does \
NOT sanitize uses of `c`.
     - `<... $X != null ...>` is the deep-expression ellipsis: it finds the check at ANY nesting \
depth inside the if condition (`if (ok && c != null)`); bare `...` matches any statements.
     - Fully-qualified names do NOT match short spellings and vice versa: list BOTH in a \
`pattern-either` (`Optional.ofNullable(...)` AND `java.util.Optional.ofNullable(...)`).
     - Sources must be SPECIFIC APIs from the bug (a broad source like `$X.getY()` taints \
everything and fires everywhere); sinks may stay broad — precision comes from the source list.

Metavariables: `$NAME` (uppercase) matches any AST node; `...` matches any code \
(0+ statements/args); `$X` bound in one pattern can be referenced in \
`metavariable-regex`/`focus-metavariable`/`metavariable-comparison`.

Optional fields (usually OMIT): `fix`/`fix-regex` (autofix), `metadata` (cwe/owasp), \
`paths`, `options` (taint config only).
"""

GEN_SYSTEM_PROMPT = """You are Code Watch Rule-Gen, an expert in Java static analysis and Semgrep rule \
engineering. You receive a structural delta between a vulnerable and a patched version of a Java \
method (plus the root cause and the exact vulnerable line ranges), and you write a Semgrep YAML \
rule that:

  - MATCHES the vulnerable version at the affected locations (detects the vulnerability).
  - STAYS SILENT on the patched version (the fix removes the pattern the rule targets).

## Output contract (STRICT)
You MUST submit the final rule by calling the `submit_rule` tool with the complete rule \
YAML as the tool argument (content starts with `rules:`). The output file path is fixed \
by the system — do not ask for or invent a path. Every submission is validated with \
`semgrep --validate`; if the tool result reports REJECTED, fix ONLY the reported \
syntax/schema problem (keep the detection semantics unchanged) and call `submit_rule` \
again with the corrected YAML. Do not emit the YAML inline in your message text — it \
must go through the tool.

## Generalization contract (CRITICAL)
The buggy method is ONE instance of a mistake pattern. The rule must encode the PATTERN CLASS, \
not this instance — it should also catch the same class of mistake in different code, with \
different names, written by a different developer.

- Anchor on the MISTAKE, not a shape: the pattern must encode the semantic essence of the bug — \
the misused API, the missing validation, the wrong comparison, the unchecked value. A pattern \
that merely describes a common code shape (e.g. `return $CALL(...);` inside a method) carries \
zero bug semantics: it fires on ordinary correct code everywhere and proves nothing.
- NO verbatim method replicas: never quote a multi-statement block copied from the buggy source. \
Anchor on the minimal expression/statement that embodies the flaw, plus at most one surrounding \
context operator (`pattern-inside`).
- Metavariables for everything incidental: variable names, helper method names, types, constants \
unrelated to the flaw (`$X`, `$F`, `$RET`, `...`).
- Concrete identifiers/literals are allowed ONLY when they are the semantic essence of the bug \
(e.g. the misused API `Integer.decode`, the dangerous `"file:"` prefix).
- Prefer 1-2 small semantic anchors over one giant structural pattern. Use \
`focus-metavariable` to report at the vulnerable expression.
- Exclusions must generalize too: `pattern-not` / `pattern-not-inside` must exclude the CLASS of \
the fix — ANY equivalent guard/validation/sanitizer, written with metavariables — never the \
fix's literal text. A sibling's fix checks the same condition with different spellings \
(`length() > 1`, `isEmpty()`, `size() >= 1`, a range test); excluding only the training fix's \
exact spelling leaves the rule firing on correct code.
- Litmus test before writing, BOTH sides: (a) would this rule fire on a sibling bug — same \
mistake, different names, slightly different fix? (b) would it stay silent on correct code \
that has ANY equivalent guard? Fail either side → recalibrate: too narrow = verbatim replica, \
too broad = shape without bug semantics.

## Guidance
- Target the `added_in_buggy` nodes (the bug pattern) with `pattern` / `pattern-either`. These are \
what the rule MUST match.
- Use `pattern-not-inside` / `pattern-not` to exclude the `added_in_fixed` nodes (the fix's \
introduction, e.g. a new guard or a sanitizer call) — generalized to the guard CLASS as the \
exclusion contract above requires. Correct code must be silent, not just this fixed tree.
- The rule id should be `vul4j-<caseid>-r1` (lowercase, hyphens, e.g. `vul4j-10-r1`).
- **Always include `languages: [java]`** as a list under the rule. Never omit it.
- Omit `fix`/`metadata`/`paths`/`options` unless taint mode is required.
- Choose the mode by the bug's shape. Use `mode: taint` when the defect is a VALUE FLOWING to a \
dangerous use — external input reaching exec/query/URL/File (injection), a nullable/unchecked \
return being dereferenced (`$OBJ.getChannel().close()`), a resource acquired but never \
released (leak). In taint mode: sources = the dangerous ORIGIN (specific APIs from the delta), \
sinks = the dangerous USE of the value, sanitizers = the FIX's guard CLASS generalized with \
metavariables (null check, Optional wrap, try-with-resources/close). Otherwise prefer \
syntactic pattern mode (missing guard around a specific API, wrong comparison, unsafe \
construction — no value traveling).

## Inspection tools
You also have read-only tools (read_file / glob / grep / list_dir / java_symbols / java_index / \
bash) rooted at the double-checkout parent directory. Both source trees are available as \
`vul/...` (vulnerable) and `fix/...` (patched) relative paths — e.g. `read_file("vul/src/main/java/...")` \
to see the vulnerable file, or `grep` for an API usage. Use them when you need more context than \
the delta provides (surrounding code, callers, the exact guard the fix added), then submit via \
`submit_rule`.
"""


def _format_method_delta(md) -> str:
    """Render one MethodASTDelta as a prompt section."""
    lines = [f"### Method: {md.method.fqcn} :: {md.method.method_signature}"]
    lines.append("Buggy source:")
    lines.append("```java")
    lines.append(md.method.buggy_source.strip())
    lines.append("```")
    lines.append("Fixed source:")
    lines.append("```java")
    lines.append(md.method.fixed_source.strip())
    lines.append("```")
    if md.deltas:
        lines.append("Structural delta:")
        for d in md.deltas:
            if d.change == "added_in_buggy":
                lines.append(f"- [BUG PATTERN — rule MUST match] {d.node_type}: {d.buggy_text}")
            elif d.change == "added_in_fixed":
                lines.append(f"- [FIX INTRODUCED — rule should NOT match] {d.node_type}: {d.fixed_text}")
            elif d.change == "changed":
                lines.append(f"- [CHANGED] {d.node_type}: {d.buggy_text}  ->  {d.fixed_text}")
    else:
        lines.append("Structural delta: (none at statement level — use full method text)")
    return "\n".join(lines)


def build_generation_prompt(fix_delta, analysis: BugAnalysis, out_path: str) -> str:
    """Build the rule-generation user prompt from a FixDelta + BugAnalysis."""
    affected = "\n".join(f"  - {f}" for f in analysis.affected_files) or "  - (none)"
    method_sections = "\n\n".join(_format_method_delta(md) for md in fix_delta.method_deltas) or "(no methods)"

    return f"""Bug: {analysis.bug_id}

Root cause:
{analysis.root_cause}

Affected locations (file:line — the rule SHOULD fire here on the buggy tree):
{affected}

{method_sections}

Semgrep schema reference:
{_SEMGREP_SCHEMA_CHEATSHEET}

Target: a rule that GENERALIZES. The method above is one instance of a mistake-pattern class \
(e.g. "unchecked numeric parse then partial range-check", "index validated against the wrong \
bound", "unescaped user input into a path"). First identify the class in one short phrase, then \
write the rule for the CLASS — metavariables everywhere except the semantically essential API or \
literal. Both sides are enforced by the oracle: the rule MUST fire at the bug locations on the \
buggy tree, and MUST be silent on the fixed tree AND on any correct code guarded by an \
equivalent check. A rule that fires everywhere proves nothing; a rule that fires only on this \
exact instance generalizes nowhere.

    Write ONE Semgrep YAML rule (Java) that matches the vulnerability pattern (the `added_in_buggy` \
nodes above) and stays silent on the patched version (excludes the `added_in_fixed` nodes). The rule \
must fire at the affected locations on the vulnerable tree and fire nowhere on the patched tree.

Submit the rule by calling the `submit_rule` tool with the complete rule YAML as the
argument (content starts with `rules:`). Then stop.
"""


def build_round_feedback_prompt(rule, evaluation, analysis: BugAnalysis) -> str:
    """语义修复（增量反馈消息）：只含本轮差分结果与指令。

    不重复 root cause / 方法源码 / schema 速查表等大上下文——它们只在
    第 1 轮生成 prompt 里出现一次，作为对话历史的不可变前缀；每轮只
    追加这条增量消息，历史字节级不变，前缀缓存可命中全部历史 tokens。
    """
    def _lines(items: list[str], cap: int = 20) -> str:
        shown = items[:cap]
        text = "\n".join(f"  - {x}" for x in shown) or "  - (none)"
        if len(items) > cap:
            text += f"\n  ... and {len(items) - cap} more"
        return text

    if evaluation.status == "FP":
        verdict = (
            "FALSE POSITIVE: the rule fired on the FIXED tree — it matches correct code. "
            "Silence every location listed under 'fired on the FIXED tree' below: figure out "
            "what makes that code correct (usually a guard/validation) and exclude the guard "
            "CLASS with a metavariableed `pattern-not-inside` — any equivalent check "
            "(`$S.length() > $N`, `$C.isEmpty()`, a range/emptiness test), NOT the fix's "
            "literal spelling. Do NOT over-exclude: the rule must still fire at the expected "
            "buggy locations and still catch sibling bugs."
        )
    elif evaluation.status == "FN":
        verdict = (
            "FALSE NEGATIVE: the rule missed the expected buggy locations. Re-anchor on the "
            "semantic essence of the mistake (the misused API / missing check / wrong "
            "comparison); replace training-specific identifiers and literals with "
            "metavariables and `...` — but keep it specific to the mistake: do NOT degrade "
            "it into a generic code shape that fires on ordinary correct code."
        )
    else:
        verdict = (
            f"SYNTAX ERROR: the rule still fails `semgrep --validate`.\n"
            f"semgrep error:\n{evaluation.validation_msg[:2000]}"
        )

    return f"""Round feedback for bug {analysis.bug_id} (previous rule `{rule.rule_id}`):

Evaluation: status={evaluation.status} precision={evaluation.precision} recall={evaluation.recall}

{verdict}

Where the rule fired on the BUGGY tree (should cover the expected locations):
{_lines(evaluation.fired_on_buggy)}

Where the rule fired on the FIXED tree (must be empty):
{_lines(evaluation.fired_on_fixed)}

Expected locations on the buggy tree:
{_lines(evaluation.expected)}

Submit the corrected rule with the `submit_rule` tool. Then stop.
"""
