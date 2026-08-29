# 规则生成 + 规则测试 接入 codeWatch 实施计划

> **目标**:在 codeWatch 现有"历史缺陷原因分析"(`analyze_bug`)之上,新增**从零创造 Semgrep 规则**的能力,并用"buggy 树命中 / fixed 树静默"作 oracle 在 Defects4J 测试集上评测。
>
> **关键定位**:这是**规则创造**,不是 RuleRefiner 的规则精化。RuleRefiner 修一条已存在的 buggy 规则;codeWatch 从 bug + fix 创造规则。两者复用面有限,本计划只取其可复用件,不强套其精化流程。

---

## 1. 背景与对齐

### 1.1 两个项目的本质差异

| 维度 | RuleRefiner | codeWatch(本计划) |
|---|---|---|
| 任务 | 精化一条**已存在**的 buggy Semgrep 规则 | 从 bug + fix **从零创造**规则 |
| 主输入 | buggy 规则 + 测试用例(通过/失败) + expected/actual | `BugAnalysis`(root_cause + affected_files) + buggy/fixed 两棵树 |
| 定位机制 | `semgrep --matching-explanations` 运行时 trace → 谓词图(`semgrep2nx`)→ `graph.diff` 比对**规则执行路径** | 不适用(无规则可跑 explanation)→ 改用 **agent 选片段 + tree-sitter AST 节点差分** |
| oracle | 之前正确的用例仍正确 + 失败用例现通过 | **buggy 树命中 affected_files ∧ fixed 树静默** |
| LLM 角色 | 在定位出的规则片段上填模板(精化) | 从 fix-delta + 规则 schema 从零写出整条规则(创造) |

### 1.2 codeWatch 现状(可复用基座)
- `analyze_bug()`(`src/code_watch/analysis/analyzer.py:35`)已产出 `BugAnalysis`(`analysis/schema.py:8`):`root_cause`(命题逻辑句)+ `affected_files`(精确 file:line)+ `reasoning_trace`。样本见 `output/analysis-Lang-1.json`。
- `DefectMetadata`(`defects4j/metadata.py:17`):带 `buggy_commit`/`fixed_commit`/`modified_classes`/`trigger_tests`/`patch_src`。
- `checkout_defect(project, bug_id, version)`(`defects4j/checkout.py:14`)可拿 buggy/fixed 两棵树。
- 7 个只读 agent 工具(`tools/__init__.py:20` 的 `build_tools(ctx)`):`read_file`/`glob`/`grep`/`list_dir`/`java_symbols`/`java_index`/`bash`,均闭包绑定 `RepoContext`(`context.py`),带路径 jail。
- LLM:`_llm(config)`(`analyzer.py:23`)返回 `ChatOpenAI(model=config.model, temperature=0)`,OpenAI 兼容(当前 `.env` 指 DeepSeek)。
- tree-sitter-java 已是依赖(`pyproject.toml`),`tools/java_symbols.py` 已有 AST 解析能力。
- 测试:`uv run pytest -q`,`@pytest.mark.slow` 标真实 D4J checkout。

### 1.3 关键缺口(本计划要补)
- `patch_src` 在 `analyzer.py:53` 塞进抽取 prompt 后丢弃,未持久化 → 模块 0.3 补。
- 零规则脚手架 → 全新 `src/code_watch/rules/` 子包。

---

## 2. 设计决策总览(已锁定)

| ID | 决策 | 选定 | 理由 |
|---|---|---|---|
| D1 | 规则表示 | **Semgrep YAML** | RuleRefiner 全栈基于它,Java 原生支持,最大化复用运行时/解析件 |
| D2 | AST diff 方式 | **Option C 混合** | 复用 `ts_cfg.TSHelper.gen_ast`(tree-sitter-java parser)+ 改造 `graph.diff` 算法骨架做 AST 节点序列差分;CFG 仅在控制流语义需要时补 |
| D3 | 相关片段选取 | **新增 rule-gen-prep agent** | 独立 agent 调用,职责分离,可独立迭代/缓存;不机械用 diff 切 hunk |
| D4 | patch_src 角色 | **agent 辅助线索** | 不作切片主路径,仅可选喂给 agent prompt 作提示 |

### 2.1 为什么 `graph.diff` 不能直接用、要改造
读完 `lcp_locate`(`RuleRefiner/semgrep_locate.py:64`)确认:`graph.diff(bad_path, good_path)`(`graph.py:29`)比的是**同一规则在失败用例 vs 通过用例上的两条"执行路径"**——节点是 `(ast_node_id, is_truth)`,`is_truth` = 该子 pattern 在此用例上是否真匹配。它定位"规则哪段子 pattern 判错了",前提是**已有一条规则可跑 `--matching-explanations`**。codeWatch 创造场景无规则可跑,`semgrep2nx.Semgrep2NX`/`align`/`is_true`/`lcp_locate` 整套**用不上**。

能复用的只有两件:
1. `ts_cfg.TSHelper.gen_ast`(`RuleRefiner/experimental/ts_cfg.py:21`)— tree-sitter-java 拿 Java AST(直接用,tree-sitter-java 已是 codeWatch 依赖)
2. `graph.diff` 的**算法骨架**(序列对齐 + 交集/区间检测 + 真值比较)— 改造到"buggy 方法 AST 节点序列 vs fixed 方法 AST 节点序列",真值语义从"子 pattern 是否匹配"改成"节点是否在 buggy/fixed 存在"

---

## 3. 模块详细设计

### 模块 0: 基建

**目的**:把后续模块依赖的共享底层理顺。

#### 0.1 共享 LLM 客户端
- **落地**:`src/code_watch/llm.py`
- **做法**:把 `analysis/analyzer.py:23` 的私有 `_llm(config)` 提升为模块级函数,新增 `LLMClient` 协议(`chat(prompt)->str` / `with_structured_output(model, method="json_mode")` / `set_temperature(t)`)。`analysis/analyzer.py` 与 `rules/generator.py`、`rules/prep_agent.py` 都从这里取。
- **规避**:RuleRefiner 各 backend(`deepseek.py`/`qwen.py`/`gpt.py`/`kimi.py`/`doubao.py`)的 `chat2` 返回类型异构(doubao 返回 str,其他返回 JSON)——codeWatch 不移植这些 backend,直接用 `ChatOpenAI` 统一。

#### 0.2 加依赖
- `pyproject.toml` 增:`semgrep`、`ruamel.yaml`、`tqdm`。`networkx` 仅模块 1.3 差分需要(轻量,可一并加)。
- **验证步骤**:先 `uv add semgrep` 跑 `uv sync`,确认与现有 `tree-sitter-java>=0.23` 无版本冲突;`uv run python -c "import semgrep"` 验证可装。这是模块 2/3 的硬前提,放最前。

#### 0.3 持久化 patch_src + modified_classes
- **落地**:改 `src/code_watch/analysis/schema.py:8` 的 `BugAnalysis`,增两个字段:`patch_src: str`、`modified_classes: list[str]`。
- **改 `analyzer.py`**:在 `analyzer.py:53` 已 `compute_clean_patch` 得 `meta.patch_src` 后,把它和 `meta.modified_classes` 传进 `analyzer.py:148-159` 的抽取 prompt,让模型在 `BugAnalysis` 里回填;或在写 `output/analysis-<project>-<bug>.json` 时直接注入(兜底,防模型漏填)。
- **理由**:模块 1.2 的 rule-gen-prep agent 要用 `patch_src` 作辅助线索。

#### 0.4 Rule 数据模型
- **落地**:`src/code_watch/rules/schema.py`
- **模型**:
  ```python
  class Rule(BaseModel):
      rule_id: str            # 如 "d4j-Lang-1-r1"
      bug_id: str             # 来源,如 "Lang-1"
      language: str = "java"
      yaml: str               # 完整 Semgrep YAML 规则字符串(rules: [...])
      message: str            # 从 yaml 抽取或单独存
      severity: str = "ERROR"
      mode: str = "pattern"   # "pattern" | "taint"
      metadata: dict          # {生成时间, 模型, prompt 版本, temperature}
  ```
- `yaml` 字段就是附录 A 描述的完整 `rules: [...]` 文本。

---

### 模块 1: fix 前后结构树理解(核心)

**目的**:为规则生成提供"buggy 中存在、fixed 中消除"的结构化 delta——这是从零创造规则的最强信号。

**输入**:`BugAnalysis`(root_cause + affected_files + patch_src + modified_classes) + `DefectMetadata`(buggy_commit/fixed_commit)
**输出**:`FixDelta`(`src/code_watch/rules/delta.py`):
```python
class MethodPair(BaseModel):
    fqcn: str                # 如 org.apache.commons.lang3.math.NumberUtils
    method_signature: str
    buggy_source: str
    fixed_source: str

class ASTNodeDelta(BaseModel):
    node_type: str           # tree-sitter 节点类型
    buggy_text: str | None
    fixed_text: str | None
    change: str              # "added_in_buggy" | "removed_in_fixed" | "changed"

class MethodASTDelta(BaseModel):
    method: MethodPair
    deltas: list[ASTNodeDelta]

class FixDelta(BaseModel):
    bug_id: str
    method_deltas: list[MethodASTDelta]   # agent 选出的每个方法一个
```

#### 1.1 checkout 两棵树到公共父目录
- **复用**:`defects4j/checkout.py:14` 的 `checkout_defect(project, bug_id, version, work_dir)`。
- **落地**:`src/code_watch/rules/checkout.py` 的 `checkout_both(project, bug_id) -> tuple[Path, Path]`,布局:
  ```
  tmp/rulegen-<project>-<bug>/
  ├── buggy/     # checkout_defect(version="buggy")
  └── fixed/     # checkout_defect(version="fixed")
  ```
- **关键设计**:两棵树放**公共父目录**下,这样模块 1.2 的 agent 用**一个 `RepoContext(repo_root=父目录)`** 即可用 `read_file("buggy/src/...")` / `read_file("fixed/src/...")` 同时访问两棵树,路径 jail(`context.py` 的 `ensure_inside`)仍满足,**现有工具签名零改动**。
- **缓存**:同一 `(project, bug_id)` 的 checkout 跨模块 1/3 复用,目录名带 bug_id 做幂等;批量评测(模块4)时按需清理。

#### 1.2 rule-gen-prep agent(相关片段选取)
**目的**:让 agent 用语义判断(而非机械 diff)选出与 bug 相关的方法,产出 buggy/fixed 配对源码片段。

**落地**:`src/code_watch/rules/prep_agent.py`,镜像 `analysis/analyzer.py:27-34` 的 `create_agent` 结构。

**架构**:
- `RepoContext(repo_root=tmp/rulegen-<project>-<bug>)` 单上下文,覆盖 buggy/ + fixed/ 两棵子树
- `build_tools(ctx)`(`tools/__init__.py:20`)复用现有 7 工具,零改动
- agent = `create_agent(model=_llm(config), tools=build_tools(ctx), system_prompt=PREP_SYSTEM_PROMPT)`
- 输出:`_llm(config).with_structified_output(RelevantSnippets, method="json_mode").invoke(prep_prompt)`(镜像 `analyzer.py:161` 的结构化抽取)

**输出 schema**(`rules/schema.py`):
```python
class Snippet(BaseModel):
    fqcn: str
    method_signature: str
    buggy_source: str        # 从 buggy/<path> 取
    fixed_source: str        # 从 fixed/<path> 取
    why_relevant: str        # agent 解释为何此方法与 root_cause 相关

class RelevantSnippets(BaseModel):
    bug_id: str
    snippets: list[Snippet]
```

**PREP_SYSTEM_PROMPT 要点**(放 `rules/prompts.py`):
- 身份:Java 源码结构分析专家
- 任务:给定 `root_cause` + `affected_files` + `patch_src`(辅助线索),在 buggy/ 和 fixed/ 两棵树中定位与 bug 相关的方法,成对抽取 buggy/fixed 源码
- 工具使用策略:`java_index` 先按 `modified_classes` 查方法定位 → `java_symbols` 抽 AST 确认方法边界 → `read_file` 取精确行范围;buggy/ 和 fixed/ 用相对路径前缀区分
- 输出:`why_relevant` 必须关联到 `root_cause` 的某个条件

**build_prep_prompt 输入**:`BugAnalysis`(root_cause, affected_files, patch_src)+ buggy_workdir + fixed_workdir。

**patch_src 角色(D4)**:作为辅助线索写进 prompt("开发者修复 diff 如下,仅作参考,最终选取以你的探索为准"),**不作切片主路径**。agent 可参考它缩小搜索范围,但相关方法由 agent 自主判定。

**测试**:`tests/test_rules_prep_agent.py`:
- 快速测试(无 LLM):mock `_llm` 返回固定 `RelevantSnippets`,断言 agent 能把 buggy/fixed 路径正确解析(用 `fixtures/sample-java` 复制成 buggy/fixed 对)
- `@pytest.mark.slow` 真实 Lang-1 跑一次,断言 `snippets` 非空且 `fqcn` 含 `NumberUtils`

#### 1.3 AST 节点差分(改造 graph.diff)
**目的**:对 agent 选出的每个方法,做 buggy vs fixed 的 AST 节点级差分,产出 `MethodASTDelta`。

**复用件**:
- `RuleRefiner/experimental/ts_cfg.py:21` `TSHelper.gen_ast(source)` — tree-sitter-java 解析,返回 root `Node`
- `RuleRefiner/experimental/ts_cfg.py:12` `TSHelper.find_methods(node)` — 找方法节点
- `RuleRefiner/graph.py:29` `diff(p1, p2)` 的**算法骨架** — 序列对齐 + 交集/区间检测 + 真值比较

**落地**:`src/code_watch/rules/ast_diff.py`

**改造点**(关键):`graph.diff` 原签名 `diff(p1, p2)` 其中 `p1`/`p2` 是 `[(node_id, is_truth), ...]` 路径,比的是同一图的两条执行路径。改造为 `ast_diff(buggy_nodes, fixed_nodes)`:
- 输入:`buggy_nodes`/`fixed_nodes` 是 AST 节点序列,每元素 `(signature, node)`,`signature = (node.type, normalized_text_hash)`(normalized = 去空白/注释后取 text)
- 对齐:沿用 `graph.diff` 的 `find_index` + 交集/区间逻辑,找出两序列的公共节点(签名匹配)和区间段
- 真值重映射:`is_truth` 原语义"子 pattern 是否匹配此用例"→ 新语义"节点是否存在于 buggy / fixed"。具体:
  - 公共节点(签名在两侧都出现)→ 无差分
  - `buggy` 序列有、`fixed` 序列无 → `added_in_buggy`(规则该匹配的 bug 模式!)
  - `fixed` 序列有、`buggy` 序列无 → `removed_in_fixed`(修复引入的 guard/替换)
  - 区间段内位置错配 → `changed`
- 输出:每方法一个 `MethodASTDelta`(见上)

**复用 `graph.priority`**(`graph.py:60`):多方法/多 hunk 差分时排序哪个最相关,公式照搬。

**为什么不建 CFG**:`ts_cfg.CFGBuilder`(`experimental/ts_cfg.py:78`)能建控制流图,但 Semgrep pattern 是**语法树**匹配,AST 节点级差分直接对口。CFG 仅在控制流语义需要时(如"漏检 guard 条件导致路径缺陷"类 bug)作可选增强,默认不上。

**测试**:`tests/test_rules_ast_diff.py`:
- 构造几对 buggy/fixed 方法片段(如 Lang-1 的 `createNumber` hex 处理),断言 `added_in_buggy` 含预期节点
- 用 `RuleRefiner/examples/tainted-sql-string.java` 的 test1(buggy)vs ok1(fixed)做冒烟

#### 1.4 fix-delta 摘要组装
**落地**:`src/code_watch/rules/delta.py` 的 `build_fix_delta(snippets, ast_diffs) -> FixDelta`。
- 把 1.2 的 `RelevantSnippets` + 1.3 的 `MethodASTDelta` 列表组装成 `FixDelta`
- 持久化:`output/fixdelta-<project>-<bug>.json`,供模块 2 消费(可缓存,重试规则生成时不必重跑 agent + diff)

---

### 模块 2: 规则生成

**目的**:从 `FixDelta` + 规则 schema,让 LLM 写出一条 Semgrep YAML 规则。

**输入**:`FixDelta`(buggy/fixed 片段 + AST 节点差分)+ `BugAnalysis`(root_cause + affected_files)
**输出**:`Rule`

#### 2.1 生成 prompt
**落地**:`src/code_watch/rules/prompts.py`

- `GEN_SYSTEM_PROMPT`:身份 = "Java 静态分析与 Semgrep 规则工程专家"
- `build_generation_prompt(fix_delta, analysis)`:喂入
  - `root_cause`(命题逻辑句,告诉 LLM 要检测什么)
  - `affected_files`(规则应命中的精确 file:line,作 ground-truth 锚点)
  - 每个 `MethodPair`:`buggy_source` + `fixed_source`(对照看)
  - 每个 `MethodASTDelta`:`added_in_buggy`(规则该匹配的)+ `removed_in_fixed`(修复手段,规则该避开)
  - **Semgrep schema cheatsheet**:附录 A 的精简版(句法模式 + 污点模式的关键操作符表,Java 实例)
- **输出契约**(沿用 RuleRefiner `semgrep_prompt.py:4-32`):
  ```
  <FINAL_ANSWER>
  ```yaml
  rules:
  - id: ...
    languages: [java]
    ...
  ```
  </FINAL_ANSWER>
  ```
- **设计要点**:prompt 显式说"规则要在 buggy 命中、在 fixed 静默",把 oracle 语义写进生成目标;给 `added_in_buggy` 节点作"该匹配什么"的直接提示,`removed_in_fixed` 作"该避开什么"的提示。

#### 2.2 生成器
**落地**:`src/code_watch/rules/generator.py` 的 `generate_rule(fix_delta, analysis, config) -> Rule`

- 调 `_llm(config).invoke(gen_prompt)` 拿文本(或 `with_structured_output`,但 Semgrep YAML 用结构化输出易丢格式,优先走文本 + postprocess)
- **postprocess**:移植 `RuleRefiner/semgrep_prompt.py:387` 的 `postprocess`(`rules/postprocess.py`),正则抽 `<FINAL_ANSWER>` 里的 fenced yaml 块,strip ```yaml 围栏 → `Rule.yaml`
- **schema 校验**:`ruamel.yaml` 解析 `Rule.yaml` 确认是合法 `rules: [...]`;调 `semgrep --validate --config <tmpfile> -q --json`(移植 `RuleRefiner/semgrep.py:122` 的 `semgrep_validate_in_tempdir`)确认 semgrep 接受
- **失败处理(可选,2.3)**:校验失败 → 重试一次(把错误信息回灌 prompt),最多 k 次

#### 2.3 语法修复循环(可选,后置)
- 移植 `RuleRefiner/semgrep_syntax.py:96` 的 `do_fix`,但把硬编码的 `doubao.chat2` 换成注入的 `LLMClient`。复用 `semgrep --validate` 的错误信息 + cheatsheet 修复。
- **默认关闭**,模块 2 跑通后再加,避免初期复杂度。

#### 2.4 持久化
- `output/rules-<project>-<bug>.json`:单规则 + metadata
- `output/rules-batch.jsonl`:批量评测用,每行一条 `Rule` + 生成参数

#### 2.5 测试
`tests/test_rules_generator.py`:
- 快速(无 LLM):`build_generation_prompt` 构造正确性(断言含 `root_cause`/`added_in_buggy`/`fixed_source`);`postprocess` 解析(喂固定 LLM 输出文本,断言抽出正确 YAML)
- `Rule` schema 校验(`ruamel.yaml` 解析合法)
- `@pytest.mark.slow`:真实 Lang-1 跑一次生成,断言 `semgrep --validate` 通过

---

### 模块 3: 规则测试(oracle)

**目的**:验证规则在 buggy 树命中 `affected_files`、在 fixed 树静默。

**输入**:`Rule` + buggy_workdir + fixed_workdir + `affected_files`(来自 `BugAnalysis`)
**输出**:`RuleEvaluation`(`rules/schema.py`):
```python
class RuleEvaluation(BaseModel):
    rule_id: str
    bug_id: str
    syntax_ok: bool
    fired_on_buggy: list[str]      # "file:line" 列表
    fired_on_fixed: list[str]
    expected: list[str]            # affected_files
    precision: float               # 命中中落在 expected 的比例
    recall: float                  # expected 被命中的比例
    status: str                    # "PASS" | "FP" | "FN" | "SYNTAX_ERROR"
```

#### 3.1 semgrep 扫描(移植 + 简化)
**复用**:`RuleRefiner/semgrep.py` 的子进程封装,但**只用 `scan`,不用 `test`**(因为 Defects4J 测试文件无 `#ruleid:`/`#ok:` marker)。
- 移植 `semgrep_scan_in_tempdir`(`RuleRefiner/semgrep.py:62`)到 `rules/semgrep_runner.py`,改成扫描真实 workdir 而非 tempdir:`semgrep scan --json --config <rule.yaml> <workdir>`
- 输出解析:从 `semgrep scan --json` 的 `results` 取每命中的 `{check_id, path, start: {line}}`,汇总成 `fired_on_*` 列表

#### 3.2 oracle 三态
- `syntax_ok`:`semgrep --validate` 通过
- `fired_on_buggy`:扫 buggy 树的命中行
- `fired_on_fixed`:扫 fixed 树的命中行(理想为空)
- `status`:
  - `PASS` = `fired_on_buggy ∩ expected ≠ ∅` ∧ `fired_on_fixed == []`
  - `FP` = `fired_on_fixed ≠ []`(fixed 还有命中,规则没抓住修复点)
  - `FN` = `fired_on_buggy ∩ expected == ∅`(buggy 没命中,规则没抓住 bug)
  - `SYNTAX_ERROR` = `not syntax_ok`

#### 3.3 行级 precision/recall
- `expected_lines` = `affected_files` 解析出的 `(file, line_set)`(`file:line-range` → 行集合)
- `reported_lines` = `fired_on_buggy` 的 `(file, line_set)`
- `recall = |reported ∩ expected| / |expected|`
- `precision = |reported ∩ expected| / |reported|`(规则命中有多少落在真实 bug 行)

#### 3.4 评估器
**落地**:`src/code_watch/rules/evaluator.py` 的 `evaluate_rule(rule, buggy_workdir, fixed_workdir, expected) -> RuleEvaluation`
- 复用模块 1.1 的 checkout(不重复 checkout)
- 复用模块 3.1 的 runner

#### 3.5 测试
`tests/test_rules_evaluator.py`:
- 快速:用 `fixtures/sample-java` 复制 buggy/fixed 对,手写一条能命中 buggy 不命中 fixed 的规则,断言 `status==PASS`
- `@pytest.mark.slow`:真实 Lang-1 端到端(模块1→2→3),断言 `status` 非 `SYNTAX_ERROR`

---

### 模块 4: Defects4J 批量评测

**目的**:在 Defects4J 测试集上跑全流程,产出聚合指标。

#### 4.1 批量 runner
**落地**:`src/code_watch/rules/batch.py` 的 `run_batch(config, project_bug_pairs) -> BatchReport`
- 串起:checkout(1.1)→ prep agent(1.2)→ AST diff(1.3)→ generate(2.2)→ evaluate(3.4)
- **并发**:`map_reduce`(移植 `RuleRefiner/para.py:14` 到 `rules/parallel.py`,线程池 + tqdm)。但 D4J checkout 重 IO,并发度限 2-4,避免磁盘抖动
- **缓存**:每个 `(project, bug_id)` 的 checkout + FixDelta 落盘,规则生成重试不重跑前置

#### 4.2 聚合指标
**落地**:`src/code_watch/rules/metrics.py`
- 移植 `RuleRefiner/scripts/semgrep_view_results.py:8` 的 `passk` 思路(多候选采样时,任一 attempt PASS 即算通过)
- 加 macro/micro precision/recall,按 project 分组
- 输出 `BatchReport { total, passed, by_project: {...} }`

#### 4.3 CLI
**落地**:`src/code_watch/rules/run_demo.py`,Typer 子应用
- `pyproject.toml` 增 `[project.scripts] code-watch-rules = "code_watch.rules.run_demo:app"`
- 命令:
  - `generate --project Lang --bug 1` — 跑到模块 2,产出 `Rule`
  - `test --project Lang --bug 1` — 跑到模块 3,产出 `RuleEvaluation`
  - `evaluate --projects Lang,Chart --bugs 1-5` — 批量评测,产出报告
- 沿用 `analysis/run_demo.py` 的 Rich Panel 输出风格

#### 4.4 报告
- `output/rules-report.md`:按 project/bug 列 `status` + precision/recall + 规则 id
- `output/rules-report.csv`:同内容,便于后续统计

#### 4.5 样板跑
- 先 Lang-1..5(已有 Lang-1 分析样本)端到端跑通,确认管线稳定
- 再扩 Chart/Cli 各 5 个
- 稳定后再上全量(17 项目)

---

## 4. 砍掉的 RuleRefiner 组件(及理由)

| 砍掉件 | 原位置 | 理由 |
|---|---|---|
| `semgrep2nx.Semgrep2NX`/`align`/`is_true`/`simplfiy` | `semgrep2nx.py:286/163/334/214` | 需先有规则跑 `--matching-explanations`,创造场景无规则 |
| `lcp_locate`/`spfl` | `semgrep_locate.py:64/11` | 规则故障定位,创造不需要 |
| `graph.find_all_paths`/`positive_path`/`negative_path` | `graph.py:10/20/26` | 依赖谓词图路径,无谓词图则无用 |
| 三段验证 `syntax_check`/`regression`/`verify_fix` | `semgrep_verify.py:4/11/26` | 简化为 scan buggy + scan fixed(模块3) |
| `semgrep_syntax.do_fix` | `semgrep_syntax.py:96` | 可选后置(模块 2.3),非核心 |
| `Example` 数据类 | `testcase.py:1` | 暂不需要(评测用 `RuleEvaluation`,非 Example) |
| `para.map_reduce` | `para.py:14` | 仅批量评测(模块4)按需引入 |
| `pass@k` | `scripts/semgrep_view_results.py:8` | 仅多候选采样时引入 |
| 各 LLM backend(`deepseek.py` 等) | 根目录 | codeWatch 用 `ChatOpenAI` 统一,不移植异构 backend |

**保留复用**:
- `ts_cfg.TSHelper.gen_ast`/`find_methods`(`experimental/ts_cfg.py:21/12`)— 模块 1.3
- `graph.diff`/`priority`(`graph.py:29/60`)的**算法骨架**(改造)— 模块 1.3
- `semgrep_scan_in_tempdir`(`semgrep.py:62`)— 模块 3.1
- `semgrep_validate_in_tempdir`(`semgrep.py:122`)— 模块 2.2
- `postprocess`(`semgrep_prompt.py:387`)— 模块 2.2
- `para.map_reduce`(`para.py:14`)— 模块 4.1
- `passk`(`scripts/semgrep_view_results.py:8`)— 模块 4.2

---

## 5. 里程碑与依赖顺序

```
0(基建) → 1(fix-delta 理解) → 2(规则生成) → 3(规则测试) → 4(批量评测)
```

**最小可演示路径**:`0 → 1 → 2 → 3`,在 Lang-1 上跑通一条规则的创造+测试,作为里程碑 1。然后扩 4.5(Lang-1..5)作里程碑 2。

**依赖**:
- 模块 1.3 依赖 0.2(networkx)+ 1.2(agent 输出)
- 模块 2 依赖 0.2(semgrep)+ 1(FixDelta)
- 模块 3 依赖 0.2(semgrep)+ 1.1(checkout 复用)
- 模块 4 依赖 1+2+3 全部就绪

---

## 6. 风险点

1. **semgrep 包安装** — 重依赖,可能与 `tree-sitter-java` 版本冲突。模块 0.2 先验证 `uv add semgrep && uv sync` 可装。最大前置风险。
2. **Defects4J 测试缺 `#ruleid:` 标记** — 已消解:模块 3 用 `semgrep scan` + `affected_files` 行集合作 oracle,不走 `semgrep test` + marker 路径(见附录 A.5)。
3. **Semgrep Java 规则从零生成的质量** — 比 refinement 难。模块 2.1 prompt 给足 `added_in_buggy`/`removed_in_fixed` + schema cheatsheet;必要时加 few-shot Java 缺陷→规则范例。
4. **D4J checkout 成本** — 每评测 buggy+fixed 两份(30-90s/份)。模块 4.1 缓存 workdir,跨生成重试复用。
5. **rule-gen-prep agent 选片段质量** — agent 可能漏选或选错方法。模块 1.2 prompt 要给 `affected_files`/`modified_classes` 作硬锚点;`patch_src` 作辅助线索缩小范围。

---

## 7. 待定决策点

| ID | 决策 | 选项 | 当前倾向 |
|---|---|---|---|
| D5 | 首批 bug 范围 | Lang-1..5 / Lang+Chart 各5 | Lang-1..5 |
| D6 | 模块 2.3 语法修复循环 | 现在做 / 后置 | 后置 |
| D7 | 多候选采样(pass@k) | 现在做 / 后置 | 后置 |

---

# 附录 A: Semgrep YAML 规则 Schema 详解

> 依据:`RuleRefiner/examples/tainted-sql-string.yaml`、`RuleRefiner/dataset/items/{saxparserfactory,xmlinputfactory,tainted-sql-string}/rule.txt`、`RuleRefiner/example.json`。模块 2 的生成 prompt 把本附录精简版作 cheatsheet 喂给 LLM。

## A.1 顶层结构

```yaml
rules:                          # 顶层必须是 list(一个文件可含多条规则)
- id: <unique-rule-id>          # 必填,全局唯一,小写连字符
  languages: [java]              # 必填,codeWatch 固定 java
  message: <string>              # 必填,匹配时报告的文本(支持多行 | 或 >-)
  severity: ERROR|WARNING|INFO  # 必填
  # —— 以下二选一:句法模式 或 污点模式 ——
  patterns: [...]               # 句法模式:AND 语义,列表内全部满足
  # 或 pattern-either / pattern / pattern-regex / mode: taint
```

## A.2 两种匹配模式

### 模式 1: 句法模式(Pattern Mode) — 基于语法树匹配

顶层用 `pattern` / `patterns` / `pattern-either` / `pattern-regex` 之一。

| 字段 | 语义 | Java 示例 |
|---|---|---|
| `pattern` | 单个模式,匹配即报告 | `pattern: SAXParserFactory.newInstance()` |
| `patterns` | 列表,**AND**:全部子模式在同一作用域同时满足 | 见 saxparserfactory 规则 |
| `pattern-either` | 列表,**OR**:任一子模式满足 | 见 xmlinputfactory 规则 |
| `pattern-regex` | 纯正则(不走 AST),整文件扫描 | `pattern-regex: <a.*href\s*=...` |

`patterns:` 列表内的子操作符(AND 语义叠加):

| 子操作符 | 作用 |
|---|---|
| `pattern` | 必须匹配此模式 |
| `pattern-inside` | 仅在此上下文块内匹配 |
| `pattern-not-inside` | 排除在此上下文内的匹配(精化 FN → 减 FP) |
| `pattern-not` | 排除此模式匹配 |
| `pattern-not-regex` | 排除正则匹配 |
| `metavariable-regex` | 用正则约束某 metavariable 的文本 |
| `metavariable-comparison` | 用 Python 表达式约束 metavariable(数值比较) |
| `metavariable-pattern` | 用子模式匹配 metavariable |
| `focus-metavariable: $X` | 只报告 $X 对应的代码位置(而非整条匹配) |
| `metavariable-analysis` | 对 metavariable 做数据流分析 |

**实例**(`saxparserfactory/rule.txt` 精简版,纯句法模式):
```yaml
rules:
- id: owasp.java.xxe.SAXParserFactory
  languages: [java]
  severity: ERROR
  message: SAXParserFactory 未禁用实体处理
  patterns:
  - pattern-either:                 # OR:任一 newInstance 写法
    - pattern: SAXParserFactory $SPF = SAXParserFactory.newInstance();
    - pattern: SAXParser $SAXPARSER = SAXParserFactory.newInstance().newSAXParser();
  - pattern-not-inside:             # AND + 排除:已调用 setFeature 的不算缺陷
      $RETURNTYPE $METHOD(...) {
        ...
        $XXX.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        ...
      }
```

### 模式 2: 污点模式(Taint Mode) — 基于数据流追踪

顶层加 `mode: taint`,用 `pattern-sources` / `pattern-sinks` / `pattern-sanitizers`。适合 SQL 注入、命令注入、XSS 等"用户输入流到危险终点"类缺陷。

| 字段 | 语义 |
|---|---|
| `mode: taint` | 启用污点追踪 |
| `pattern-sources` | 污点源列表(用户输入入口) |
| `pattern-sinks` | 污点汇聚点列表(危险操作) |
| `pattern-sanitizers` | 净化器列表(经过则不算污点) |
| `pattern-propagators` | 跨变量传播污点(`from → to`) |
| `options` | 污点配置:`taint_assume_safe_numbers`/`taint_assume_safe_booleans` 等 |

每个 source/sink/sanitizer可以是裸 `pattern`,也可是 `{patterns: [...], focus-metavariable: $X}` 复合块。

**实例**(`examples/tainted-sql-string.yaml` 精简版,污点模式):
```yaml
rules:
- id: tainted-sql-string
  languages: [java]
  severity: ERROR
  message: 用户输入流入手工拼接的 SQL 字符串,存在 SQL 注入风险
  options:
    taint_assume_safe_numbers: true
    taint_assume_safe_booleans: true
  mode: taint
  pattern-sources:                # 源:Spring 注解标注的用户输入
  - patterns:
    - pattern-either:
      - pattern-inside: |
          $METHODNAME(..., @$REQ(...) $TYPE $SOURCE,...) { ... }
    - metavariable-regex:
        metavariable: $REQ
        regex: (RequestBody|PathVariable|RequestParam|RequestHeader|CookieValue)
    - metavariable-regex:           # 排除基本类型(非字符串不算污点)
        metavariable: $TYPE
        regex: ^(?!(Integer|Long|int|long|...))
    - focus-metavariable: $SOURCE   # 只把 $SOURCE 标为污点起点
  pattern-sinks:                   # 汇:SQL 字符串拼接
  - patterns:
    - pattern-either:
      - pattern: |
          "$SQLSTR" + ...
      - pattern: |
          "$SQLSTR".concat(...)
      - pattern: String.format("$SQLSTR", ...)
    - pattern-not-inside: System.out.println(...)   # 日志里的不算
    - metavariable-regex:           # 只对 SQL 动词触发
        metavariable: $SQLSTR
        regex: (?i)(select|delete|insert|create|update|alter|drop)\b
```

## A.3 metavariable 与通配符

| 记号 | 含义 |
|---|---|
| `$NAME` | metavariable,大写,匹配任意 AST 节点(表达式/语句/类型/字面量),可被后续引用 |
| `$NAME(...)` | 匹配函数调用,`...` 表示任意参数 |
| `...` | 匹配任意代码(0 到多语句/参数/字段) |
| `_$FIELD` | 字段访问简写 |
| `$X` 在 `metavariable-regex`/`metavariable-comparison`/`focus-metavariable` | 跨模式约束同一 metavariable |

## A.4 可选字段(生成时通常省略)

| 字段 | 用途 | codeWatch 建议 |
|---|---|---|
| `fix` / `fix-regex` | 自动修复 | 省略(D4J 评测只看检测,不看修复) |
| `metadata` | cwe/owasp/references/category 等 | 省略或仅填 `cwe`(若 BugAnalysis 能推出) |
| `paths` | include/exclude glob | 省略 |
| `options` | 仅污点模式需要 | 污点规则才填 |

RuleRefiner 的 `scripts/dataset_clean.py:8` 在评测前会 strip 掉 `metadata`/`fix`/`fix-regex`/`paths`/`min-version` 减噪 — codeWatch 生成阶段可直接省略这些字段。

## A.5 测试约定(关键:codeWatch 如何绕过 marker 问题)

RuleRefiner 测试文件用行内标记声明期望:
```java
String sql = "SELECT * FROM t WHERE name = " + name + ";";  // ruleid: tainted-sql-string   ← 应被命中
String sql = "SELECT * FROM t WHERE name = 'everyone';";    // ok: tainted-sql-string        ← 不应被命中
```
`semgrep_output_parser.analysis_semgrep_output`(`RuleRefiner/semgrep_output_parser.py:6`)靠这些标记算 `expected_lines`,再与 `reported_lines` 求差集得 fp/fn。

**Defects4J 测试文件没有这些标记**,所以 codeWatch 不走 `semgrep test` + marker 路径,改走:

1. **`semgrep scan --json --config rule.yaml <tree>`** 直接扫描 buggy 树 / fixed 树(无需 marker)
2. 从 `BugAnalysis.affected_files`(已是 `file:line-range` 精确位置)取 `expected_lines`
3. oracle:
   - buggy 树上 `reported_lines ∩ expected_lines / expected_lines` = **recall**
   - buggy 树上 `reported_lines − expected_lines` = **FP**(precision 的分母)
   - fixed 树上 `reported_lines` 应为空(任何命中 = 漏报修复点的 FP)

模块 2.2/3.1 都基于 `semgrep scan` 而非 `semgrep test`,**消解了风险点 #2**。

## A.6 规则 schema 的 codeWatch 落地(`rules/schema.py` 的 `Rule` 模型)

见模块 0.4。`yaml` 字段就是上面 A.1-A.4 描述的完整 `rules: [...]` 文本。生成器产出此字符串,验证器用 `semgrep --validate` + `semgrep scan` 检查。

## A.7 生成 prompt 的输出契约(模块 2 复用 RuleRefiner)

LLM 输出格式(RuleRefiner `semgrep_prompt.py` 既定,codeWatch 直接沿用):
```
<FINAL_ANSWER>
```yaml
rules:
- id: d4j-Lang-1-r1
  languages: [java]
  severity: ERROR
  message: ...
  patterns:
  - ...
```
</FINAL_ANSWER>
```
`rules/postprocess.py`(模块 2.2 移植)用正则抽 `FINAL_ANSWER` 里的 fenced yaml 块,strip ```yaml 围栏,得 `Rule.yaml`。

---

# 附录 B: 目录落地预览(执行后)

```
codeWatch/
├── docs/
│   └── rules-integration-plan.md          # 本文档
├── src/code_watch/
│   ├── llm.py                              # 0.1 共享 LLM 客户端
│   ├── analysis/
│   │   └── schema.py                       # 0.3 增 patch_src/modified_classes
│   └── rules/                              # 新增子包
│       ├── __init__.py
│       ├── schema.py                       # 0.4 Rule / 1.2 RelevantSnippets / 3 RuleEvaluation
│       ├── delta.py                        # 1.4 FixDelta 组装
│       ├── checkout.py                     # 1.1 checkout_both
│       ├── prep_agent.py                   # 1.2 rule-gen-prep agent
│       ├── ast_diff.py                    # 1.3 改造 graph.diff 做 AST 节点差分
│       ├── semgrep_runner.py               # 2.2/3.1 semgrep scan/validate 子进程封装
│       ├── postprocess.py                  # 2.2 LLM 输出后处理(移植)
│       ├── prompts.py                     # 2.1 GEN_SYSTEM_PROMPT + build_generation_prompt
│       ├── generator.py                    # 2.2 generate_rule
│       ├── evaluator.py                    # 3.4 evaluate_rule
│       ├── parallel.py                     # 4.1 map_reduce(移植)
│       ├── metrics.py                      # 4.2 聚合指标 + passk(移植)
│       ├── batch.py                        # 4.1 run_batch
│       └── run_demo.py                     # 4.3 Typer CLI
├── tests/
│   ├── test_rules_prep_agent.py            # 1.2
│   ├── test_rules_ast_diff.py             # 1.3
│   ├── test_rules_generator.py            # 2.5
│   └── test_rules_evaluator.py            # 3.5
├── fixtures/
│   └── defect-analyses/                    # 脱敏 BugAnalysis+meta JSON(测试夹具)
└── output/
    ├── analysis-<project>-<bug>.json       # 已有,模块0.3后增字段
    ├── fixdelta-<project>-<bug>.json        # 1.4 缓存
    ├── rules-<project>-<bug>.json           # 2.4
    ├── rules-batch.jsonl                    # 4.1
    └── rules-report.md                      # 4.4
```
