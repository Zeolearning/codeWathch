# rules 流水线运行流程详解

> 本文档描述 `src/code_watch/rules/` 的规则生成流水线如何从 Defects4J 缺陷分析一步步生成并验证 Semgrep 规则。核心编排在 `src/code_watch/rules/pipeline.py` 的 `run_rule_pipeline`。

---

## 1. 总览

```
CLI: code-watch-rules run -p <Project> -b <bug>
  ├─ config = CodeWatchConfig.from_env(); config.apply_env()
  ├─ load_analysis_with_patch(project, bug)      # 阶段 0:读取 analysis JSON
  └─ run_rule_pipeline(analysis, config)         # 阶段 1-4:核心流水线
       ├─ select_relevant_snippets(...)          #  → (snippets, parent, buggy_dir, fixed_dir)
       ├─ build_fix_delta(snippets)              #  → FixDelta
       ├─ generate_rule(delta, analysis, config) #  → Rule
       └─ evaluate_rule(rule, buggy_dir, fixed_dir, expected)  #  → RuleEvaluation
```

产物落盘结构（`output/` 先按业务分目录，业务内再按项目分）：

```
output/
  analysis/                          # 业务：缺陷分析
    analysis-<proj>-<bug>.json
  rules/                             # 业务：规则生成
    d4j-<proj>-<bug>/                # 项目粒度
      d4j-<proj>-<bug>-snippets.json
      d4j-<proj>-<bug>-fixdelta.json
      d4j-<proj>-<bug>-rule.json
      d4j-<proj>-<bug>-eval.json
      d4j-<proj>-<bug>-gen-rule.yaml        # agent 提交的原始规则 YAML（每轮覆盖）
  reports/                           # 业务：批量报告
    rules-report.md
    rules-report.csv
```

内层前缀 `output/rules/d4j-<proj>-<bug>/d4j-<proj>-<bug>` 拼接各产物后缀。

---

## 2. 阶段 0:加载分析 `load_analysis_with_patch`(`pipeline.py:23`)

输入：`(project, bug_id)`。输出：内存中的 `BugAnalysis` 对象。

1. **定位文件**：`output/analysis/analysis-<project>-<bug>.json`(`pipeline.py:26-27`)。
2. **判断是否需要补 patch**（`pipeline.py:36`）：
   ```
   need_patch = analysis is None          # 文件不存在
             or refresh_patch             # CLI 参数 --refresh-patch
             or not analysis.patch_src    # 旧版本产物缺 patch_src
   ```
3. **若 need_patch**（`pipeline.py:40-56`）：
   - `load_defect_metadata(project, bug)` → `DefectMetadata`（src_dir、modified_classes、fixed_commit）
   - `checkout_defect(project, bug, version="fixed")` → 调 perl 脚本拉修复版
   - `compute_clean_patch(...)` → 重算 developer patch
   - analysis 为 None → **抛 `FileNotFoundError`**，提示先跑 `code-watch-analysis run`（`pipeline.py:50`）
   - 注入 `patch_src` + `modified_classes` 并回写 JSON（`pipeline.py:54-56`）
4. 返回 `BugAnalysis`。

**只用到的字段**：`bug_id`、`patch_src`、`modified_classes`。

---

## 3. 阶段 1:Prep Agent 选方法 `select_relevant_snippets`(`prep_agent.py:34`)

全流水线最重的一步（一次 agent 会话 + 一次结构化提取）。

### 3.1 双树 checkout（`prep_agent.py:55` → `checkout.py:9`）

- 新建临时目录 `rulegen-<project>-<bug>-XXXX` 作 `parent`（`checkout.py:29`）
- 布局：
  ```
  <parent>/
  ├── buggy/     # checkout_defect(version="buggy")  → d4j-checkout -v 1b
  └── fixed/     # checkout_defect(version="fixed")  → d4j-checkout -v 1f
  ```
- 缓存判定：`refresh=True` 或目录下无 `.git` 时才重新拉（`checkout.py:36-39`）

### 3.2 建 agent（`prep_agent.py:26-31`）

- `RepoContext(repo_root=parent)`：路径 jail 覆盖 buggy/ + fixed/ 两棵树
- `create_agent(model, tools=build_tools(ctx), system_prompt=PREP_SYSTEM_PROMPT)`

### 3.3 流式执行（`prep_agent.py:80`）

- 喂 `build_prep_prompt(analysis, buggy_dir, fixed_dir)`（`prompts.py:60`），其中包含 `root_cause`、`affected_files`、`modified_classes`、`patch_src`（作为提示线索）
- `recursion_limit=50`；边跑边记录工具调用进 `tool_trace`、最后文本进 `last_text`

### 3.4 结构化提取（`prep_agent.py:118`）

- 用 `tool_trace + last_text` 拼第二个 prompt
- `with_structured_output(RelevantSnippets, method="json_mode")` 强制 JSON
- 结果含 1-5 个方法对（buggy_source ≠ fixed_source 才保留）
- 覆盖 `final.bug_id = analysis.bug_id`

---

## 4. 阶段 2:结构差异 `build_fix_delta`(`delta.py:10`)

纯本地，无 LLM。

1. 遍历 snippet，`buggy_source == fixed_source` 的直接跳过（`delta.py:19`）
2. 其余调 `diff_method_pair`（`ast_diff.py:84`）：
   - tree-sitter 把方法源码包进哑类解析出 `block` 节点（`ast_diff.py:15-52`）
   - 提取语句序列签名（`ast_diff.py:63`）
   - `difflib.SequenceMatcher` 对齐（`ast_diff.py:114`）
   - 产出三类 delta：

| change | 语义 | 规则约束 |
|---|---|---|
| `added_in_buggy` | buggy 有、fixed 无 = 缺陷模式 | 规则**必须**匹配 |
| `added_in_fixed` | fixed 有、buggy 无 = 修复引入 | 规则**不应**匹配 |
| `changed` | 同位置文本不同 | 提示改写 |

3. 聚合为 `FixDelta`（bug_id + method_deltas）

---

## 5. 阶段 3:生成规则 `generate_rule`(`generator.py:35`)

1. `build_generation_prompt(delta, analysis, out_path)`（`prompts.py`）：拼入 `root_cause`、`affected_files`、方法源码、结构 delta、Semgrep schema 速查表、`submit_rule` 输出契约
2. 单工具 agent（`create_agent` + `submit_rule`，`generator.py`）：流式执行，agent 通过 `submit_rule(content)` 提交规则 YAML。**校验钩子**：`submit_rule` 工具内置 `validator`（即 `semgrep --validate`），每次提交自动校验——通过则工具返回 `accepted`，失败则把 semgrep 报错作为 REJECTED 结果回传给 agent，agent 在**同一个对话轮里**修复后重新提交（自愈，无需 pipeline 另起修复轮）；`recursion_limit=40` 给重提留预算
3. 工具把内容写到代码写死的固定路径（`{out_prefix}-gen-rule.yaml`）；未提交 → 抛 `RuleGenError`（携带 agent 输出供回灌）
4. 读回 YAML 文本；复用钩子的判定（`validation_state`，不重复跑 semgrep）
5. `_extract_rule_fields` 解析 message/severity/mode（`generator.py`）
6. 组装 `Rule`；验证失败信息存入 `metadata.validation_msg`

---

## 6. 阶段 4:差分评估 `evaluate_rule`(`evaluator.py`)

差分 oracle（两条检查）：规则必须命中 buggy 树上的预期行、且对**本 bug 的 fixed 仓库整树**静默（`scan_tree` 扫的是完整 fixed checkout，不是只扫修复片段）。

1. `validate_rule` 语法检查；失败直接返回 `status="SYNTAX_ERROR"`（msg 存 `validation_msg`）
2. `scan_tree` 两次：`semgrep scan --json` 分别扫 buggy_dir、fixed_dir（超时 300s）；scan 子进程失败（退出码非 0 / JSON 不可解析）抛 `RuntimeError`，由 batch 层按 bug 隔离记录，不再静默计为 FN
3. 命中转 `{file: set(lines)}`，与 `expected`（`_expected_locations`：开发者补丁真值行优先，affected_files 兜底）求交集
4. 算 precision / recall：

   ```
   recall    = |hit ∩ expected| / |expected|
   precision = |hit ∩ expected| / |reported|
   ```

5. 状态判定优先级：

   ```
   SYNTAX_ERROR  >  FP (fixed 仓库有命中)  >  FN (漏掉 bug)  >  PASS
   ```

---

## 7. 运行时消耗

| 类别 | 次数 |
|---|---|
| `d4j-checkout` 子进程 | 2（buggy + fixed） |
| `semgrep --validate` 子进程 | 每次提交 1 次（校验钩子）+ 评估时 1 次；agent 自愈可多次 |
| `semgrep scan` 子进程 | 2（buggy + fixed） |
| LLM 交互 | ≥3（prep agent 会话 + 结构化提取 + 规则生成）；同轮内 submit 被拒重提不计新会话 |

## 8. 关键观察

- **中间产物每步落盘**，但流水线内不读回（重跑即全量重算）。
- **`expected` = `affected_files`**，是 PASS/FN 判定的 ground truth。
- **两棵树复用**：prep 阶段 checkout 的目录传给生成、评估复用，不重复 checkout。
- **阶段边界在 CLI 层**：`run_rule_pipeline` 单函数串起全部 4 个阶段，分析（贵、一次）与规则生成（可重试）分离。
