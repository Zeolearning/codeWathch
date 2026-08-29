# Code Watch

Java 漏洞根因分析 + Semgrep 规则生成 Agent。基于 LangChain + LangGraph + LangSmith，针对 [Vul4J](https://github.com/tuhh-softsec/Vul4J) 漏洞数据集（129 个真实 Java 漏洞，79 条带 PoV）：checkout 出漏洞/修复双树 → ReAct agent 用只读工具探索代码 → 用命题逻辑（AND/OR/NOT）抽取结构化根因 → 确定性 AST 差分 → agent 生成 Semgrep 规则 → vul/fix 双树差分评估（oracle）。

每个 case 共 2 个 agent 会话（旧版 3 个已合并）：

1. **分析 agent**（双树）：探索 `vul/` + `fix/`，产出根因 JSON（root_cause / affected_files / patch_src / reasoning_trace）。
2. **生成 agent**：基于确定性 FixDelta（patch diff → tree-sitter 方法对，无 agent 参与）生成规则，`submit_rule` 工具内嵌 `semgrep --validate` 同轮自愈，评估反馈驱动多轮修复。

## 安装

```bash
uv sync
git clone --depth 1 https://github.com/tuhh-softsec/Vul4J.git vul4j/
uv sync --project vul4j
uv run --project vul4j vul4j init   # 首次初始化 ~/vul4j_data/
```

初始化后编辑 `~/vul4j_data/vul4j.ini`：`VUL4J_GIT = <本仓库绝对路径>/vul4j`（默认值无效）。Vul4J 仓库已 gitignore，不提交。

## 配置

```bash
cp .env.example .env
# 编辑 .env: OPENAI_API_KEY / OPENAI_BASE_URL / OPENAI_MODEL / LANGSMITH_*
```

## 使用

单 CLI `code-watch`（`uv run code-watch <command>`）。

`--cases` 的格式：`pov`（79 条 PoV 组）| `sb`（50 条 SpotBugs-only）| `all` | 逗号分隔的 id / 数字 / 数字范围 / `N-S`，如 `"VUL4J-1,4-10,80-S"`。

---

### `code-watch run` — 单 case 全流程

```bash
uv run code-watch run --case VUL4J-10
```

流程：分析（缓存命中则跳过）→ 确定性 FixDelta → 生成 → 差分评估。

| 选项 | 默认 | 说明 |
|------|------|------|
| `-c, --case` | `VUL4J-10` | Vul4J case id |
| `--refresh-analysis` | 关 | 忽略已有分析 JSON，重跑分析 agent |
| `--refresh-checkout` | 关 | 强制重新 vul4j checkout |
| `--max-attempts` | `3` | 生成→评估→修复循环最大轮数 |

### `code-watch batch` — 批量 + 汇总报告

```bash
uv run code-watch batch --cases pov --max-attempts 3
```

| 选项 | 默认 | 说明 |
|------|------|------|
| `--cases` | `pov` | case 说明（见上） |
| `--split` / `--role` | — / `train` | 从 split JSON 读 case 列表（覆盖 `--cases`），`--role train\|test` |
| `--refresh-analysis` / `--refresh-checkout` | 关 | 同 `run` |
| `--max-attempts` | `3` | 修复循环最大轮数 |
| `--skip-existing` / `--no-skip-existing` | skip-existing | 已有 `-eval.json` 的 case 直接读回（断点续跑） |
| `--retry-failed` | 关 | 上次 SYNTAX_ERROR 的 case 重跑 |
| `--work-root` | (持久缓存) | 临时 checkout 根目录（见下） |
| `--keep-work` | 关 | 保留临时 checkout 目录 |
| `--report` / `--csv` | `output/reports/rules-report.{md,csv}` | 报告路径 |

报告含：total / passed / pass@1 / macro·micro precision·recall / 按项目分组 / 按 CWE 分组 / 错误列表。

### `code-watch split` — 训练/测试切分

```bash
uv run code-watch split --cases pov --ratio 0.8 --seed 42
```

CWE 分层 + 项目尽量不相交的确定性切分（默认 79 PoV → 63 train / 16 test），固化到 `splits/vul4j-pov-seed42.json`。算法：按 CWE 分组，组内整项目贪心分配（同大小项目 seed 洗牌），单项目组内随机切分；`meta.shared_projects` 记录两侧共现项目。

| 选项 | 默认 | 说明 |
|------|------|------|
| `--cases` | `pov` | 切分池 |
| `--ratio` | `0.8` | 训练侧比例 |
| `--seed` | `42` | 随机种子（可复现） |
| `--out` | `splits/vul4j-<spec>-seed<seed>.json` | 输出路径 |
| `--force` | 关 | 覆盖已存在的 split 文件 |

### `code-watch holdout` — 泛化评估

```bash
uv run code-watch holdout --split splits/vul4j-pov-seed42.json   # 推荐实验入口
uv run code-watch holdout --train pov --test sb                  # 任意组合
```

用训练阶段产出的合并规则集扫描 held-out test case 的漏洞树，三档判定（same-file / near≤10 / localized≤3 行）对齐人工补丁触碰行。

| 选项 | 默认 | 说明 |
|------|------|------|
| `--split` | — | 从 split JSON 读 train+test（覆盖 `--train/--test`） |
| `--train` / `--test` | `pov` / `sb` | 训练/测试 case 说明（规则从 `output/rules/` 加载） |
| `--tolerance` / `--near-tolerance` | `3` / `10` | localized / near 的行容差 |
| `--work-root` / `--keep-work` | — | 临时 checkout 管理 |
| `--report` / `--json` | `output/reports/holdout-report.{md,json}` | 报告路径 |

### 标准实验流程

```bash
# 1. 切分（一次）
uv run code-watch split --cases pov --ratio 0.8 --seed 42
# 2. 训练侧全流程（分析 agent → FixDelta → 规则生成/修复循环，断点续跑）
uv run code-watch batch --split splits/vul4j-pov-seed42.json --role train
# 3. 泛化评估：合并 train 规则扫 test 漏洞树
uv run code-watch holdout --split splits/vul4j-pov-seed42.json
```

---

### checkout 缓存

- 默认：所有 case 的双树缓存在 `output/checkouts/<case_id>/`（`vul/` + `fix/`），跨阶段、跨批次复用；`.git` 存在即跳过。
- 指定 `--work-root <dir>` 后改用 `<dir>/<case_id>/`，跑完即删（`--keep-work` 保留）。
- 断点续跑依赖 `output/` 下已落盘的 JSON，删 checkout 不影响。

### 产物目录

```
output/
  analysis/<VUL4J-ID>.json            根因分析 JSON
  rules/vul4j-<ID>/                   单 case 的规则流水线产物
    vul4j-<ID>-fixdelta.json            确定性方法级差分
    vul4j-<ID>-rule.json / -eval.json   最优规则与评估
    vul4j-<ID>-gen-rule.yaml            agent 提交的原始 YAML（每轮覆盖）
  checkouts/<VUL4J-ID>/vul|fix/       双树 checkout 缓存
  reports/                            批量/holdout 汇总报告
```

## 工具

Agent 可用的只读工具（定义在 `src/code_watch/tools/`）：

| 工具 | 作用 |
|------|------|
| `read_file` | 读文件内容（Java/properties/xml），支持 offset/limit |
| `glob` | 按模式找文件 |
| `grep` | 正则搜内容（默认 `*.java`），rg 不可用时回退 Python |
| `list_dir` | 列目录 |
| `java_symbols` | tree-sitter 解析单文件 AST（类/方法/字段/注解/行号） |
| `java_index` | 全仓符号索引（按 kind/annotation/name 过滤） |
| `bash` | 白名单只读 shell（git/rg/find/ls/pwd），拒绝元字符 |

## 测试

```bash
uv run pytest -q                 # 快速（不打网络）
uv run pytest -m slow -q         # 真 vul4j checkout 集成测试
```

## 结构

```
src/code_watch/
  analysis/      双树根因分析 agent (analyzer / prompts / schema / batch)
  rules/         Semgrep 规则流水线 (pipeline / delta / generator / evaluator / holdout / metrics / batch)
  dataset/       Vul4J 数据集层 (schema / vul4j: CSV 解析、checkout_pair、compute_patch、resolve_case_ids)
  tools/         只读代码探索工具 + write_file / submit_rule
  cli.py         单 CLI（run / batch / holdout）
  config.py      环境配置
  context.py     仓库路径解析与越界保护
  tracing.py     LangSmith 追踪链接
```
