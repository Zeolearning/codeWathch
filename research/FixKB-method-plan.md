# FixKB 方法方案:从修复历史蒸馏资源泄漏知识库,零 LLM 检测引擎

> 目标会议:ASE(研究论文,方法 + 实证)
> 工作名:FixKB(Compile Fixes into Checkers)
> 状态:方案 v1.0(待可行性探针)

---

## 0. 论文定位与贡献声明

**一句话**:从资源泄漏的历史修复 commit 中,由 LLM 离线蒸馏出经预言机验证的"生命周期配对事实"知识库;检测阶段由**确定性引擎**解释知识库完成定位,**全程零 LLM**。

**三个贡献**:
1. **C1 生命周期配对意图分类学**:超出 INFER ROI 的 closeable 三意图(ACQ/REL/VAL),基于 24 个真实修复的形态普查,定义五种泄漏缺陷形态(F1-F5,见 §3)。实证:75% 的真实"内存泄漏"修复不在 closeable 分类学内。
2. **C2 修复→事实的蒸馏-验证闭环**:LLM 蒸馏的事实必须通过差分预言机单元测试(vul 树命中缺陷行 / fix 树新增行静默)才入库——保证入库知识"可执行、可复现、被验证"。
3. **C3 零 LLM 检测引擎**:确定性 AST 引擎解释事实完成定位,检测吞吐、成本、可复现性全面优于逐 snippet LLM 分析(INFER ROI 范式)。

**动机实证(已完成)**:主题簇 ≠ 形态簇(9 成员值普查:8 个不同可空值,零重叠);三层工具(结构 semgrep / taint / 字段敏感 AST)对兄弟修复迁移全为 0;单修复合成检查器自覆盖 16/16 完美——**知识必须逐修复蒸馏、以库的形式组合**,这是本方法的立论。

---

## 1. 总体架构

```
┌────────────────────────────────────────────────────────────┐
│ Phase A 数据准备(无 LLM)                                   │
│   仓库挖掘 → 修复 commit 集 → vul/fix 双树物化 → 期望行提取   │
└──────────────┬─────────────────────────────────────────────┘
               ▼
┌────────────────────────────────────────────────────────────┐
│ Phase B 缺陷形态分类学(人工冻结,LLM 按 form 蒸馏)           │
│   F1 duplicate-add / F2 add-no-remove / F3 create-no-destroy│
│   F4 acquire-no-close / F5 retain-no-release                │
└──────────────┬─────────────────────────────────────────────┘
               ▼
┌────────────────────────────────────────────────────────────┐
│ Phase C 知识蒸馏(LLM,每修复一次,离线)                      │
│   diff + 方法级上下文 ──LLM──> 生命周期配对事实(JSON)        │
│   检索增强:BGE 在历史已验证事实库中找相似事实作 few-shot      │
└──────────────┬─────────────────────────────────────────────┘
               ▼
┌────────────────────────────────────────────────────────────┐
│ Phase D 事实验证门(差分预言机,自动,无 LLM)                 │
│   事实实例化 → 引擎跑 vul 树:命中 ≥1 期望行 ✔                │
│              → 引擎跑 fix 树:新增行零命中 ✔                  │
│   通过 → 入库;失败 → 携错误反馈重蒸馏 ≤2 次 → 仍败弃(计数)   │
└──────────────┬─────────────────────────────────────────────┘
               ▼
┌────────────────────────────────────────────────────────────┐
│ Phase E0 资源类闭包计算(确定性,零 LLM;详见 §6 E0)          │
│   种子表(策展~50 类型)+ 三类图(继承/返回/持有)            │
│   → 不动点闭包 → R(资源类型集)+ A(获取方法集)              │
│   闭包外盲区 ← 修复事实库补充(与 Phase D 同源)              │
└──────────────┬─────────────────────────────────────────────┘
               ▼
┌────────────────────────────────────────────────────────────┐
│ Phase E 检测引擎(确定性,零 LLM)                            │
│   容器声明定位 → add/remove 调用点枚举 → 容器同一性归并       │
│   → 配对可达性分析 → 泄漏/残留报告(file:line + 事实依据)     │
└────────────────────────────────────────────────────────────┘
               ▼
Phase F 评测(RQ1-RQ5,见 §8)
```

---

## 2. Phase A:数据准备

### A1 修复挖掘
- **工具**:`git`(本地完整克隆)+ 现有 `dataset/src/git_history` 管线(关键词家族过滤:leak/unclosed/not closed/memory)
- **仓库清单**:
  - 自有:apache/dubbo(24 泄漏修复)、spring-projects/spring-boot(6)
  - 扩展(资源泄漏高发仓库):netty/netty、HikariCP/HikariCP、lettuce-io/lettuce、xetorthio/jedis、apache/kafka、eclipse/jetty.project、apache/tomcat
  - JLeaks 自带的原始项目(按其论文附录列表)
- **输出**:每修复 `{hash, subject, diff, files, vul/fix 双树, 期望行}`;统一入 `dataset/` 布局

### A2 期望行(oracle 标签)提取
- 工具:自研 `expected_from_patch`(patch 删除行)± AST 行号对齐(已实现)
- 已知噪声:移动/import 行会混入;对 hunk 前后行做 ±1 对齐(已实现);test 目录行过滤(已实现)

### A3 数据清洗门槛
- 修复 diff 需含 ≥1 个资源管理信号行(close/put/register/release/retain/… 词表,见 §3)
- 剔除:纯测试改动、纯重构(无资源语义行)、非 NPE/泄漏主题混入(如 MemoryOverflow 类)

---

## 3. Phase B:缺陷形态分类学(F1-F5)

| form | 名称 | 判定特征(修复新增行的形态) | 普查占比(24 dubbo) |
|---|---|---|---|
| F1 | duplicate-add 重复添加无去重 | 新增 Set/CAS/computeIfAbsent 去重结构 | ~4 |
| F2 | add-no-remove 容器条目只进不出 | 新增 remove/evict/invalidate 调用或清理调度 | ~5 |
| F3 | create-no-destroy 创建不销毁 | 新增 destroy/dispose/cancel 传播 | ~2 |
| F4 | acquire-no-close(经典 closeable) | 新增 close()/try-with-resources/null 守卫+close | ~3 |
| F5 | retain-no-release(引用计数) | 新增 ReferenceCountUtil.release / discardReadComponents | ~6 |
| — | 杂质(非泄漏/重构/测试) | — | 剔除并计数 |

> 分类学 v1 由普查冻结;蒸馏时 LLM 必须输出 form 字段,错分在验证门被自然拦截(错误 form 的事实过不了预言机)。

---

## 4. Phase C:知识蒸馏(LLM,离线)

### C1 输入构造
| 输入 | 来源 | 工具 |
|---|---|---|
| 修复 diff(增删核心行,≤200 行/侧) | Phase A | 现有 diffs.json |
| 缺陷方法上下文(期望行所在方法全文,vul 侧) | Phase A 双树 | **tree-sitter-java**(已有 java_symbols 封装)方法级 span 提取 |
| 相似已验证事实(top-2,检索增强 few-shot) | 知识库 | **BGE**(`BAAI/bge-small-en-v1.5`,已装)+ 余弦检索 |

### C2 Prompt 设计(三段式,对齐 INFER ROI Fig.3 的工程实践)
1. Task Description:逐步 CoT——识别泄漏资源 → 定位容器 → 识别 acquire API → 识别"缺失的配对操作"(remove/destroy/dedup 之一)→ 归纳泛化形态
2. Output Format:JSON Schema(下)
3. Few-shot:2 个金例(人工从 seq1/seq12 精标)+ 检索到的相似事实

### C3 事实 Schema(v1)
```json
{
  "fact_id": "dubbo-2922",
  "source": {"repo": "dubbo", "fix_hash": "...", "form": "F1"},
  "resource": "DubboShutdownHook (JVM shutdown hook)",
  "container": {"kind": "external-registry", "decl": "Runtime hook registry",
                "match": {"type_pattern": "*Registry|Runtime", "field_pattern": null}},
  "add":  {"apis": ["addShutdownHook", "register"]},
  "remove":{"apis": ["removeShutdownHook", "unregister"]},
  "defect_form": "F1",
  "defect_site": {"file": "...", "line": 1292},
  "generalized": {
      "container_match": {"type_pattern": "*Registry|*Repository|Runtime"},
      "add_api_patterns":  ["addShutdownHook", "register*"],
      "remove_api_patterns": ["removeShutdownHook", "unregister*"]
  },
  "notes": ""
}
```

### C4 蒸馏工具与调用
- **工具**:LLM API(主:deepseek-flash/.reasoner 级;RQ4 换 GPT-4o/Claude/开源 Qwen)
- 结构化输出:json_mode + pydantic 校验;失败→附错误重试 ≤2
- **成本核算**:每修复 1-3 次调用,单次 ≤4K token;1000 修复 ≈ 2-3K 次调用(蒸馏是离线一次性)

---

## 5. Phase D:事实验证门(差分预言机)

**验证算法**(对每条蒸馏事实 f,对来源修复 c):
```
1. 实例化:f.generalized + f.container → 引擎配置
2. r_vul = 引擎.scan(c.vul_tree, f)
3. r_fix = 引擎.scan(c.fix_tree, f)
4. PASS 当且仅当:
   a) r_vul 存在命中行 ∈ c.期望行(允许 ±1 对齐)     [召回侧]
   b) r_fix 在 c 的 patch 新增行上零命中               [精度侧]
5. 失败 → 组装反例(vul 未命中行 / fix 误报行源码)→ 重蒸馏 ≤2
```
- 工具:引擎自身(§6)+ 已有差分比较函数(`_intersect/_parse_locations`)
- **意义**:入库的每条事实都被证明"可复现其来源修复的缺陷形态"——知识库自带单元测试,这是对 INFER ROI"意图无验证"的直接改进(RQ1/RQ5 素材)

---

## 6. Phase E:检测引擎(零 LLM,确定性)

### E0 资源类闭包计算(资源识别层,引擎输入 R/A 的来源)

检测引擎的输入 R(资源类型集)与 A(获取方法集)由一个**确定性不动点闭包**计算得出,零 LLM。

**种子表**(人工策展一次,~50 类型,版本化数据文件 `seeds.json`):
- JDK 种子:InputStream, OutputStream, Reader, Writer, Channel, Socket/ServerSocket,
  Connection, Statement, ResultSet, ExecutorService, Thread, Timer, Process,
  RandomAccessFile, ZipFile, JarFile, Selector, Lock, ...
- 库种子:ByteBuf, DefaultHttp2DataFrame(netty), Jedis, Cursor(android), ...

**三类图**(全仓解析,与 E1 同一 AST 前端):

| 图 | 边 | 例 |
|---|---|---|
| 继承图 | X ─extends/implements→ Y | ClientStream ─→ AbstractStream |
| 返回图 | 方法 M ─returns→ 类型 T(或调用 c 的返回值) | getServiceInfo() ─→ MetadataInfo |
| 持有图 | 类 X ─field→ 类型 T | Handler ─field→ Map<String,Channel> |

**不动点迭代**:
```
R = 种子表; A = ∅
repeat until R, A 不再变化:
    继承传播: X extends/implements T ∈ R   → R ∪= {X}
    返回传播: M 返回 T ∈ R                  → A ∪= {M}
    包装传播: X 持有 T ∈ R 的字段           → R ∪= {X}
    调用传播: M 返回某 A∈A 成员的结果       → A ∪= {M}
```

**在 24 个 dubbo 泄漏修复上的验证**:

| 成员族 | 闭包覆盖 | 依靠 |
|---|---|---|
| InputStream/JarFile(2) | ✓ | JDK 种子 |
| ByteBuf/DataFrame(7) | ✓ | netty 种子 |
| Netty Channel(2) | ✓ | netty 种子 |
| Executor/Thread/Timer(3) | ✓ | JDK 种子 |
| Map/Set 容器、proxy、cancel 传播、内部缓存(10) | ✗ | **修复事实库补充**(各有对应修复 commit) |

**合计:历史修复 100% 覆盖(闭包 58% + 修复事实 42%)**,且闭包部分零误报。

**边界(诚实声明)**:闭包外且无修复记录的泄漏容器不可发现——信息论极限,
已由 NPE 三层实验证(0/4 迁移)。相关工作定位:**Resource Leak Checker**(Kellogg et al.)
与 **Infer** 亦做资源推断,但依赖全程序抽象推断;我们的差异是事实来自修复历史
(证据化、项目特定)且产出为可解释的事实库。

### E1 AST 前端
- **v0 原型**:tree-sitter-java(Python,已有 java_symbols 封装:类/方法/字段/行范围)
- **论文版**:JavaParser 3.x(com.github.javaparser,源码级解析无需构建;选它的原因:比 Spoon 轻、API 简单、无需 classpath;Spoon 按用户要求弃用)
- 输出统一中间表示:类 → 方法 → 语句/调用(带行号)

### E2 核心算法(伪代码)
```
def scan(tree, facts, scope):
    idx = build_index(tree)                 # 类/字段/方法/调用点
    findings = []
    for fact in facts:
        for decl in find_containers(idx, fact.container_match):
            adds   = call_sites(decl, fact.add_api_patterns)
            removes= call_sites(decl, fact.remove_api_patterns)
            if fact.form == F1:   # duplicate-add
                for key, sites in group_by(adds, key_arg):
                    if len(sites) > 1 and no_dedup_guard(sites, decl):
                        findings.append(ResidualFinding(sites, fact))
            elif fact.form == F2: # add-no-remove
                if removes == [] and len(adds) > 0:
                    findings.append(ResidualFinding(adds, fact))
                else:                                  # 方法级配对检查
                    for add in adds:
                        m = enclosing_method(add)
                        if no remove_of(decl) reachable_in(m, after=add):
                            findings.append(ResidualFinding([add], fact))
            elif fact.form in (F3,F4,F5):              # 创建/获取-销毁/关闭/释放
                for acq in acquire_sites(decl, fact):
                    if no release reachable on any path from acq (同方法,含 finally/异常边):
                        findings.append(ResidualFinding([acq], fact))
    return ranked(findings)                  # 按 事实验证通过率 × 上下文置信度排序
```

### E3 已知 FP 源与对策
| FP 源 | 对策 |
|---|---|
| memoization/有意缓存(ADD 无 REMOVE 是设计) | **修复历史 FP 过滤**:容器曾有修复补 remove → 已知意外型;从未被修且引用广泛 → 降权/白名单 + LLM 离线复核(不计入检测阶段) |
| 跨方法字段持有(close() 在生命周期方法) | v0 字段级全类 remove 计数;v1 调用图(类内)可达性 |
| 容器同一性误归并 | 字段级按声明类+字段名;局部按方法内数据流(v0 用名字+类型) |

### E4 定位输出
`{file, line, fact_id, form, container, evidence: "add@line 无可达 remove@-/...", confidence}`

---

## 7. Phase F:知识库

- **存储**:SQLite(标准库 `sqlite3`;表:fact / site / validation / source_commit)——单文件、零部署、随仓库走
- **检索索引**:BGE 嵌入库(蒸馏 few-shot 与相似事实检索用;工具:sentence-transformers,已装)
- **规模**:1000 修复 ≈ 800-1000 条事实,SQLite 足矣

---

## 8. 评测设计

### 数据集
| 数据集 | 规模 | 来源/获取 | 用途 |
|---|---|---|---|
| FixKB-dubbo(自有) | 24 修复 | 已挖 | 试点/消融 |
| FixKB-springboot(自有) | 6 修复 | 已挖 | 跨项目测试 |
| **JLeaks** | 784 修复(368 资源类型) | 公开下载 | 主评测(INFER ROI 同款,直接可比) |
| DroidLeaks | 86 修复 | 公开下载 | 次评测 |
| 扩展自挖(计划) | 目标 ≥1000 修复 | 我们的管线 | 规模与 RQ4 |

### 基线
| 基线 | 获取方式 |
|---|---|
| SpotBugs | GitHub release jar,按 JLeaks/DroidLeaks 协议跑 |
| Infer | 官方发布(二进制/docker) |
| PMD | 官方 release |
| **INFER ROI(复现)** | 按论文 Fig.3 prompt 模板 + GPT-4;snippet 级,无需编译(论文已证可行) |
| LineVul 式微调(可选参考) | 开源实现,GPU 一次训练 |

### 指标
- 检测:BDR / FAR / F1(沿用 JLeaks/DroidLeaks 协议,直接可比)
- 定位:命中缺陷行比例(我们的 oracle 增强口径)
- 残留检测(RQ 拓展):fix 树新增泄漏路径发现数
- 效率:每 1K 文件扫描时间、LLM 调用次数/成本(对比 INFER ROI)
- 统计:bootstrap 95% CI;McNemar 检验(vs 最强基线)

### RQ 协议
- **RQ1 蒸馏有效性**:N 修复 → 蒸馏通过率(一次/重试后)、错误分类(JSON 错/召回侧/精度侧);跨 form 与跨仓库分布
- **RQ2 检测力**:KB 引擎 vs 四基线,于 JLeaks/DroidLeaks/自有(BDR/FAR/F1 + CI)
- **RQ2b 资源识别覆盖**:资源类型闭包覆盖率 / 修复事实补全率 / 合计对全部历史修复的覆盖
  (dubbo 24 修复上实测 58%+42%=100%);对照 INFER ROI 自报类型覆盖 60.1%(JLeaks)/67.9%(DroidLeaks)
- **RQ3 潜伏发现**:KB 引擎扫各项目 HEAD → 残留/潜伏候选 → LLM 分流 + 人工复核(报告确认率);对比 INFER ROI 在 HEAD 的产出
- **RQ4 消融**:去验证门(未验证事实直接入库的伤害)/ 去检索增强 / 去分类学(全用 closeable 三意图)/ 换 LLM(GPT-4o、Claude、Qwen-72B、deepseek)
- **RQ5 效率**:零 LLM 检测的吞吐与成本 vs INFER ROI 逐 snippet 调用;fold/蒸馏的摊销成本

---

## 9. 里程碑(周计划,9-10 周成稿)

| 周 | 里程碑 |
|---|---|
| W1 | 分类学冻结;蒸馏 prompt + 金例;24 dubbo 修复全量蒸馏,出 RQ1 试点数字 |
| W2 | 验证门 + 资源类闭包计算(E0)+ 引擎 v0(tree-sitter);24 修复自覆盖数字(RQ2 试点)|
| W3-4 | JavaParser 引擎强化;JLeaks 接入(784);基线跑通(PMD/SpotBugs/Infer/INFER ROI 复现)|
| W5-6 | 全量评测(RQ2)+ HEAD 潜伏扫描与分流(RQ3)|
| W7 | 消融与多 LLM(RQ4/RQ5)+ 统计检验 |
| W8-10 | 写作 + 图表 + 打磨投稿 |

---

## 10. 风险与缓解

| 风险 | 概率 | 缓解 |
|---|---|---|
| 蒸馏通过率低(复杂修复学不出) | 中 | 双树上下文增强 + 检索 few-shot + 2 次重试;通过率本身就是 RQ1 的报告内容 |
| 引擎 FP 过高(memoization 类) | 高 | 修复历史 FP 过滤(§6 E3)+ 置信度排序;FP 分析是论文实证的一部分 |
| INFER ROI 复现失真 | 中 | 用论文公开 prompt(全文在 Fig.3)+ GPT-4,在其数据集上报其论文数字作为对照锚点 |
| JLeaks 原仓库消失/不可挖 | 低 | 退化为 snippet 级(数据集自带 snippet);主扩展靠自有挖矿仓库 |
| 撞车风险(RAG-for-leak 已有零星工作) | 中 | 差异化三件套:验证门(事实级 oracle)、零 LLM 检测、生命周期分类学;_related work 全量核查 |
| 每仓库形态分布偏斜 | 低 | 扩仓策略:优先资源管理密集型(netty/HikariCP/lettuce/jedis/kafka) |

---

## 11. 相关工作定位

- **INFER ROI(直接前驱)**:LLM 逐 snippet 标注三意图 + 路径检查。差异:①意图分类学推广到生命周期配对(覆盖 75% 此前盲区);②事实经预言机验证入库(其意图无验证);③检测阶段零 LLM(其逐 snippet 调用)。
- **JLeaks/DroidLeaks**:数据来源 + 评测协议沿用。
- **传统检测器(SpotBugs/Infer/PMD)**:预定义 API 清单的 FN/FP 问题由 INFER ROI 与本文共同解决;本文额外覆盖生命周期家族。
- **Resource Leak Checker(Kellogg et al., PLDI)/ Infer 资源分析 / IntelliJ AutoCloseableResource 检查**:同样基于类型闭包/抽象推断发现资源泄漏,但 ①依赖编译或全程序分析(本文 git archive 源码级,零构建);②资源语义来自预定义注解/模型(本文事实来自修复历史挖掘,可覆盖无类型链的项目特定容器);③产出为告警(本文产出为经验证的事实库+可解释定位)。
- **LLM-for-static-analysis(如 LLM 写 CodeQL/semgrep)**:本文不用 LLM 写规则,而用 LLM 蒸馏**数据形态的事实**交由固定引擎解释——事实可验证、可组合、引擎可复现。
- **APR / patch 正确性**:正交;KB 事实可作为 APR 的缺陷规格来源(future work)。

---

## 12. 外部工具汇总表

| 步骤 | 外部工具 | 用途 | 获取 |
|---|---|---|---|
| A1 | git + git_history 管线(自有) | 修复挖掘 | 已有 |
| A2 | git archive | 双树物化 | 已有 |
| C1 | tree-sitter-java(Python) | 方法级上下文提取 | 已有(java_symbols) |
| C1/C7 | BGE(bge-small-en-v1.5) | 相似事实检索 | 已装 |
| C3/C-D | LLM API(deepseek / GPT-4o / Claude / Qwen) | 蒸馏与 RQ4 | .env 已配 deepseek |
| E1(v0) | tree-sitter-java | 引擎 AST | 已有 |
| E1(论文版) | **JavaParser**(com.github.javaparser) | 引擎 AST(替代 Spoon) | Maven Central 单 jar |
| E 基线 | SpotBugs / Infer / PMD | 基线检测器 | GitHub/官方 release |
| F | SQLite(Python sqlite3) | 知识库 | 标准库 |
| 评测 | JLeaks / DroidLeaks 公开数据 | 主评测集 | 公开下载 |
| 评测 | GPT-4 API | INFER ROI 复现 | 按需 |
