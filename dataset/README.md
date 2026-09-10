# dataset/ — 漏洞数据集与挖掘产物

目标:从仓库 git 历史构建**按漏洞类型分类的修复提交子数据集**,
按 commit 时间先后 `seq` 编号,供下游 CodeWatch 规则生成(前段训练)与
holdout 评测(后段测试)按 seq 前后缀切分使用。

## 目录结构

| 子目录 | 内容 | 产生方式 |
|---|---|---|
| `commits/<repo>/fix_commits.json` | 全部 fix 提交(带 ISO 时间戳;注释/文档类 fix 已剔除) | 流水线步骤 1 |
| `diffs/<repo>/diffs.json` | 每个 fix 提交解析后的 diff(files/deleted/added) | 流水线步骤 2 |
| `subsets/<type>/<repo>.json` | 按漏洞类型的子数据集,按 commit_date 升序 + `seq: 1..N` | 流水线步骤 3 |
| `clusters/diff/<repo>/<type>_clusters.json` | 每家族的 diff 语义聚类报告(调研用) | 流水线步骤 4 |
| `java-repos/<repo>/` | 原始 git 仓库(**完整克隆**,部分克隆会触发海量按需回源) | git clone |
| `src/` | 构建管线源码 + 入口脚本(见 `src/README.md`) | — |

`java-repos` 现状:dubbo(71MB)、spring-boot(252MB)均已完整克隆。
不要再使用 `--filter=blob:none` 部分克隆。

## 标准用法

```bash
dataset/src/run_pipeline.sh dubbo          # repo_path 缺省 dataset/java-repos/<name>
dataset/src/run_pipeline.sh springboot     # 名字自动归一匹配 spring-boot 目录
```

## 子数据集 schema(`subsets/<type>/<repo>.json`)

```json
{"repo": "dubbo", "type": "npe", "count": 83, "sorted_by": "commit_date asc",
 "commits": [{"seq": 1, "hash": "...", "subject": "...", "commit_date": "...",
              "author_date": "...", "matched_terms": [...],
              "all_matched_types": ["npe"]}]}
```

- 一个提交**只进一个**子集(优先级独占);`all_matched_types` 记录所有命中的类型。
- 训练/测试切分:按 `seq` 前缀切(如前 70% 训练),构建时不产 split 文件。

## 当前类型(dubbo / springboot,2025-xx 基线)

| type | dubbo | springboot | 匹配逻辑 |
|---|---|---|---|
| `npe` | 83 | 41 | message:NPE/null pointer/NullPointerException + bare-null 修复上下文 |
| `resource_leak` | 24 | 6 | message 强信号:leak/unclosed/not closed |

## 扩展新类型

在 `src/git_history/vuln_types.py` 加一个带装饰器的 matcher 即可,无需改其他代码:

```python
@register_type("concurrency", priority=30)
def _match_concurrency(commit, diff_record):
    ...  # 返回命中的 canonical terms;空列表 = 不匹配
```

## 复现(全流程一条命令)

```bash
dataset/src/run_pipeline.sh dubbo && dataset/src/run_pipeline.sh springboot
```
