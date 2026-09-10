# dataset/src — 挖掘管线源码与运行入口

## 布局

```
src/
├── git_history/       # 管线实现(独立 Python 包,自包含、无 code_watch 依赖)
│   ├── fix_commits.py         # 步骤1:收集修复类提交
│   ├── cluster_fixes.py       # 共享引擎:BGE 嵌入 / UMAP / HDBSCAN / TF-IDF 标签
│   ├── npe_cluster.py         # NPE 筛选 + 按 message 聚类(CLI)
│   ├── npe_diff_cluster.py    # NPE diff 收集 + 按 diff 聚类(CLI)
│   └── __init__.py
└── run_pipeline.sh    # 一键入口:四步全跑
```

包内使用相对导入,与 `code_watch` 包零耦合;调用前把本目录(`dataset/src`)
加入 `PYTHONPATH` 即可(`run_pipeline.sh` 已自动处理)。

## 用法

```bash
# 一键(repo_path 缺省 dataset/java-repos/<repo_name>)
dataset/src/run_pipeline.sh dubbo

# 单模块
PYTHONPATH=dataset/src python -m git_history.npe_diff_cluster --help
```

或直接 import:

```python
import sys; sys.path.insert(0, "dataset/src")
from git_history import collect_fix_commits, collect_npe_diffs, cluster_npe_diffs
```
