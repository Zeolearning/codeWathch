#!/usr/bin/env bash
# 一键流水线:fix 提交收集 → diff 收集 → 漏洞类型子集 → 每家族 diff 聚类。
#
# 用法:
#   dataset/src/run_pipeline.sh <repo_name> [repo_path]
#   repo_path 缺省为 dataset/java-repos/<repo_name>(完整克隆,勿用 --filter)
# 示例:
#   dataset/src/run_pipeline.sh dubbo
#   dataset/src/run_pipeline.sh springboot dataset/java-repos/spring-boot
#
# 产物(约定见 ../README.md):
#   dataset/commits/<repo>/fix_commits.json        # 全部 fix 提交(带时间戳)
#   dataset/diffs/<repo>/diffs.json                # 解析后的 diff
#   dataset/subsets/<type>/<repo>.json             # 按类型子集(时序 seq 编号)
#   dataset/clusters/diff/<repo>/<type>_clusters.json  # 每家族聚类报告

set -euo pipefail

REPO_NAME="${1:?usage: run_pipeline.sh <repo_name> [repo_path]}"
REPO_PATH="${2:-dataset/java-repos/$REPO_NAME}"
# 名字归一化匹配:springboot -> spring-boot(忽略 - 与 _ 差异)
norm() { printf '%s' "$1" | tr -d '_-'; }
if [ ! -d "$REPO_PATH" ]; then
  for d in dataset/java-repos/*/; do
    if [ "$(norm "$(basename "$d")")" = "$(norm "$REPO_NAME")" ]; then
      REPO_PATH="${d%/}"
      break
    fi
  done
fi
[ -d "$REPO_PATH" ] || { echo "repo not found: $REPO_PATH" >&2; exit 1; }
REDUCE_DIMS="${3:-10}"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
[ -x "$PY" ] || PY=python3
# git_history 是 dataset/src 下的独立包
export PYTHONPATH="$ROOT/dataset/src${PYTHONPATH:+:$PYTHONPATH}"

echo "== [1/2] build sub-datasets -> dataset/{commits,diffs,subsets}/"
"$PY" -m git_history.build_dataset "$REPO_PATH" dataset --name "$REPO_NAME"

echo "== [2/2] per-family diff clustering -> dataset/clusters/diff/"
"$PY" - "$REPO_NAME" "$REDUCE_DIMS" <<'EOF'
import json, sys
from pathlib import Path
from git_history.npe_diff_cluster import cluster_diff_records

repo, reduce_dims = sys.argv[1], int(sys.argv[2])
diffs = {r["hash"]: r for r in json.load(open(f"dataset/diffs/{repo}/diffs.json"))["commits"]}
for path in sorted(Path("dataset/subsets").glob("*/" + repo + ".json")):
    vtype = path.parent.name
    subset = json.load(open(path))["commits"]
    records = [diffs[c["hash"]] for c in subset if c["hash"] in diffs]
    if len(records) < 3:
        print(f"  {repo}/{vtype}: n={len(records)} (少于 3 条,跳过聚类)")
        continue
    out = f"dataset/clusters/diff/{repo}/{vtype}_clusters.json"
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    report = cluster_diff_records(records, out, reduce_dims=reduce_dims)
    print(f"  {repo}/{vtype}: n={report['input_count']} clusters={report['n_clusters']} noise={report['n_noise']} -> {out}")
EOF

echo
echo "== done. 产物:"
find dataset/commits dataset/diffs dataset/subsets dataset/clusters -name "*${REPO_NAME}*" -o -path "*subsets/*/*" -name "*.json" | sort -u | grep -i "$REPO_NAME" || true
