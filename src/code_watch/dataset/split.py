from __future__ import annotations

import json
import random
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from code_watch.dataset.schema import CaseInfo
from code_watch.dataset.vul4j import load_cases


@dataclass
class SplitResult:
    """A reproducible train/test split over Vul4J case ids.

    Fields:
        train / test:  ordered case-id lists (disjoint, union == input pool)
        meta:          ratio, seed, pool spec, per-CWE counts, shared projects
    """

    train: list[str] = field(default_factory=list)
    test: list[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    @property
    def shared_projects(self) -> list[str]:
        return list(self.meta.get("shared_projects", []))

    def to_dict(self) -> dict:
        return {"train": self.train, "test": self.test, "meta": self.meta}

    def save(self, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        return p


def load_split(path: str | Path) -> SplitResult:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return SplitResult(
        train=list(data.get("train", [])),
        test=list(data.get("test", [])),
        meta=dict(data.get("meta", {})),
    )


def make_split(
    case_ids: list[str],
    *,
    ratio: float = 0.8,
    seed: int = 42,
    pool: str = "",
    cases: dict[str, CaseInfo] | None = None,
) -> SplitResult:
    """CWE-stratified, project-disjoint-when-possible train/test split.

    Algorithm (deterministic for a given seed):
    1. Group cases by cwe_id; process groups largest-first (ties by cwe id).
    2. Each group gets a train quota proportional to the remaining global
       train target (`round(ratio * n)` overall), so the split lands close to
       the requested ratio even with fragmented groups.
    3. Inside a group with >=2 projects, whole projects go to train
       (largest-first, while they fit the quota); any leftover quota is filled
       with individually sampled cases; the rest go to test. Single-project
       groups are split by sampling within the project (overlap unavoidable).

    The 79-case PoV pool has 28 CWEs (15 singletons), so perfect project
    disjointness is impossible; `shared_projects` in meta records the overlap.
    """
    if not 0.0 < ratio < 1.0:
        raise ValueError(f"ratio must be in (0, 1), got {ratio}")
    if not case_ids:
        raise ValueError("empty case pool")

    cases = cases if cases is not None else load_cases()
    unknown = [cid for cid in case_ids if cid not in cases]
    if unknown:
        raise ValueError(f"unknown case ids: {', '.join(unknown)}")

    rng = random.Random(seed)
    n = len(case_ids)
    target_train = round(ratio * n)

    by_cwe: dict[str, list[str]] = defaultdict(list)
    for cid in case_ids:
        by_cwe[cases[cid].cwe_id or "unknown"].append(cid)

    train: list[str] = []
    test: list[str] = []
    assigned_train = 0
    assigned_total = 0

    for cwe, ids in sorted(by_cwe.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        ids = sorted(ids)
        remaining_target = max(target_train - assigned_train, 0)
        remaining_total = n - assigned_total
        quota = round(remaining_target * len(ids) / remaining_total)
        quota = max(0, min(quota, len(ids)))

        by_project: dict[str, list[str]] = defaultdict(list)
        for cid in ids:
            by_project[cases[cid].project].append(cid)

        group_train: list[str] = []
        leftovers: list[str] = []
        if len(by_project) >= 2:
            # Whole-project greedy: largest projects first; ties broken by a
            # seeded shuffle so different seeds explore different allocations.
            names = sorted(by_project)
            rng.shuffle(names)
            names.sort(key=lambda p: -len(by_project[p]))
            filled = 0
            leftovers = []
            for proj in names:
                pids = by_project[proj]
                if filled + len(pids) <= quota:
                    group_train.extend(pids)
                    filled += len(pids)
                else:
                    leftovers.extend(pids)
            if filled < quota and leftovers:
                group_train.extend(sorted(rng.sample(sorted(leftovers), quota - filled)))
        else:
            group_train = sorted(rng.sample(ids, quota))

        train.extend(group_train)
        test.extend(cid for cid in ids if cid not in set(group_train))
        assigned_train += len(group_train)
        assigned_total += len(ids)

    cwe_dist = _cwe_distribution(train, test, cases)
    shared = sorted(
        {cases[cid].project for cid in train} & {cases[cid].project for cid in test}
    )
    meta = {
        "pool": pool,
        "ratio": ratio,
        "seed": seed,
        "total": n,
        "train_count": len(train),
        "test_count": len(test),
        "shared_projects": shared,
        "cwe_distribution": cwe_dist,
    }
    return SplitResult(train=train, test=test, meta=meta)


def _cwe_distribution(
    train: list[str], test: list[str], cases: dict[str, CaseInfo]
) -> dict[str, dict[str, int]]:
    dist: dict[str, dict[str, int]] = defaultdict(lambda: {"train": 0, "test": 0})
    for cid in train:
        dist[cases[cid].cwe_id or "unknown"]["train"] += 1
    for cid in test:
        dist[cases[cid].cwe_id or "unknown"]["test"] += 1
    return dict(sorted(dist.items()))
