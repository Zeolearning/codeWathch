from __future__ import annotations

import json

import pytest

from code_watch.dataset.split import load_split, make_split
from code_watch.dataset.vul4j import load_cases, resolve_case_ids


@pytest.fixture(scope="module")
def pov_ids() -> list[str]:
    return resolve_case_ids("pov")


@pytest.fixture(scope="module")
def cases() -> dict:
    return load_cases()


def test_split_is_exact_partition(pov_ids, cases):
    result = make_split(pov_ids, ratio=0.8, seed=42, cases=cases)
    assert not set(result.train) & set(result.test)
    assert set(result.train) | set(result.test) == set(pov_ids)
    assert len(result.train) + len(result.test) == len(pov_ids)


def test_split_hits_ratio(pov_ids, cases):
    result = make_split(pov_ids, ratio=0.8, seed=42, cases=cases)
    assert abs(len(result.train) - 0.8 * len(pov_ids)) <= 1.0


def test_split_deterministic(pov_ids, cases):
    a = make_split(pov_ids, ratio=0.8, seed=42, cases=cases)
    b = make_split(pov_ids, ratio=0.8, seed=42, cases=cases)
    assert a.train == b.train and a.test == b.test


def test_split_seed_changes_allocation(pov_ids, cases):
    a = make_split(pov_ids, ratio=0.8, seed=42, cases=cases)
    b = make_split(pov_ids, ratio=0.8, seed=7, cases=cases)
    assert set(a.test) != set(b.test)


def test_split_cwe_coverage(pov_ids, cases):
    """Every CWE with >=5 cases must appear on both sides (stratification)."""
    result = make_split(pov_ids, ratio=0.8, seed=42, cases=cases)
    from collections import Counter

    cwe_total = Counter(cases[cid].cwe_id for cid in pov_ids)
    train_cwes = {cases[cid].cwe_id for cid in result.train}
    test_cwes = {cases[cid].cwe_id for cid in result.test}
    for cwe, n in cwe_total.items():
        if n >= 5:
            assert cwe in train_cwes, f"{cwe} missing from train"
            assert cwe in test_cwes, f"{cwe} missing from test"


def test_split_shared_projects_recorded(pov_ids, cases):
    result = make_split(pov_ids, ratio=0.8, seed=42, cases=cases)
    train_proj = {cases[cid].project for cid in result.train}
    test_proj = {cases[cid].project for cid in result.test}
    assert set(result.shared_projects) == train_proj & test_proj
    # large multi-project CWEs keep most projects disjoint
    assert len(train_proj - test_proj) >= 5


def test_split_rejects_unknown_ids(cases):
    with pytest.raises(ValueError, match="VUL4J-999"):
        make_split(["VUL4J-10", "VUL4J-999"], cases=cases)


def test_split_rejects_bad_ratio(pov_ids, cases):
    with pytest.raises(ValueError, match="ratio"):
        make_split(pov_ids[:3], ratio=1.5, cases=cases)


def test_split_save_load_roundtrip(tmp_path, pov_ids, cases):
    result = make_split(pov_ids, ratio=0.8, seed=42, pool="pov", cases=cases)
    path = result.save(tmp_path / "split.json")
    loaded = load_split(path)
    assert loaded.train == result.train
    assert loaded.test == result.test
    assert loaded.meta == result.meta
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["meta"]["seed"] == 42 and data["meta"]["pool"] == "pov"
