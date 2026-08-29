from __future__ import annotations

import shutil
from pathlib import Path

from code_watch.analysis.analyzer import analyze_case
from code_watch.analysis.schema import BugAnalysis


def analysis_path(case_id: str) -> Path:
    return Path(f"output/analysis/{case_id}.json")


def analyze_batch(
    case_ids: list[str],
    *,
    verbose: bool = True,
    skip_existing: bool = True,
    work_root: str | None = None,
    keep_work: bool = False,
) -> tuple[list[str], list[tuple[str, str]]]:
    """Run root-cause analysis over a list of Vul4J case ids.

    Returns (done, errors). A failure on one case is isolated — the case id and error
    message go into the errors list, and the batch continues.

    With ``skip_existing=True``, cases whose analysis JSON exists, parses, and carries
    the expected ``bug_id`` are skipped (resume support). When ``work_root`` is given,
    each case checks out into ``work_root/<case_id>`` which is removed after the case
    (success or failure) unless ``keep_work=True``; without work_root the shared
    checkout cache ``output/checkouts/<case_id>`` is used and kept.
    """
    done: list[str] = []
    errors: list[tuple[str, str]] = []

    for case_id in case_ids:
        out_path = analysis_path(case_id)

        if skip_existing and out_path.exists():
            try:
                existing = BugAnalysis.model_validate_json(
                    out_path.read_text(encoding="utf-8")
                )
                if existing.bug_id == case_id:
                    done.append(case_id)
                    if verbose:
                        print(f"[analyze-batch] skip {case_id} (already analyzed)", flush=True)
                    continue
            except Exception:
                pass

        if verbose:
            print(f"\n[analyze-batch] === {case_id} ===", flush=True)
        base_dir = None
        own_workdir = False
        if work_root:
            base_dir = str(Path(work_root) / case_id)
            own_workdir = True
        try:
            analysis, *_ = analyze_case(case_id, base_dir=base_dir, verbose=verbose)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(analysis.model_dump_json(indent=2), encoding="utf-8")
            done.append(case_id)
        except Exception as e:
            errors.append((case_id, f"{type(e).__name__}: {e}"))
            if verbose:
                print(f"[analyze-batch] {case_id} FAILED: {e}", flush=True)
        finally:
            if not keep_work and own_workdir and base_dir:
                shutil.rmtree(base_dir, ignore_errors=True)

    return done, errors
