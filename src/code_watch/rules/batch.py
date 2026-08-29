from __future__ import annotations

import shutil
from pathlib import Path

from code_watch.config import CodeWatchConfig
from code_watch.rules.pipeline import out_prefix_for, run_case_pipeline
from code_watch.rules.schema import RuleEvaluation

__all__ = ["run_batch"]


def run_batch(
    case_ids: list[str],
    config: CodeWatchConfig,
    *,
    refresh_analysis: bool = False,
    refresh_checkout: bool = False,
    verbose: bool = True,
    max_attempts: int = 3,
    skip_existing: bool = True,
    retry_failed: bool = False,
    work_root: str | None = None,
    keep_work: bool = False,
) -> tuple[list[RuleEvaluation], list[tuple[str, str]]]:
    """Run the full case pipeline (analyze -> delta -> rule -> eval) over case ids.

    Returns (evals, errors). A failure on one case is isolated — the case id and error
    message go into the errors list, and the batch continues.

    With ``skip_existing=True``, cases whose ``-eval.json`` already exists are loaded
    from disk instead of re-run (resume support); with ``retry_failed=True`` an existing
    SYNTAX_ERROR evaluation is re-run instead of skipped.

    Checkouts default to the persistent shared cache ``output/checkouts/<case_id>``.
    When ``work_root`` is given, each case checks out into ``work_root/<case_id>``
    which is removed after the case unless ``keep_work=True``.
    """
    evals: list[RuleEvaluation] = []
    errors: list[tuple[str, str]] = []

    for case_id in case_ids:
        eval_path = Path(f"{out_prefix_for(case_id)}-eval.json")
        if skip_existing and eval_path.exists():
            try:
                evaluation = RuleEvaluation.model_validate_json(
                    eval_path.read_text(encoding="utf-8")
                )
                if retry_failed and evaluation.status == "SYNTAX_ERROR":
                    if verbose:
                        print(f"[batch] {case_id}: previous eval was SYNTAX_ERROR, re-running", flush=True)
                else:
                    evals.append(evaluation)
                    if verbose:
                        print(f"[batch] skip {case_id} (already evaluated)", flush=True)
                    continue
            except Exception:
                pass

        if verbose:
            print(f"\n[batch] === {case_id} ===", flush=True)
        base_dir = None
        own_workdir = False
        if work_root:
            base_dir = str(Path(work_root) / case_id)
            own_workdir = True
        try:
            _, _, _, evaluation = run_case_pipeline(
                case_id, config, base_dir=base_dir,
                refresh_analysis=refresh_analysis, refresh_checkout=refresh_checkout,
                verbose=verbose, max_attempts=max_attempts,
            )
            evals.append(evaluation)
        except Exception as e:
            errors.append((case_id, f"{type(e).__name__}: {e}"))
            if verbose:
                print(f"[batch] {case_id} FAILED: {e}", flush=True)
        finally:
            if not keep_work and own_workdir and base_dir:
                shutil.rmtree(base_dir, ignore_errors=True)

    return evals, errors
