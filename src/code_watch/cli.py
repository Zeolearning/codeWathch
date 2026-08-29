from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from code_watch.config import CodeWatchConfig
from code_watch.dataset.split import load_split, make_split
from code_watch.dataset.vul4j import resolve_case_ids
from code_watch.rules.batch import run_batch
from code_watch.rules.holdout import evaluate_holdout
from code_watch.rules.metrics import BatchReport
from code_watch.rules.pipeline import out_prefix_for, run_case_pipeline

app = typer.Typer(
    name="code-watch",
    help="Vul4J vulnerability root-cause analysis + Semgrep rule generation",
    no_args_is_help=True,
)
console = Console()


def _resolve(spec: str) -> list[str]:
    try:
        ids = resolve_case_ids(spec)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from None
    return ids


@app.command()
def split(
    cases: str = typer.Option("pov", "--cases", help="Pool spec: 'pov' | 'sb' | 'all' | explicit ids"),
    ratio: float = typer.Option(0.8, "--ratio", help="Train fraction (0<ratio<1)"),
    seed: int = typer.Option(42, "--seed", help="RNG seed for reproducibility"),
    out: str = typer.Option("", "--out", help="Output JSON path (default splits/vul4j-<spec>-seed<seed>.json)"),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing split file"),
):
    """Create a CWE-stratified, project-disjoint-when-possible train/test split."""
    ids = _resolve(cases)
    if not out:
        safe_spec = "".join(ch if ch.isalnum() else "-" for ch in cases)
        out = f"splits/vul4j-{safe_spec}-seed{seed}.json"
    if Path(out).exists() and not force:
        console.print(f"[red]{out} already exists (use --force to overwrite)[/red]")
        raise typer.Exit(1)

    result = make_split(ids, ratio=ratio, seed=seed, pool=cases)
    result.save(out)

    table = Table(title=f"Split [bold]{out}[/bold]", show_header=True)
    table.add_column("CWE", style="bold")
    table.add_column("train", justify="right")
    table.add_column("test", justify="right")
    for cwe, dist in result.meta["cwe_distribution"].items():
        table.add_row(cwe, str(dist["train"]), str(dist["test"]))
    console.print(table)
    console.print(Panel(
        f"total: {result.meta['total']}  ->  train: {len(result.train)}  test: {len(result.test)}\n"
        f"shared projects (both sides): {', '.join(result.shared_projects) or 'none'}",
        title="Split Summary", border_style="green",
    ))
    console.print(f"[green]Saved:[/green] {out}")


def _write_report(
    evals, errors, report_md: str, report_csv: str,
) -> BatchReport:
    report = BatchReport(evals)
    md = report.to_markdown()
    if errors:
        md += "\n\n## Errors\n\n| case | error |\n|---|---|\n"
        for bid, err in errors:
            md += f"| {bid} | {err.replace('|', '/')[:200]} |\n"
    Path(report_md).parent.mkdir(parents=True, exist_ok=True)
    Path(report_md).write_text(md, encoding="utf-8")
    Path(report_csv).parent.mkdir(parents=True, exist_ok=True)
    Path(report_csv).write_text(report.to_csv(), encoding="utf-8")
    return report


@app.command()
def run(
    case: str = typer.Option("VUL4J-10", "--case", "-c", help="Vul4J case id, e.g. VUL4J-10"),
    refresh_analysis: bool = typer.Option(False, "--refresh-analysis", help="Re-run the analysis agent even if JSON exists"),
    refresh_checkout: bool = typer.Option(False, "--refresh-checkout", help="Force a fresh vul4j checkout"),
    max_attempts: int = typer.Option(3, "--max-attempts", help="Max generate/evaluate attempts (repair loop)"),
):
    """Full case pipeline: analyze (cached) -> deterministic FixDelta -> generate -> evaluate."""
    console.print(f"[bold]Case pipeline for {case}...[/bold]")

    config = CodeWatchConfig.from_env()
    config.apply_env()

    analysis, delta, rule, evaluation = run_case_pipeline(
        case, config,
        refresh_analysis=refresh_analysis, refresh_checkout=refresh_checkout,
        verbose=True, max_attempts=max_attempts,
    )

    console.print()
    console.print(Panel(
        analysis.root_cause,
        title=f"Root Cause [{case}]",
        border_style="yellow",
    ))
    console.print()
    console.print(Panel(
        rule.yaml,
        title=f"Generated Rule [{rule.rule_id}]  mode={rule.mode}  severity={rule.severity}",
        border_style="cyan",
    ))

    table = Table(title=f"Evaluation [{evaluation.status}]", show_header=True)
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_row("status", evaluation.status)
    table.add_row("syntax_ok", str(evaluation.syntax_ok))
    table.add_row("precision", str(evaluation.precision))
    table.add_row("recall", str(evaluation.recall))
    table.add_row("fired_on_vuln", "\n".join(evaluation.fired_on_buggy[:10]) or "(none)")
    table.add_row("fired_on_fixed", "\n".join(evaluation.fired_on_fixed[:10]) or "(none)")
    table.add_row("expected", "\n".join(evaluation.expected[:10]) or "(none)")
    console.print(table)

    p = out_prefix_for(case)
    console.print(f"\n[green]Artifacts:[/green]")
    console.print(f"  output/analysis/{case}.json")
    console.print(f"  {p}-fixdelta.json")
    console.print(f"  {p}-rule.json")
    console.print(f"  {p}-eval.json")


@app.command()
def batch(
    cases: str = typer.Option("pov", "--cases", help="'pov' | 'sb' | 'all' | comma-separated ids/ranges, e.g. 'VUL4J-1,4-10,80-S'"),
    split_path: str = typer.Option("", "--split", help="Read case ids from a split JSON (overrides --cases)"),
    role: str = typer.Option("train", "--role", help="Which side of --split to run: 'train' | 'test'"),
    refresh_analysis: bool = typer.Option(False, "--refresh-analysis", help="Re-run the analysis agent even if JSON exists"),
    refresh_checkout: bool = typer.Option(False, "--refresh-checkout", help="Force fresh vul4j checkouts"),
    max_attempts: int = typer.Option(3, "--max-attempts", help="Max generate/evaluate attempts (repair loop)"),
    skip_existing: bool = typer.Option(
        True, "--skip-existing/--no-skip-existing",
        help="Skip cases whose -eval.json already exists",
    ),
    retry_failed: bool = typer.Option(
        False, "--retry-failed",
        help="With --skip-existing, re-run cases whose previous eval was SYNTAX_ERROR",
    ),
    work_root: str = typer.Option(
        "", "--work-root",
        help="Directory for temporary checkouts (default: persistent output/checkouts/<case>)",
    ),
    keep_work: bool = typer.Option(False, "--keep-work", help="Keep temporary checkout directories"),
    report_md: str = typer.Option("output/reports/rules-report.md", "--report", help="Report markdown path"),
    report_csv: str = typer.Option("output/reports/rules-report.csv", "--csv", help="Report CSV path"),
):
    """Run the full pipeline over a batch of cases and write an aggregate report."""
    if split_path:
        if role not in ("train", "test"):
            console.print(f"[red]--role must be 'train' or 'test', got '{role}'[/red]")
            raise typer.Exit(1)
        try:
            ids = list(getattr(load_split(split_path), role))
        except FileNotFoundError as e:
            console.print(f"[red]split file not found: {e}[/red]")
            raise typer.Exit(1) from None
        console.print(f"[dim]Loaded {len(ids)} '{role}' cases from {split_path}[/dim]")
    else:
        ids = _resolve(cases)
    console.print(f"[bold]Batch case pipeline: {len(ids)} cases[/bold]")

    config = CodeWatchConfig.from_env()
    config.apply_env()

    evals, errors = run_batch(
        ids, config,
        refresh_analysis=refresh_analysis, refresh_checkout=refresh_checkout, verbose=True,
        max_attempts=max_attempts, skip_existing=skip_existing, retry_failed=retry_failed,
        work_root=work_root or None, keep_work=keep_work,
    )

    report = _write_report(evals, errors, report_md, report_csv)

    console.print()
    console.print(Panel(
        f"total: {report.total}  passed: {report.passed}  pass@1: {report.pass_at_1}\n"
        f"macro precision: {report.macro_precision}  macro recall: {report.macro_recall}\n"
        f"micro precision: {report.micro_precision}  micro recall: {report.micro_recall}\n"
        f"errors: {len(errors)}",
        title="Batch Report",
        border_style="green" if report.passed else "yellow",
    ))
    console.print(f"[green]Report:[/green] {report_md}")
    console.print(f"[green]CSV:[/green] {report_csv}")


@app.command()
def holdout(
    train: str = typer.Option("pov", "--train", help="Training case spec (rules loaded from output/)"),
    test: str = typer.Option("sb", "--test", help="Held-out test case spec"),
    split_path: str = typer.Option("", "--split", help="Read train+test ids from a split JSON (overrides --train/--test)"),
    work_root: str = typer.Option(
        "", "--work-root",
        help="Directory for temporary checkouts (deleted per case unless --keep-work)",
    ),
    keep_work: bool = typer.Option(False, "--keep-work", help="Keep temporary checkout directories"),
    tolerance: int = typer.Option(3, "--tolerance", help="Line tolerance for 'localized' (hit at bug location)"),
    near_tolerance: int = typer.Option(10, "--near-tolerance", help="Line tolerance for 'near' (hit within N lines of bug location)"),
    report_md: str = typer.Option("output/reports/holdout-report.md", "--report", help="Report markdown path"),
    report_json: str = typer.Option("output/reports/holdout-report.json", "--json", help="Report JSON path"),
):
    """Evaluate generalization: scan held-out test cases with the merged training rules."""
    if split_path:
        try:
            result = load_split(split_path)
        except FileNotFoundError as e:
            console.print(f"[red]split file not found: {e}[/red]")
            raise typer.Exit(1) from None
        train_ids, test_ids = list(result.train), list(result.test)
        console.print(f"[dim]Loaded split {split_path}: {len(train_ids)} train / {len(test_ids)} test[/dim]")
    else:
        train_ids = _resolve(train)
        test_ids = _resolve(test)

    report = evaluate_holdout(
        train_ids, test_ids,
        work_root=work_root or None, keep_work=keep_work,
        tolerance=tolerance, near_tolerance=near_tolerance, verbose=True,
    )

    Path(report_md).parent.mkdir(parents=True, exist_ok=True)
    Path(report_md).write_text(report.to_markdown(), encoding="utf-8")
    Path(report_json).parent.mkdir(parents=True, exist_ok=True)
    Path(report_json).write_text(
        json.dumps(report.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
    )

    s = report
    console.print()
    console.print(Panel(
        f"train cases: {len(train_ids)}  rules: {len(s.rule_ids)}"
        f"  (skipped SYNTAX_ERROR: {len(s.skipped_syntax_error)})\n"
        f"test cases: {s.total}\n"
        f"same-file: {sum(1 for v in s.verdicts if v.same_file_rule_ids)}/{s.total}\n"
        f"near (≤{near_tolerance} lines): {sum(1 for v in s.verdicts if v.near_rule_ids)}/{s.total}\n"
        f"localized (≤{tolerance} lines): {sum(1 for v in s.verdicts if v.localized_rule_ids)}/{s.total}",
        title="Holdout Report",
        border_style="green" if s.detected else "yellow",
    ))
    console.print(f"[green]Report:[/green] {report_md}")
    console.print(f"[green]JSON:[/green] {report_json}")


if __name__ == "__main__":
    app()
