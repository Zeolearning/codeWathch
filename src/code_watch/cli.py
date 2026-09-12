from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from code_watch.config import CodeWatchConfig
from code_watch.rules.merge import evaluate_generalization, run_cluster_loop
from code_watch.rules.pipeline import out_prefix_for, run_git_case_pipeline
from code_watch.workspace import (
    DEFAULT_WORKSPACE_ROOT,
    GitCase,
    clean_cluster,
    materialize_cluster,
)

app = typer.Typer(
    name="code-watch",
    help="Git-mined semgrep rule generation (cluster sampling -> per-case loops -> merge)",
    no_args_is_help=True,
)
console = Console()


@app.command()
def materialize(
    report: str = typer.Option(..., "--report", help="Cluster report JSON, e.g. dataset/clusters/diff/dubbo/npe_clusters.json"),
    subset: str = typer.Option(..., "--subset", help="Subset JSON, e.g. dataset/subsets/npe/dubbo.json"),
    diffs: str = typer.Option(..., "--diffs", help="Diffs JSON, e.g. dataset/diffs/dubbo/diffs.json"),
    repo_path: str = typer.Option(..., "--repo-path", help="Local git repository (full clone)"),
    cluster: int = typer.Option(None, "--cluster", "-c", help="Cluster id (default: largest)"),
    k: int = typer.Option(5, "--k", help="Sample size (or all, if the cluster is smaller)"),
    seed: int = typer.Option(42, "--seed", help="Sampling seed (same report+seed => same cases)"),
    workspace_root: str = typer.Option(str(DEFAULT_WORKSPACE_ROOT), "--workspace-root"),
):
    """Sample k commits from a cluster and materialize vul/fix workspaces (git archive)."""
    cases, cluster_id = materialize_cluster(
        report, subset, diffs, repo_path,
        cluster_id=cluster, k=k, seed=seed, workspace_root=workspace_root,
    )

    table = Table(
        title=f"cluster {cluster_id} [dim]({cases[0].cluster_label})[/dim] -> {len(cases)} cases",
        show_header=True,
    )
    table.add_column("case_id", style="bold")
    table.add_column("seq", justify="right")
    table.add_column("fix", justify="left")
    table.add_column("files", justify="right")
    table.add_column("subject")
    for c in cases:
        table.add_row(c.case_id, str(c.seq), c.fix_hash[:10], str(len(c.files)), c.subject[:60])
    console.print(table)
    console.print(f"[green]workspace:[/green] {cases[0].workspace.parent}")


@app.command()
def run(
    case_id: str = typer.Option("", "--case-id", help="Case id, e.g. dubbo-npe-c6-1 (dir under workspace root)"),
    case_dir: str = typer.Option("", "--case-dir", help="Explicit case directory (overrides --case-id)"),
    workspace_root: str = typer.Option(str(DEFAULT_WORKSPACE_ROOT), "--workspace-root"),
    refresh_analysis: bool = typer.Option(False, "--refresh-analysis", help="Re-run the analysis agent even if JSON exists"),
    max_attempts: int = typer.Option(3, "--max-attempts", help="Max generate/evaluate attempts (repair loop)"),
):
    """Per-case pipeline: analyze (cached) -> deterministic FixDelta -> generate -> evaluate."""
    if case_dir:
        case = GitCase.load(case_dir)
    elif case_id:
        # case_id "<repo>-<vtype>-c<cid>-<i>" -> workspace/<repo>-<vtype>-c<cid>/case-<i>
        prefix, _, idx = case_id.rpartition("-")
        case = GitCase.load(f"{workspace_root.rstrip('/')}/{prefix}/case-{idx}")
    else:
        console.print("[red]need --case-id or --case-dir[/red]")
        raise typer.Exit(1)

    console.print(f"[bold]Case pipeline for {case.case_id}...[/bold]")

    config = CodeWatchConfig.from_env()
    config.apply_env()

    analysis, delta, rule, evaluation = run_git_case_pipeline(
        case, config,
        refresh_analysis=refresh_analysis,
        verbose=True, max_attempts=max_attempts,
    )

    console.print()
    console.print(Panel(
        analysis.root_cause,
        title=f"Root Cause [{case.case_id}]",
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
    table.add_row("fired_on_buggy", "\n".join(evaluation.fired_on_buggy[:10]) or "(none)")
    table.add_row("fired_on_fixed", "\n".join(evaluation.fired_on_fixed[:10]) or "(none)")
    table.add_row("expected", "\n".join(evaluation.expected[:10]) or "(none)")
    console.print(table)

    p = out_prefix_for(case.case_id)
    console.print(f"\n[green]Artifacts:[/green]")
    console.print(f"  output/analysis/{case.case_id}.json")
    console.print(f"  {p}-fixdelta.json")
    console.print(f"  {p}-rule.json")
    console.print(f"  {p}-eval.json")


@app.command()
def clean(
    cluster_dir: str = typer.Argument(..., help="Cluster workspace dir (name under workspace/ or absolute path); 'all' wipes the root"),
    workspace_root: str = typer.Option(str(DEFAULT_WORKSPACE_ROOT), "--workspace-root"),
):
    """Delete cluster workspace(s) after the merge stage (trees are regenerable)."""
    import shutil
    from pathlib import Path
    if cluster_dir == "all":
        shutil.rmtree(Path(workspace_root), ignore_errors=True)
        console.print(f"[green]removed:[/green] {workspace_root}")
    else:
        clean_cluster(cluster_dir, workspace_root=workspace_root)
        console.print(f"[green]removed:[/green] {workspace_root.rstrip('/')}/{cluster_dir}")


@app.command()
def cluster(
    cluster_dir: str = typer.Argument(..., help="Cluster workspace dir, e.g. workspace/dubbo-npe-c1"),
    skip_existing: bool = typer.Option(True, "--skip-existing/--no-skip-existing", help="Reload per-case rule+eval from output/ when present"),
    refresh_analysis: bool = typer.Option(False, "--refresh-analysis", help="Re-run the analysis agent even if JSON exists"),
    max_attempts: int = typer.Option(3, "--max-attempts", help="Per-case generate/evaluate attempts"),
    max_rounds: int = typer.Option(3, "--max-rounds", help="Merge feedback rounds"),
    clean: bool = typer.Option(False, "--clean", help="Remove the cluster workspace after the merge loop"),
):
    """Cluster loops: per-case pipelines (cached) -> merge -> re-run gate -> feedback."""
    console.print(f"[bold]Cluster loops for {cluster_dir}...[/bold]")

    config = CodeWatchConfig.from_env()
    config.apply_env()

    outcome = run_cluster_loop(
        cluster_dir, config,
        skip_existing=skip_existing, refresh_analysis=refresh_analysis,
        max_attempts=max_attempts, max_rounds=max_rounds, verbose=True, clean=clean,
    )

    covered = set(outcome.plan.covered_cases)
    table = Table(
        title=f"Merged rule [bold]{outcome.rule.rule_id}[/bold]  "
              f"({len(covered)}/{len(outcome.verdicts)} covered, "
              f"rounds={outcome.rounds}, {'PASS' if outcome.passed else 'FAIL'})",
        show_header=True,
    )
    table.add_column("case")
    table.add_column("declared")
    table.add_column("fires on buggy")
    table.add_column("silent on fixed")
    table.add_column("bonus")
    for v in outcome.verdicts:
        table.add_row(
            v.case_id,
            "covered" if v.covered else "excluded",
            "YES" if v.hit_expected else ("—" if not v.syntax_ok else "no"),
            "YES" if not v.fired_on_fix else f"NO {v.fired_on_fix[:2]}",
            "recall" if v.bonus_recall else "",
        )
    console.print(table)
    if outcome.plan.commonality:
        console.print(Panel(outcome.plan.commonality, title="Commonality", border_style="yellow"))
    if outcome.failures:
        console.print(Panel("\n".join(outcome.failures), title="Gate failures", border_style="red"))
    p = out_prefix_for(outcome.cluster)
    console.print(f"[green]Artifacts:[/green] {p}-merged-rule.json, {p}-merged-eval.json")


@app.command()
def generalize(
    rule_path: str = typer.Option(..., "--rule", help="Merged rule JSON, e.g. output/rules/dubbo-npe-c1/dubbo-npe-c1-merged-rule.json"),
    report: str = typer.Option(..., "--report", help="Cluster report JSON"),
    subset: str = typer.Option(..., "--subset", help="Subset JSON"),
    diffs: str = typer.Option(..., "--diffs", help="Diffs JSON"),
    repo_path: str = typer.Option(..., "--repo-path", help="Local git repository"),
    cluster: int = typer.Option(None, "--cluster", "-c", help="Cluster id (default: largest)"),
    workspace_root: str = typer.Option(str(DEFAULT_WORKSPACE_ROOT), "--workspace-root"),
):
    """Scan the merged rule over the cluster's UNSAMPLED members (泛化测试)."""
    from code_watch.rules.schema import Rule

    rule = Rule.model_validate_json(Path(rule_path).read_text(encoding="utf-8"))

    # 已抽样的 hash 从 workspace 的 case meta 里读
    cluster_dir = Path(workspace_root) / rule.bug_id
    sampled = {
        json.loads((d / "meta.json").read_text(encoding="utf-8"))["fix_hash"]
        for d in cluster_dir.glob("case-*")
        if (d / "meta.json").exists()
    }
    console.print(f"[bold]Generalization for {rule.rule_id}[/bold] (excluding {len(sampled)} sampled)")

    summary = evaluate_generalization(
        rule, report, subset, diffs, repo_path,
        cluster_id=cluster, exclude_hashes=sampled, workspace_root=workspace_root,
    )

    table = Table(
        title=f"Generalization: {summary['recalled']}/{summary['evaluated']} members recalled, "
              f"FP members: {len(summary['fix_added_fp_members'])}",
        show_header=True,
    )
    table.add_column("case")
    table.add_column("seq", justify="right")
    table.add_column("buggy命中", justify="right")
    table.add_column("期望行", justify="right")
    table.add_column("fix新增FP", justify="right")
    table.add_column("subject")
    for d in summary["details"]:
        if "error" in d:
            table.add_row(d["case_id"], "-", "ERR", "-", "-", d["error"][:40])
            continue
        table.add_row(
            d["case_id"], str(d["seq"]), str(d["fired_on_buggy"]),
            f"{len(d['hit_expected_lines'])}/{d['expected_scannable']}",
            str(len(d["fix_added_fp"])), d["subject"][:40],
        )
    console.print(table)

    out = Path(f"output/rules/{rule.bug_id}/generalization.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    console.print(f"[green]Report:[/green] {out}")


if __name__ == "__main__":
    app()
