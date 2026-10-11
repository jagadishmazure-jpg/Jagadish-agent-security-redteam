"""Human-readable summary reports for red-team runs."""

from __future__ import annotations

from redteam.harness.runner import AttackOutcome
from redteam.scoring.metrics import summarize


def render_markdown_report(outcomes: list[AttackOutcome]) -> str:
    """Render a Markdown report: headline metrics, categories, per-attack table."""
    summary = summarize(outcomes)
    lines = [
        "# Red-team run report",
        "",
        "## Summary",
        "",
        f"- Attacks run: {summary['total']}",
        f"- Blocked by defenses: {summary['blocked']}",
        f"- Succeeded: {summary['succeeded']}",
        f"- Failed without triggering: {summary['failed']}",
        f"- Attack success rate: {summary['attack_success_rate']:.1%}",
        f"- Block rate: {summary['block_rate']:.1%}",
        f"- Weighted risk score: {summary['weighted_risk_score']:.3f}",
        "",
        "## By category",
        "",
        "| Category | Total | Blocked | Succeeded | Success rate |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for category, bucket in sorted(summary["by_category"].items()):
        lines.append(
            f"| {category} | {bucket['total']} | {bucket['blocked']} | "
            f"{bucket['succeeded']} | {bucket['success_rate']:.1%} |"
        )
    lines += [
        "",
        "## Per-attack outcomes",
        "",
        "| Attack | Severity | Blocked | Blocked by | Succeeded |",
        "| --- | --- | --- | --- | --- |",
    ]
    for outcome in outcomes:
        lines.append(
            f"| {outcome.attack_id} | {outcome.severity} | "
            f"{'yes' if outcome.blocked else 'no'} | {outcome.blocked_by or '-'} | "
            f"{'yes' if outcome.succeeded else 'no'} |"
        )
    lines.append("")
    return "\n".join(lines)
