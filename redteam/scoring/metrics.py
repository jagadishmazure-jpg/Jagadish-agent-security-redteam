"""Risk metrics over harness outcomes.

All metrics are pure functions over :class:`AttackOutcome` lists, so they are
trivially testable and reusable outside the harness.
"""

from __future__ import annotations

from redteam.harness.runner import AttackOutcome


SEVERITY_WEIGHTS = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _weight(severity: str) -> int:
    return SEVERITY_WEIGHTS.get(severity, 1)


def attack_success_rate(outcomes: list[AttackOutcome]) -> float:
    """Fraction of attacks that succeeded. 0.0 when there are no outcomes."""
    if not outcomes:
        return 0.0
    return sum(1 for o in outcomes if o.succeeded) / len(outcomes)


def block_rate(outcomes: list[AttackOutcome]) -> float:
    """Fraction of attacks stopped by at least one defense layer."""
    if not outcomes:
        return 0.0
    return sum(1 for o in outcomes if o.blocked) / len(outcomes)


def weighted_risk_score(outcomes: list[AttackOutcome]) -> float:
    """Severity-weighted share of successful attacks, in [0, 1].

    A critical-severity success counts 4x as much as a low-severity one.
    """
    total = sum(_weight(o.severity) for o in outcomes)
    if total == 0:
        return 0.0
    landed = sum(_weight(o.severity) for o in outcomes if o.succeeded)
    return landed / total


def category_breakdown(outcomes: list[AttackOutcome]) -> dict[str, dict]:
    """Per-category totals, blocks, and success rates."""
    breakdown: dict[str, dict] = {}
    for outcome in outcomes:
        bucket = breakdown.setdefault(
            outcome.category, {"total": 0, "blocked": 0, "succeeded": 0}
        )
        bucket["total"] += 1
        bucket["blocked"] += 1 if outcome.blocked else 0
        bucket["succeeded"] += 1 if outcome.succeeded else 0
    for bucket in breakdown.values():
        total = bucket["total"]
        bucket["success_rate"] = bucket["succeeded"] / total if total else 0.0
        bucket["block_rate"] = bucket["blocked"] / total if total else 0.0
    return breakdown


def summarize(outcomes: list[AttackOutcome]) -> dict:
    """One dict with every headline metric for a run."""
    return {
        "total": len(outcomes),
        "blocked": sum(1 for o in outcomes if o.blocked),
        "succeeded": sum(1 for o in outcomes if o.succeeded),
        "failed": sum(1 for o in outcomes if not o.blocked and not o.succeeded),
        "attack_success_rate": attack_success_rate(outcomes),
        "block_rate": block_rate(outcomes),
        "weighted_risk_score": weighted_risk_score(outcomes),
        "by_category": category_breakdown(outcomes),
    }
