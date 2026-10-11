"""Tests for scoring math: success rates, weighted risk, breakdowns."""

import pytest

from redteam.harness.runner import AttackOutcome
from redteam.scoring import (
    SEVERITY_WEIGHTS,
    attack_success_rate,
    block_rate,
    category_breakdown,
    summarize,
    weighted_risk_score,
)


def make_outcome(
    attack_id="x",
    category="prompt_injection",
    severity="high",
    blocked=False,
    succeeded=False,
) -> AttackOutcome:
    return AttackOutcome(
        attack_id=attack_id,
        category=category,
        severity=severity,
        blocked=blocked,
        blocked_by="input_sanitizer" if blocked else None,
        succeeded=succeeded,
        details="test",
    )


def test_severity_weights_sane():
    assert SEVERITY_WEIGHTS["critical"] > SEVERITY_WEIGHTS["high"] > SEVERITY_WEIGHTS["medium"]
    assert SEVERITY_WEIGHTS["medium"] > SEVERITY_WEIGHTS["low"] > 0


def test_attack_success_rate_empty_is_zero():
    assert attack_success_rate([]) == 0.0


def test_attack_success_rate_all_blocked():
    outcomes = [make_outcome(blocked=True) for _ in range(5)]
    assert attack_success_rate(outcomes) == 0.0


def test_attack_success_rate_mixed():
    outcomes = [make_outcome(succeeded=True), make_outcome(succeeded=True),
                make_outcome(blocked=True), make_outcome()]
    assert attack_success_rate(outcomes) == pytest.approx(0.5)


def test_block_rate_empty_is_zero():
    assert block_rate([]) == 0.0


def test_block_rate_counts_blocks():
    outcomes = [make_outcome(blocked=True), make_outcome(blocked=True), make_outcome()]
    assert block_rate(outcomes) == pytest.approx(2 / 3)


def test_weighted_risk_score_empty_is_zero():
    assert weighted_risk_score([]) == 0.0


def test_weighted_risk_score_all_blocked_is_zero():
    outcomes = [make_outcome(severity="critical", blocked=True) for _ in range(3)]
    assert weighted_risk_score(outcomes) == 0.0


def test_weighted_risk_score_weights_severity():
    # One critical success out of (critical + 3 lows): 4 / (4+3) = 4/7.
    outcomes = [
        make_outcome(severity="critical", succeeded=True),
        make_outcome(severity="low"),
        make_outcome(severity="low"),
        make_outcome(severity="low"),
    ]
    assert weighted_risk_score(outcomes) == pytest.approx(4 / 7)


def test_weighted_risk_score_all_succeeded_is_one():
    outcomes = [make_outcome(severity=s, succeeded=True) for s in ("low", "critical")]
    assert weighted_risk_score(outcomes) == pytest.approx(1.0)


def test_weighted_risk_score_unknown_severity_defaults_to_one():
    outcomes = [make_outcome(severity="unknown", succeeded=True)]
    assert weighted_risk_score(outcomes) == pytest.approx(1.0)


def test_category_breakdown_groups_correctly():
    outcomes = [
        make_outcome(attack_id="a1", category="prompt_injection", blocked=True),
        make_outcome(attack_id="a2", category="prompt_injection", succeeded=True),
        make_outcome(attack_id="b1", category="tool_abuse", blocked=True),
    ]
    breakdown = category_breakdown(outcomes)
    assert breakdown["prompt_injection"]["total"] == 2
    assert breakdown["prompt_injection"]["success_rate"] == pytest.approx(0.5)
    assert breakdown["prompt_injection"]["block_rate"] == pytest.approx(0.5)
    assert breakdown["tool_abuse"]["total"] == 1
    assert breakdown["tool_abuse"]["success_rate"] == pytest.approx(0.0)


def test_category_breakdown_empty():
    assert category_breakdown([]) == {}


def test_summarize_counts_failed_without_trigger():
    outcomes = [make_outcome(blocked=True), make_outcome(succeeded=True), make_outcome()]
    summary = summarize(outcomes)
    assert summary["total"] == 3
    assert summary["blocked"] == 1
    assert summary["succeeded"] == 1
    assert summary["failed"] == 1
    assert summary["attack_success_rate"] == pytest.approx(1 / 3)
    assert summary["block_rate"] == pytest.approx(1 / 3)
    assert "by_category" in summary and "weighted_risk_score" in summary
