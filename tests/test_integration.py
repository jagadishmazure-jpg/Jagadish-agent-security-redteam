"""End-to-end tests: full attack suite through every defense layer."""

import pytest

from conftest import BENIGN_INPUTS, BENIGN_TOOL_CALLS
from redteam.attacks.catalog import ATTACKS
from redteam.scoring import (
    attack_success_rate,
    block_rate,
    render_markdown_report,
    weighted_risk_score,
)


@pytest.mark.parametrize("attack", ATTACKS, ids=lambda a: a.id)
def test_every_attack_is_caught_by_a_defense(harness, attack):
    """Core guarantee: no catalog attack survives the layered defenses."""
    outcome = harness.run_attack(attack)
    assert outcome.blocked, f"{attack.id} was not blocked by any defense"
    assert outcome.blocked_by, "blocked outcome must name the layer"
    assert not outcome.succeeded


@pytest.mark.parametrize("attack", ATTACKS, ids=lambda a: a.id)
def test_blocking_layer_matches_expectation(harness, attack):
    outcome = harness.run_attack(attack)
    assert outcome.blocked_by == attack.expected_defense


@pytest.mark.parametrize("text", BENIGN_INPUTS)
def test_benign_inputs_pass_full_pipeline(harness, text):
    """No false positives: benign input -> agent -> guardrail stays clean."""
    agent = harness.agent_factory()
    assert not harness.sanitizer.sanitize(text).flagged
    output = agent.respond(text)
    assert "COMPROMISED" not in output
    assert not harness.guardrail.check(output).blocked


@pytest.mark.parametrize("name,args", BENIGN_TOOL_CALLS)
def test_benign_tool_calls_pass_policy(harness, name, args):
    assert harness.policy.evaluate(name, args).allowed


def test_full_suite_scores_zero_risk(harness):
    outcomes = harness.run_all()
    assert block_rate(outcomes) == pytest.approx(1.0)
    assert attack_success_rate(outcomes) == pytest.approx(0.0)
    assert weighted_risk_score(outcomes) == pytest.approx(0.0)


def test_report_renders_all_sections(harness):
    outcomes = harness.run_all()
    report = render_markdown_report(outcomes)
    assert "# Red-team run report" in report
    assert "## Summary" in report
    assert "## By category" in report
    assert "## Per-attack outcomes" in report
    for attack in ATTACKS:
        assert attack.id in report


def test_report_shows_perfect_block_rate(harness):
    report = render_markdown_report(harness.run_all())
    assert "Block rate: 100.0%" in report
