"""Red-team harness: run the attack suite against a fake target agent."""

from redteam.harness.fake_agent import FakeTargetAgent
from redteam.harness.runner import AttackOutcome, RedTeamHarness

__all__ = ["FakeTargetAgent", "AttackOutcome", "RedTeamHarness"]
