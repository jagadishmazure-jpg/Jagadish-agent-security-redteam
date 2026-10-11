"""Harness runner: execute attacks through the defense layers.

Pipeline per attack:

1. ``user_input``  -> input sanitizer -> (blocked?) -> agent -> output guardrail
2. ``tool_output`` -> input sanitizer on the tool result -> agent -> guardrail
3. ``tool_call``   -> tool-call policy -> (denied?) -> agent executes tool

Every outcome records which layer caught the attack (``blocked_by``), so the
attack/defense matrix can be derived empirically rather than asserted.
"""

from __future__ import annotations

from dataclasses import dataclass

from redteam.attacks.catalog import ATTACKS, Attack
from redteam.defenses import (
    GuardrailResult,
    InputSanitizer,
    OutputGuardrail,
    PolicyDecision,
    ToolCallPolicy,
)
from redteam.harness.fake_agent import FakeTargetAgent


@dataclass
class AttackOutcome:
    attack_id: str
    category: str
    severity: str
    blocked: bool
    blocked_by: str | None
    succeeded: bool
    details: str


class RedTeamHarness:
    """Run attacks against the fake agent with defenses engaged."""

    def __init__(
        self,
        sanitizer: InputSanitizer | None = None,
        guardrail: OutputGuardrail | None = None,
        policy: ToolCallPolicy | None = None,
        agent_factory=None,
    ) -> None:
        self.sanitizer = sanitizer or InputSanitizer()
        self.guardrail = guardrail or OutputGuardrail()
        self.policy = policy or ToolCallPolicy()
        triggers = {a.id: a.trigger for a in ATTACKS}
        self.agent_factory = agent_factory or (lambda: FakeTargetAgent(triggers))

    # -- single attack ------------------------------------------------------
    def run_attack(self, attack: Attack) -> AttackOutcome:
        agent = self.agent_factory()
        if attack.vector == "user_input":
            return self._run_input_attack(attack, agent, attack.payload)
        if attack.vector == "tool_output":
            return self._run_tool_output_attack(attack, agent)
        if attack.vector == "tool_call":
            return self._run_tool_call_attack(attack, agent)
        raise ValueError(f"unknown attack vector: {attack.vector}")

    def _run_input_attack(self, attack: Attack, agent: FakeTargetAgent, text: str) -> AttackOutcome:
        result = self.sanitizer.sanitize(text)
        if result.flagged:
            return self._blocked(attack, "input_sanitizer", "; ".join(result.reasons))
        return self._check_agent_output(attack, agent, agent.respond(text))

    def _run_tool_output_attack(self, attack: Attack, agent: FakeTargetAgent) -> AttackOutcome:
        # Defense in depth: tool results are sanitized like user input.
        result = self.sanitizer.sanitize(attack.payload)
        if result.flagged:
            return self._blocked(
                attack, "input_sanitizer", "tool output: " + "; ".join(result.reasons)
            )
        return self._check_agent_output(attack, agent, agent.handle_tool_output(attack.payload))

    def _run_tool_call_attack(self, attack: Attack, agent: FakeTargetAgent) -> AttackOutcome:
        spec = attack.tool_call or {}
        decision: PolicyDecision = self.policy.evaluate(spec.get("name", ""), spec.get("args", {}))
        if not decision.allowed:
            return self._blocked(attack, "tool_call_policy", decision.reason)
        output = agent.call_tool(spec.get("name", ""), spec.get("args", {}))
        return AttackOutcome(
            attack_id=attack.id,
            category=attack.category,
            severity=attack.severity,
            blocked=False,
            blocked_by=None,
            succeeded=True,
            details=f"tool executed without policy denial: {output}",
        )

    def _check_agent_output(
        self, attack: Attack, agent: FakeTargetAgent, output: str
    ) -> AttackOutcome:
        guard: GuardrailResult = self.guardrail.check(output)
        if guard.blocked:
            return self._blocked(attack, "output_guardrail", "; ".join(guard.reasons))
        if "COMPROMISED[" in output:
            return AttackOutcome(
                attack_id=attack.id,
                category=attack.category,
                severity=attack.severity,
                blocked=False,
                blocked_by=None,
                succeeded=True,
                details="agent emitted compromise marker",
            )
        return AttackOutcome(
            attack_id=attack.id,
            category=attack.category,
            severity=attack.severity,
            blocked=False,
            blocked_by=None,
            succeeded=False,
            details="agent did not fall for the attack",
        )

    @staticmethod
    def _blocked(attack: Attack, layer: str, details: str) -> AttackOutcome:
        return AttackOutcome(
            attack_id=attack.id,
            category=attack.category,
            severity=attack.severity,
            blocked=True,
            blocked_by=layer,
            succeeded=False,
            details=details,
        )

    # -- full suite ----------------------------------------------------------
    def run_all(self, attacks: list[Attack] | None = None) -> list[AttackOutcome]:
        """Run every attack in the catalog (or ``attacks``) and return outcomes."""
        return [self.run_attack(a) for a in (attacks if attacks is not None else ATTACKS)]
