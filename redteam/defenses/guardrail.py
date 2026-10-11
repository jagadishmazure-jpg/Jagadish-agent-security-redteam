"""Output guardrail: block disallowed content classes in agent output.

The guardrail is the last line of defense. Even if a malicious input slips
past the sanitizer, the agent's *response* is inspected before it reaches the
user: compromise markers, leaked secrets, and disallowed instructions are
blocked.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class GuardrailResult:
    blocked: bool
    reasons: list[str] = field(default_factory=list)


class OutputGuardrail:
    """Blocklist-based inspector for agent outputs."""

    PATTERNS: list[tuple[str, str]] = [
        ("compromise_marker", r"COMPROMISED\["),
        ("secret_leak", r"sk-test|internal_api_key|CONFIDENTIAL"),
        ("system_prompt_leak", r"system prompt (is|:)"),
        (
            "disallowed_instructions",
            r"how to make explosives|bypass content filters.{0,40}step",
        ),
    ]

    def __init__(self, extra_patterns: list[tuple[str, str]] | None = None) -> None:
        patterns = list(self.PATTERNS) + list(extra_patterns or [])
        self._compiled = [(name, re.compile(rx, re.IGNORECASE)) for name, rx in patterns]

    def check(self, text: str) -> GuardrailResult:
        """Return which disallowed content classes ``text`` contains, if any."""
        reasons = [name for name, rx in self._compiled if rx.search(text)]
        return GuardrailResult(blocked=bool(reasons), reasons=reasons)
