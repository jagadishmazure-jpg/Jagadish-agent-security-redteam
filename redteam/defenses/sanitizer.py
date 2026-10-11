"""Input sanitizer: detect prompt-injection and jailbreak patterns.

The sanitizer is the first line of defense. It scans user input *and* tool
output (defense in depth against indirect injection) for known adversarial
patterns. It never modifies the text — it flags, and the harness decides.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class SanitizerResult:
    flagged: bool
    reasons: list[str] = field(default_factory=list)


class InputSanitizer:
    """Pattern-based detector for injection, jailbreak, and PII-probe inputs."""

    PATTERNS: list[tuple[str, str]] = [
        ("direct_instruction_override", r"ignore\s+(all\s+)?previous\s+instructions"),
        ("fake_system_block", r"\[(system|admin|instruction)[^\]]*\]"),
        ("system_override", r"system\s+override|priority\s*0"),
        ("fake_assistant_turn", r"(?m)^(assistant|system)\s*:"),
        ("roleplay_instruction", r"\byou are now\b|\bpretend\b|\broleplay\b"),
        ("jailbreak_persona", r"\bdan\b|do anything now|developer\s*mode"),
        ("hypothetical_framing", r"hypothetically"),
        ("social_engineering_story", r"\bgrandma\b|\bbedtime\b"),
        ("encoded_instruction", r"base64.{0,40}(decode|follow)|decode.{0,40}base64"),
        ("hidden_instruction", r"hidden\s+instruction|covert\s+instruction"),
        (
            "pii_extraction",
            r"social security( number)?|\bssn\b|credit card( number)?|"
            r"repeat back|list all email addresses|\bpassword\b",
        ),
        (
            "reveal_secret",
            r"reveal.*(api key|secret|password|system prompt)|print.*system prompt",
        ),
    ]

    def __init__(self, extra_patterns: list[tuple[str, str]] | None = None) -> None:
        patterns = list(self.PATTERNS) + list(extra_patterns or [])
        self._compiled = [(name, re.compile(rx, re.IGNORECASE)) for name, rx in patterns]

    def sanitize(self, text: str) -> SanitizerResult:
        """Return which adversarial patterns ``text`` matches, if any."""
        reasons = [name for name, rx in self._compiled if rx.search(text)]
        return SanitizerResult(flagged=bool(reasons), reasons=reasons)
