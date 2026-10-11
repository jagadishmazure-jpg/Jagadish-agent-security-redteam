"""PII scrubber: detect and redact personal data in text.

Runs over agent outputs (and, in the harness, over tool results) so that even
when an extraction probe slips through, the sensitive values never leave the
system in the clear.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class ScrubResult:
    text: str
    findings: list[str] = field(default_factory=list)

    @property
    def redacted(self) -> bool:
        return bool(self.findings)


class PIIScrubber:
    """Regex-based PII detector with deterministic redaction tokens."""

    PATTERNS: list[tuple[str, str, str]] = [
        ("ssn", r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]"),
        (
            "credit_card",
            r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
            "[REDACTED_CARD]",
        ),
        (
            "email",
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            "[REDACTED_EMAIL]",
        ),
        (
            "phone",
            r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
            "[REDACTED_PHONE]",
        ),
    ]

    def __init__(self, extra_patterns: list[tuple[str, str, str]] | None = None) -> None:
        patterns = list(self.PATTERNS) + list(extra_patterns or [])
        self._compiled = [(n, re.compile(rx), token) for n, rx, token in patterns]

    def scrub(self, text: str) -> ScrubResult:
        """Return ``text`` with every detected PII value replaced."""
        findings: list[str] = []
        scrubbed = text
        for name, rx, token in self._compiled:
            if rx.search(scrubbed):
                findings.append(name)
                scrubbed = rx.sub(token, scrubbed)
        return ScrubResult(text=scrubbed, findings=findings)
