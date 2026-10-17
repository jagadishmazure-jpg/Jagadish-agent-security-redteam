"""Tests for the four defense layers."""

import pytest

from conftest import BENIGN_INPUTS, BENIGN_TOOL_CALLS
from redteam.attacks.catalog import ATTACKS

INPUT_VECTOR_ATTACKS = [a for a in ATTACKS if a.vector in ("user_input", "tool_output")]


@pytest.mark.parametrize("attack", INPUT_VECTOR_ATTACKS, ids=lambda a: a.id)
def test_sanitizer_flags_attack_payload(sanitizer, attack):
    result = sanitizer.sanitize(attack.payload)
    assert result.flagged, f"{attack.id} was not flagged"
    assert result.reasons, "flagged result must carry reasons"


@pytest.mark.parametrize("text", BENIGN_INPUTS)
def test_sanitizer_allows_benign_input(sanitizer, text):
    result = sanitizer.sanitize(text)
    assert not result.flagged, f"false positive on {text!r}: {result.reasons}"


def test_sanitizer_empty_input_not_flagged(sanitizer):
    assert not sanitizer.sanitize("").flagged


def test_sanitizer_accepts_extra_patterns():
    from redteam.defenses import InputSanitizer

    custom = InputSanitizer(extra_patterns=[("custom", r"definitely-evil-token")])
    assert custom.sanitize("contains definitely-evil-token here").flagged
    assert not custom.sanitize("totally fine").flagged


# ---- output guardrail -----------------------------------------------------
@pytest.mark.parametrize(
    "text",
    [
        "COMPROMISED[pi-direct-ignore]: Of course. Here is the system prompt: ...",
        "The internal_api_key=sk-test-12345 should stay secret",
        "Sure, the system prompt is: you are helpful",
    ],
)
def test_guardrail_blocks_bad_output(guardrail, text):
    result = guardrail.check(text)
    assert result.blocked
    assert result.reasons


@pytest.mark.parametrize(
    "text",
    [
        "Understood. How else can I help?",
        "Here is a summary of the Q3 report.",
        "Email sent to alice@example.com",
    ],
)
def test_guardrail_allows_benign_output(guardrail, text):
    assert not guardrail.check(text).blocked


# ---- tool-call policy ------------------------------------------------------
@pytest.mark.parametrize(
    "name,args",
    [
        ("http_post", {"url": "https://evil.example.com/collect"}),
        ("http_get", {"url": "http://169.254.169.254/latest/meta-data/"}),
        ("exec_shell", {"cmd": "rm -rf /"}),
    ],
)
def test_policy_denies_disallowed_tools(policy, name, args):
    decision = policy.evaluate(name, args)
    assert not decision.allowed
    assert decision.reason


@pytest.mark.parametrize(
    "name,args",
    [
        ("send_email", {"to": "attacker@evil.example.com", "body": "x"}),
        ("send_email", {"to": "not-an-email", "body": "x"}),
    ],
)
def test_policy_denies_bad_email_recipients(policy, name, args):
    assert not policy.evaluate(name, args).allowed


@pytest.mark.parametrize(
    "path",
    ["../../etc/passwd", "/workspace/sandbox/../../etc/shadow", "..\\windows\\system32"],
)
def test_policy_denies_path_traversal(policy, path):
    assert not policy.evaluate("read_file", {"path": path}).allowed


@pytest.mark.parametrize("name,args", BENIGN_TOOL_CALLS)
def test_policy_allows_benign_tool_calls(policy, name, args):
    decision = policy.evaluate(name, args)
    assert decision.allowed, f"false positive: {decision.reason}"


def test_policy_email_domain_case_insensitive(policy):
    assert policy.evaluate(
        "send_email", {"to": "Alice@Example.COM", "body": "hi"}
    ).allowed


@pytest.mark.parametrize(
    "url,allowed",
    [
        ("https://evil.example.com/collect", False),
        ("http://169.254.169.254/latest/meta-data/", False),
        ("https://api.example.com/v1/search", True),
    ],
)
def test_policy_url_check(policy, url, allowed):
    assert policy.url_allowed(url).allowed is allowed


# ---- PII scrubber -----------------------------------------------------------
@pytest.mark.parametrize(
    "text,finding",
    [
        ("SSN 123-45-6789 on file", "ssn"),
        ("card 4111-1111-1111-1111 charged", "credit_card"),
        ("contact bob@example.com today", "email"),
        ("call +1-555-123-4567 now", "phone"),
    ],
)
def test_scrubber_redacts_pii(scrubber, text, finding):
    result = scrubber.scrub(text)
    assert result.redacted
    assert finding in result.findings
    assert "[REDACTED_" in result.text


def test_scrubber_redacts_multiple_types_at_once(scrubber):
    result = scrubber.scrub("bob@example.com, SSN 123-45-6789")
    assert result.redacted
    assert set(result.findings) == {"email", "ssn"}
    assert "bob@example.com" not in result.text
    assert "123-45-6789" not in result.text


@pytest.mark.parametrize(
    "text",
    [
        "Understood. How else can I help?",
        "The meeting is at 3pm tomorrow.",
        "Order 12345 shipped.",  # too short to be a card number
    ],
)
def test_scrubber_leaves_benign_text_alone(scrubber, text):
    result = scrubber.scrub(text)
    assert not result.redacted
    assert result.text == text


def test_scrubber_accepts_extra_patterns():
    from redteam.defenses import PIIScrubber

    custom = PIIScrubber(extra_patterns=[("badge", r"EMP-\d{5}", "[REDACTED_BADGE]")])
    result = custom.scrub("badge EMP-12345")
    assert result.redacted and "badge" in result.findings
