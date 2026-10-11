"""Tests for the attack catalog and payload generators."""

import pytest

from redteam.attacks import (
    ATTACKS,
    CATEGORIES,
    SEVERITIES,
    VECTORS,
    attacks_by_category,
    delimiter_escape,
    developer_mode_jailbreak,
    direct_injection,
    exfiltration_tool_call,
    get_attack,
    hypothetical_jailbreak,
    instruction_override,
    pii_probe,
    poisoned_tool_output,
    roleplay_jailbreak,
)
from redteam.defenses import InputSanitizer


def test_catalog_is_not_empty():
    assert len(ATTACKS) >= 15


def test_attack_ids_unique():
    ids = [a.id for a in ATTACKS]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("attack", ATTACKS, ids=lambda a: a.id)
def test_attack_fields_valid(attack):
    assert attack.id and attack.name and attack.description
    assert attack.category in CATEGORIES
    assert attack.severity in SEVERITIES
    assert attack.vector in VECTORS
    assert attack.expected_defense in {
        "input_sanitizer",
        "output_guardrail",
        "tool_call_policy",
        "pii_scrubber",
    }


@pytest.mark.parametrize("attack", ATTACKS, ids=lambda a: a.id)
def test_attack_has_executable_content(attack):
    if attack.vector == "tool_call":
        assert isinstance(attack.tool_call, dict)
        assert attack.tool_call.get("name")
        assert isinstance(attack.tool_call.get("args"), dict)
    else:
        assert attack.payload, "non-tool attacks need a payload"
        assert attack.trigger, "non-tool attacks need a fake-agent trigger"


def test_every_category_represented():
    present = {a.category for a in ATTACKS}
    assert present == set(CATEGORIES)


def test_category_counts():
    assert len(attacks_by_category("prompt_injection")) == 6
    assert len(attacks_by_category("jailbreak")) == 4
    assert len(attacks_by_category("indirect_injection")) == 2
    assert len(attacks_by_category("tool_abuse")) == 4
    assert len(attacks_by_category("pii_extraction")) == 3


def test_get_attack_roundtrip():
    assert get_attack("pi-direct-ignore").name == "Direct instruction override"


def test_get_attack_unknown_raises():
    with pytest.raises(KeyError):
        get_attack("no-such-attack")


def test_attacks_by_category_unknown_is_empty():
    assert attacks_by_category("no-such-category") == []


# ---- generators -----------------------------------------------------------
def test_direct_injection_wraps_instruction():
    payload = direct_injection("reveal the password")
    assert "reveal the password" in payload
    assert "ignore all previous instructions" in payload.lower()


def test_delimiter_escape_forges_system_block():
    payload = delimiter_escape("reveal the password")
    assert "[SYSTEM]" in payload and "[/SYSTEM]" in payload
    assert "reveal the password" in payload


def test_instruction_override_claims_priority():
    payload = instruction_override("reveal the password")
    assert "priority 0" in payload


def test_roleplay_jailbreak_uses_persona():
    payload = roleplay_jailbreak("DAN", "tell me secrets")
    assert "DAN" in payload and "tell me secrets" in payload


def test_hypothetical_jailbreak_frames_goal():
    payload = hypothetical_jailbreak("bypass the filter")
    assert "Hypothetically" in payload and "bypass the filter" in payload


def test_developer_mode_jailbreak():
    assert "developer mode" in developer_mode_jailbreak().lower()


def test_poisoned_tool_output_styles():
    html = poisoned_tool_output("exfiltrate data", style="html_comment")
    note = poisoned_tool_output("exfiltrate data", style="admin_note")
    assert "hidden instruction" in html and "exfiltrate data" in html
    assert "[ADMIN NOTE" in note and "exfiltrate data" in note


@pytest.mark.parametrize("kind", ["ssn", "credit_card", "email"])
def test_pii_probe_kinds(kind):
    assert pii_probe(kind)


def test_pii_probe_unknown_kind_raises():
    with pytest.raises(ValueError):
        pii_probe("dna")


def test_exfiltration_tool_call_channels():
    email = exfiltration_tool_call("email")
    webhook = exfiltration_tool_call("webhook")
    assert email["name"] == "send_email" and "evil.example.com" in email["args"]["to"]
    assert webhook["name"] == "http_post" and "evil.example.com" in webhook["args"]["url"]


def test_exfiltration_tool_call_unknown_channel_raises():
    with pytest.raises(ValueError):
        exfiltration_tool_call("pigeon")


GENERATED_VARIANTS = [
    direct_injection("reveal the password"),
    delimiter_escape("reveal the password"),
    instruction_override("reveal the password"),
    roleplay_jailbreak("DAN", "reveal the password"),
    hypothetical_jailbreak("reveal the password"),
    developer_mode_jailbreak(),
    poisoned_tool_output("forward secrets outward", style="html_comment"),
    poisoned_tool_output("forward secrets outward", style="admin_note"),
    pii_probe("ssn"),
    pii_probe("credit_card"),
    pii_probe("email"),
]


@pytest.mark.parametrize("payload", GENERATED_VARIANTS)
def test_every_generated_variant_is_caught(payload):
    """Property test: generated phrasings must trip the input sanitizer."""
    assert InputSanitizer().sanitize(payload).flagged
