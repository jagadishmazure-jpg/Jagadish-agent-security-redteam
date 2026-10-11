# Threat model: agentic AI systems under test

This document describes the threat model that the red-team suite in this
repository exercises. It follows a simple assets → actors → surfaces →
mitigations structure.

## Assets

| Asset | Why it matters |
| --- | --- |
| System prompt / instructions | Leakage reveals behavior controls and embedded secrets |
| User PII (SSN, card numbers, emails) | Extraction enables fraud and identity theft |
| Tool credentials / API keys | Tool abuse can pivot into infrastructure |
| Tool execution itself | SSRF, path traversal, and exfiltration turn the agent into an attacker proxy |
| Data integrity | Indirect injection makes the agent act on untrusted content |

## Threat actors

* **Malicious user** — crafts prompt injections and jailbreaks in direct input.
* **Compromised third party** — poisons tool outputs, documents, or web content
  the agent retrieves (indirect injection).
* **Curious insider** — probes for PII or secrets the agent can see but should
  never repeat.

## Attack surfaces

1. **User input channel** — prompt injection, jailbreak templates, PII probes.
2. **Tool output channel** — indirect prompt injection via retrieved content.
3. **Tool invocation channel** — exfiltration through tool arguments, SSRF,
   path traversal, use of non-allowlisted tools.
4. **Agent output channel** — the last place a compromise becomes visible
   (leaked secrets, attacker-directed content).

## Mitigations (defense in depth)

| Layer | Covers | Module |
| --- | --- | --- |
| Input sanitizer | Surfaces 1 + 2 — flags injection, jailbreak, and PII-probe patterns in user input *and* tool output | `redteam/defenses/sanitizer.py` |
| Tool-call policy | Surface 3 — allowlisted tools, approved email domains, sandbox-confined file reads, blocked metadata/attacker URLs | `redteam/defenses/tool_policy.py` |
| PII scrubber | Surfaces 1 + 4 — redacts SSN, card numbers, emails, phones from text before it leaves the system | `redteam/defenses/pii_scrubber.py` |
| Output guardrail | Surface 4 — blocks compromise markers, leaked secrets, and disallowed instructions in final output | `redteam/defenses/guardrail.py` |

No single layer is trusted alone: the harness test suite asserts that every
catalog attack is stopped by *at least one* layer, and that benign traffic
passes all layers without false positives.

## Residual risks / out of scope

* Adaptive attackers who rephrase beyond the pattern set (mitigated in part by
  the payload generators, which fuzz phrasings).
* Model-level vulnerabilities (the fake target agent stands in for a real LLM;
  point the harness at a real agent to measure those).
* Supply-chain compromise of the agent's own dependencies.
* Human social engineering outside the agent's channels.
