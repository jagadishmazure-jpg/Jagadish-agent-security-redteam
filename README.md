# Jagadish Agent Security Redteam

[![CI](https://github.com/jagadishmazure-jpg/Jagadish-agent-security-redteam/actions/workflows/ci.yml/badge.svg)](https://github.com/jagadishmazure-jpg/Jagadish-agent-security-redteam/actions/workflows/ci.yml)
![Python 3.12](https://img.shields.io/badge/python-3.12-blue)
![Tests](https://img.shields.io/badge/tests-206%20passing-brightgreen)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

Agentic AI red-teaming **as code**: a versioned **attack catalog**, **layered
defenses**, a deterministic **harness** that runs the suite against a fake
target agent, and **risk scoring** with Markdown reports.

Everything runs offline — no model APIs, no network, no keys. The fake agent
is deliberately naive so every attack has a verifiable success condition;
the defenses are what make the suite go green.

## Quickstart

```bash
pip install -e ".[dev]"
python -m pytest -q
```

## How it works

```
user input ──▶ InputSanitizer ──▶ FakeTargetAgent ──▶ OutputGuardrail ──▶ user
                      │                                        ▲
tool output ──────────┘                                        │
                                                               │
tool call ───▶ ToolCallPolicy ──▶ FakeTargetAgent ─────────────┘
text ────────▶ PIIScrubber (redacts PII anywhere text leaves the system)
```

1. **Attacks** (`redteam/attacks/`) — 19 catalogued attacks as data
   (`catalog.py`) plus payload generators (`generators.py`) that fuzz new
   phrasings of each technique: prompt injection, jailbreaks, tool abuse,
   data exfiltration.
2. **Defenses** (`redteam/defenses/`) — four independent layers: input
   sanitizer, output guardrail, tool-call policy, PII scrubber.
3. **Harness** (`redteam/harness/`) — runs every attack through the layers
   against the fake agent and records per-attack outcomes (`blocked_by`,
   `succeeded`).
4. **Scoring** (`redteam/scoring/`) — attack success rate, severity-weighted
   risk score, per-category breakdowns, Markdown reports.

Every attack is stopped by at least one layer (asserted by
`tests/test_integration.py`). Threat model: [docs/threat-model.md](docs/threat-model.md).

## Project structure

```
redteam/
  attacks/     versioned attack catalog (19 techniques) + payload generators
  defenses/    input sanitizer, output guardrail, tool-call policy, PII scrubber
  harness/     deterministic runner: every attack vs every layer
  scoring/     success rates, severity-weighted risk, markdown reports
docs/          threat-model.md
tests/         206 offline pytest tests
```

## Tests & CI

**206 tests, all passing, fully offline.** GitHub Actions runs the suite on
every push and pull request (Python 3.12). Releases ship to PyPI from version
tags (`v*`) via trusted publishing — see `.github/workflows/release.yml`
(add manually; workflow files can't be pushed via the GitHub API).

## Portfolio

Part of an agentic-AI engineering portfolio by
[jagadishmazure-jpg](https://github.com/jagadishmazure-jpg):

| Repo | What it is | Tests |
|---|---|---|
| [Jagadish-multi-agent-orchestration](https://github.com/jagadishmazure-jpg/Jagadish-multi-agent-orchestration) | Orchestration patterns as code | 124 |
| **This repo** | Red-teaming suite: attack catalog, layered defenses, risk scoring | 206 |
| [Jagadish-llm-evals-observability](https://github.com/jagadishmazure-jpg/Jagadish-llm-evals-observability) | LLM evals + observability as code | 111 |
| [Jagadish-ingredion-agentic-ai](https://github.com/jagadishmazure-jpg/Jagadish-ingredion-agentic-ai) | End-to-end multi-agent platform (Microsoft Agent Framework 1.0) + live demo | 564 |

## License

MIT — see [LICENSE](LICENSE).
