# Jagadish Agent Security Redteam

Agentic AI red-teaming as code: a versioned **attack catalog**, **layered
defenses**, a deterministic **harness** that runs the suite against a fake
target agent, and **risk scoring** with Markdown reports.

Everything runs offline — no model APIs, no network, no keys. The fake agent
is deliberately naive so every attack has a verifiable success condition;
the defenses are what make the suite go green.

## Quickstart

```bash
# with uv
uv sync --group dev        # or: uv pip install -e ".[dev]"

# without uv
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
   phrasings of each technique.
2. **Defenses** (`redteam/defenses/`) — four independent layers: input
   sanitizer, output guardrail, tool-call policy, PII scrubber.
3. **Harness** (`redteam/harness/`) — runs every attack through the layers
   against the fake agent and records per-attack outcomes (`blocked_by`,
   `succeeded`).
4. **Scoring** (`redteam/scoring/`) — attack success rate, severity-weighted
   risk score, per-category breakdowns, Markdown reports.

## Attack / defense matrix

Every attack is stopped by at least one layer (asserted by
`tests/test_integration.py`):

| Attack | Category | Severity | Caught by |
| --- | --- | --- | --- |
| pi-direct-ignore | prompt_injection | high | input_sanitizer |
| pi-delimiter-escape | prompt_injection | high | input_sanitizer |
| pi-instruction-override | prompt_injection | critical | input_sanitizer |
| pi-fake-assistant-turn | prompt_injection | medium | input_sanitizer |
| pi-translation-smuggle | prompt_injection | medium | input_sanitizer |
| pi-base64-decode | prompt_injection | high | input_sanitizer |
| jb-roleplay-dan | jailbreak | high | input_sanitizer |
| jb-hypothetical | jailbreak | medium | input_sanitizer |
| jb-developer-mode | jailbreak | high | input_sanitizer |
| jb-grandma-story | jailbreak | medium | input_sanitizer |
| ii-poisoned-search | indirect_injection | critical | input_sanitizer |
| ii-poisoned-doc | indirect_injection | high | input_sanitizer |
| ta-exfil-email | tool_abuse | critical | tool_call_policy |
| ta-exfil-webhook | tool_abuse | critical | tool_call_policy |
| ta-path-traversal | tool_abuse | high | tool_call_policy |
| ta-ssrf-metadata | tool_abuse | high | tool_call_policy |
| pii-ssn-probe | pii_extraction | high | input_sanitizer |
| pii-cc-probe | pii_extraction | high | input_sanitizer |
| pii-email-harvest | pii_extraction | medium | input_sanitizer |

## Running the suite

```bash
python -m pytest -q            # full suite
python -m pytest tests/test_integration.py -q   # end-to-end guarantee
```

Generate a sample report:

```python
from redteam.harness import RedTeamHarness
from redteam.scoring import render_markdown_report

outcomes = RedTeamHarness().run_all()
print(render_markdown_report(outcomes))
```

## Project structure

```
redteam/
  attacks/     catalog.py (attack data) · generators.py (payload fuzzing)
  defenses/    sanitizer.py · guardrail.py · tool_policy.py · pii_scrubber.py
  harness/     fake_agent.py (naive target) · runner.py (suite execution)
  scoring/     metrics.py (ASR, weighted risk) · report.py (markdown)
tests/         200+ offline pytest tests
docs/          threat-model.md
```

See [`docs/threat-model.md`](docs/threat-model.md) for the threat model this
suite exercises.

## License

MIT — see [LICENSE](LICENSE).
