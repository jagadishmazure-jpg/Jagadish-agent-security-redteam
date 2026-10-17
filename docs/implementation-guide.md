# Implementation guide: from offline build to Azure

> Status: **planned**. Nothing here has been deployed. The offline build in this
> repository is what exists today; this guide is how it would be taken to a
> real Azure environment.

## Azure service mapping

| Offline component | Azure service (planned) | Notes |
|---|---|---|
| InputSanitizer | Azure AI Content Safety Prompt Shields | Keep the pattern layer as a backstop |
| OutputGuardrail | Azure AI Content Safety text moderation + groundedness |  |
| PIIScrubber | Azure AI Language PII detection |  |
| ToolCallPolicy | APIM policies and managed identity scopes per tool |  |
| Harness | Azure AI Foundry evaluation runs or a CI job against a staging endpoint |  |

## Steps

1. Point the harness at a staging agent endpoint instead of the fake agent.
2. Add Prompt Shields ahead of the sanitizer and compare catch rates.
3. Enforce tool policy at the gateway (APIM), not only in agent code.
4. Run the suite on every model or prompt change and track the weighted risk score.

## Guardrails to keep when going live

- Defence in depth: four layers that work independently.
- Tool allowlist; email only to allowlisted domains; file reads confined to a sandbox root; path traversal rejected.
- Cloud metadata endpoint and known attacker hosts are refused.
- A benign corpus is tested so defences do not block normal requests.
- An integration test asserts every catalogued attack is blocked by at least one layer.

## What to measure before calling it production-ready

- Attack success rate and weighted risk score per release.
- False positive rate on a larger benign corpus.
- Attacks caught only by one layer (single points of failure).
