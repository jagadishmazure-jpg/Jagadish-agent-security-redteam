# Interview points

Short, honest talking points for Jagadish-agent-security-redteam. Every number quoted is from the
real run shown in the README.

- Attacks are data with a success condition, so security becomes a regression suite.
- Layers are independent: in the run, 15 attacks stop at input and 4 at the tool policy.
- I test the benign side too; defences that block normal work get switched off.
- Honest limit: 0% success is against my own catalogue, not a guarantee.

## Likely follow-up questions

- How do you handle indirect injection? (Treat tool output as untrusted input and sanitise it.)
- Why a fake agent? (Deterministic success conditions; a live model is the next step.)
- What would you add first in production? (Gateway-enforced tool policy and Prompt Shields.)
