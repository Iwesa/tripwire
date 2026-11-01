# Tripwire Harness Router

You are an AI agent working on Tripwire, a spend firewall for AI agents. Do not guess project rules. Read the referenced files.

## Routing Directory
- **Current Tasks & Checkboxes**: Read `.harness/specs.md`
- **Architecture & Invariants**: Read `docs/ARCHITECTURE.md`
- **Known Compromises & Debt**: Read `.harness/tech_debt_tracker.md`
- **Blockers & Handbrake**: If you cannot proceed, write to `.harness/blocked.md` and STOP.
- **Learnings & Edge Cases**: Read `.harness/learnings.md`
- **Automated Engine**: Triggered via `.harness/loop_prompt.md`

## Base Rules
1. Never modify code without first writing a test in `backend/tests/`.
2. Do not fix failing builds manually; fix the instructions or specs that caused them.
3. If an external service (e.g., PayPal Sandbox) is down, do not hallucinate a fix. Use `blocked.md`.