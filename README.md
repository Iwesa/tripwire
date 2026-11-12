# Tripwire

[![CI](https://github.com/Iwesa/tripwire/actions/workflows/ci.yml/badge.svg)](https://github.com/Iwesa/tripwire/actions/workflows/ci.yml)

**A spend firewall for AI agents.** Agents can now move money; one poisoned web page can redirect it.
Tripwire sits between an agent and PayPal and decides, deterministically, whether each payment may happen.

> Prototype for the PayPal AI Hackathon. **PayPal sandbox only.** Not a production payment-control product.

## What it does

An agent calls `POST /gateway/tool-call` instead of calling PayPal. Tripwire checks the call against the **mandate** a
human gave that agent, then answers:

| Outcome | HTTP | What happens |
|---|---|---|
| **allow** | 200 | The payment executes and is recorded |
| **escalate** | 202 | A human approval ticket is created; budget is held until it is approved, rejected or expires (24 h) |
| **deny** | 403 | Nothing executes. The attempt and the reasons are written to the audit log |

Every policy decision, including every denial, is written to the audit log before the response is sent.

### How a call is decided

1. **Hard gates:** kill switch, mandate expiry, allowed tools.
2. **Money rules:** per-payment cap, total budget, payments per hour, currency, well-formed amounts.
3. **Payee rules:** approved-payee allowlist (or approval for new payees), same-domain lookalike detection, non-ASCII payees.
4. **Provenance:** did the payee or amount come from untrusted content? Which sources are trusted is set by the
   mandate (`trusted_origins`), never by the caller.
5. **Prompt-injection signals:** local pattern checks, with optional Lakera Guard (see limitations).
6. **LLM judge (optional):** can only tighten a verdict, never loosen it, and fails closed.

The decisive controls (caps, allowlist, budget, velocity, kill switch) do not depend on recognizing the attack.

### Agent identity

An agent's identity is derived **only from its API key** (`agent-` plus a hash of `X-Agent-Key`). Any `agent_id` in a
request body is ignored, so a caller cannot borrow another agent's mandate by naming it. One configured key means one
agent identity.

### Budget and the kill switch

Budget and velocity are reserved in one SQLite write transaction, and the reservation **re-reads the stored mandate**
inside that transaction. A revocation, expiry or limit change committed while a request was being evaluated (for
example while the LLM judge was thinking) still blocks that request.

### Audit log

An HMAC-signed, hash-chained JSONL log. Verification covers the whole chain across rotated segments. The dashboard's
Audit tab and `GET /audit/verify` re-check it.

## Quickstart

```bash
cd backend && python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
cp ../.env.example .env     # set three different random secrets (openssl rand -hex 32); keep TRIPWIRE_MODE=dry offline
python3 -m unittest discover -s tests -t .                      # unit, integration and red-team tests
uvicorn app.main:create_app --factory --reload                  # http://localhost:8000/docs
```

On Windows PowerShell, set variables with `$env:NAME = "value"` instead of loading `.env`.

### Run the demo (from the repo root, with the same environment loaded in each terminal)

```bash
python3 agent/evil_site.py                          # a vendor page with a hidden "change the bank details" note
python3 agent/demo_agent.py setup                   # creates the mandate for the agent derived from TRIPWIRE_AGENT_API_KEY
python3 agent/demo_agent.py run --direct --naive    # without Tripwire the agent pays the attacker
python3 agent/demo_agent.py run --guarded --naive   # through Tripwire the same payment is denied (403) and audited
```

`setup` needs `TRIPWIRE_ADMIN_TOKEN` and `TRIPWIRE_AGENT_API_KEY`. The dashboard shows the agent as `agent-<hash>`.

### Dashboard

```bash
cd tripwire-dashboard && npm install && npm run dev        # http://localhost:5173
```

Enter the API address and `TRIPWIRE_ADMIN_TOKEN` (kept in memory only). Tabs: **Activity** (every decision, including
blocked attacks), **Approvals**, **Agents** (spend bars and a two-step kill switch) and **Audit record**.

### Configuration

All settings are in `.env.example`. Set distinct random values of at least 32 bytes for `TRIPWIRE_AGENT_API_KEY`,
`TRIPWIRE_ADMIN_TOKEN` and `TRIPWIRE_AUDIT_HMAC_KEY`; missing credentials fail closed. The gateway allows 50 requests per
minute per client IP (HTTP 429); behind a reverse proxy, check that the limiter sees the real client address.

## Evidence

`backend/evals/redteam_cases.json` is the specification: attack and benign cases with expected verdicts, run by
`tests/test_redteam.py`, which also checks that each rule on its maintained list is needed to produce an expected
verdict. `tests/test_gateway_hardening.py` covers audited denials, key-only identity and the stale-mandate race.
CI runs the backend tests and the dashboard build on every push.

## Known limitations

Stated plainly, because they matter more than the feature list.

- **Detection is heuristic.** Injection patterns are evadable and can flag ordinary invoice wording ("please pay
  immediately"), which escalates for human review rather than denying. With `LAKERA_API_KEY` set, the gateway
  currently treats every untrusted source as a classifier error and escalates it; leave the key unset until that path
  is fixed.
- **Lookalikes are narrow.** Detection compares the local part when the domain is identical. Domain impersonation
  (`acme-suppliers.com`) is not flagged as a lookalike; in `allowlist` mode any non-allowlisted payee is still denied.
- **Taint tracking is literal.** An obfuscated payee in untrusted text (HTML entities, `[at]`, encoded) is not matched.
  The allowlist still blocks it.
- **`sources` are reported by the agent.** A compromised agent can omit them; the deterministic rules still hold.
- **A timeout is not a failure.** If PayPal accepts a payout but the response is lost, the reservation is released and
  a retry could pay twice. Reconciliation is not implemented.
- **The audit log cannot detect rollback.** Editing entries is detected; removing the newest entries or deleting the
  file is not, without an external checkpoint. Appending also re-verifies the chain, so cost grows with log size.
- **One key is one agent.** Per-agent keys are not implemented.
- **SQLite serializes writes**, which is fine for a demo, not for high concurrency.

## License

MIT (see LICENSE).
