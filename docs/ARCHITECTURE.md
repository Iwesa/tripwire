# Tripwire architecture

```
 Untrusted world            Agent (any framework)              Tripwire                         PayPal sandbox
 web pages, emails  --->  reads, plans, proposes  --->  POST /gateway/tool-call  --->  Payouts / Orders / Refunds
                          tool call + `sources`        |  1 hard gates (kill switch, expiry, tool)
                          (what it read)               |  2 money rules (cap, budget, velocity, currency)
                                                       |  3 payee rules (allowlist, lookalike)
                                                       |  4 provenance / taint (payee came from a web page?)
                                                       |  5 LLM judge (tighten-only, fail-closed)
                                                       |  => ALLOW (execute) | ESCALATE (human ticket) | DENY (403)
                                                       |  every step -> hash-chained audit log
                                                       +-> React dashboard: live feed, approvals, kill switch, verify
```

## The two harness layers
Tripwire is a harness twice over, and that is the project's thesis:
- **Build-time harness** (`.harness/`, `CLAUDE.md`): hooks block live-PayPal/secret access and gate "done" on a green suite;
  skills hold the eval-first workflow; a fresh-context `reviewer` subagent checks invariants.
- **Run-time harness** (`backend/app/`): the same idea applied to the *agent you deploy*. Prompts and system messages are
  advice an attacker can talk around; Tripwire is the hook layer that cannot be talked around.

## Harness principle -> where it lives
| Principle | Tripwire implementation |
|---|---|
| Hooks enforce, instructions only suggest | Policy engine decides deterministically; "never pay unknown payees" is code, not a prompt line |
| Guides (feed-forward) + sensors (feedback) | Mandate = guide; audit log + red-team evals = sensors |
| Fail closed | Judge error / bad JSON / missing amount or payee => ESCALATE or DENY |
| Least privilege / scoped permissions | Mandate: tools, payees, per-tx cap, budget, TTL; `.harness/settings.json` deny rules for the builder |
| Every rule traces to a real failure | `redteam_cases.json` + `test_every_rule_is_necessary` (mutation check) |
| Measure, don't vibe | Scoreboard test: attacks blocked N/N, benign wrongly denied 0 |
| Independent review with fresh context | `.harness/agents/reviewer.md`; judge sees untrusted text as quoted data only |
| Observability | Async append to an HMAC-signed SHA-256 chain, verify endpoint, dashboard |
| Non-blocking external checks | HTTPX async clients for the LLM judge, injection classifier, and PayPal sandbox |
| Edge protection | Agent-key and admin-token dependencies; gateway limited to 50 requests/minute per client IP |

## Known limitations (say these in the README; judges respect honesty)
- Prompt-injection detection normalizes zero-width characters and decodes Base64 before applying local heuristics.
  Configuring `LAKERA_API_KEY` also sends the original excerpt plus normalized and decoded variants to Lakera Guard
  classification; without it, detection remains heuristic and evadable. Classifier errors escalate affected payments.
  The *decisive* controls (caps, allowlist, budget, velocity, kill switch) do not depend on detecting the attack, which
  is the point.
- Payee lookalike detection compares the local part (edit distance) only when the domain is identical, and rejects
  non-ASCII payees. Domain impersonation is not detected as a lookalike; the allowlist remains decisive.
- Taint tracking is string provenance (payee/amount echoed from untrusted text). A paraphrased or encoded payee evades it;
  the allowlist still blocks it.
- `sources` are reported by the agent SDK. A fully compromised agent could omit them; deterministic rules still hold.
- SQLite persists mandates, tickets, spend, and velocity state across restarts. SQLite serializes write transactions
  database-wide; higher-concurrency deployments should use a database with row-level locking.
- Persisted audit logs rotate into numbered JSONL segments before an append would exceed the 10 MiB size threshold (a
  single oversized event may exceed it). Verification checks the continuous HMAC/hash chain across all segments;
  segments are retained indefinitely. HMACs detect modification of existing entries. They cannot detect removal of the
  newest entries (a valid prefix still verifies) or deletion of the whole log; that needs an external checkpoint.
  Each append re-verifies the chain, so its cost grows with log size.
- Identity comes only from the agent API key; a request's `agent_id` is ignored. One configured key is one agent.
- The budget reservation re-reads the stored mandate inside its write transaction, so a revocation committed while a
  request was in flight still blocks it. Every decision, including denials, is audited before the response is sent.
- A timeout after PayPal accepted a payout releases the reservation, so a retry could pay twice. Reconciliation is not
  implemented.
- Prototype for the sandbox. Not a production payment-control product.
