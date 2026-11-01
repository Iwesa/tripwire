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
- Payee lookalikes use cosine similarity over normalized character n-gram vectors. This catches spelling variants, not
  conceptually related names or paraphrased payees; the allowlist remains decisive.
- Taint tracking is string provenance (payee/amount echoed from untrusted text). A paraphrased or encoded payee evades it;
  the allowlist still blocks it.
- `sources` are reported by the agent SDK. A fully compromised agent could omit them; deterministic rules still hold.
- SQLite persists mandates, tickets, spend, and velocity state across restarts. SQLite serializes write transactions
  database-wide; higher-concurrency deployments should use a database with row-level locking.
- Audit HMACs detect modification of signed entries, but truncating or rolling back the entire file requires an
  external checkpoint or remote anchor to detect.
- Prototype for the sandbox. Not a production payment-control product.
