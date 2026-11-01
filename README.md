# Tripwire

**A spend firewall for AI agents.** Agents can now move money; one poisoned web page can redirect it.
Tripwire sits between any agent and PayPal and decides - deterministically - whether each payment may happen.

> Status: prototype for the PayPal AI Hackathon. **PayPal sandbox only.**

## How it decides
Hard gates (kill switch, expiry, tool scope) -> money rules (per-tx cap, budget, velocity, currency) -> payee rules
(allowlist, vector-based lookalike detection) -> provenance/taint (did the payee come from untrusted content?) ->
prompt-injection detection -> LLM judge
(can only *tighten* a verdict, fails closed). Every step is written to an asynchronously persisted, HMAC-signed SHA-256 chain.
Outcomes: **allow** (executes), **escalate** (human approval ticket), **deny** (HTTP 403).

Prompt-injection detection normalizes zero-width characters and inspects decodable Base64 text. Set `LAKERA_API_KEY`
to enable Lakera Guard classification; source excerpts are sent to Lakera when enabled, and a classifier error escalates
the payment. Without a key, the local normalization and pattern checks still run, but are heuristic and can be evaded.
Payee lookalikes are compared using cosine similarity over normalized character n-gram vectors; this targets spelling
variants, not conceptual aliases.

## State
Mandates, approval tickets, spend totals, and velocity events persist in SQLite. The default database is
`tripwire.db` in the backend working directory; set `TRIPWIRE_DATABASE_URL` to choose another SQLAlchemy SQLite URL.
Budget and velocity are checked and reserved in one SQLite write transaction before an action executes. Failed
execution releases its reservation.

## Authentication
Set distinct random values of at least 32 bytes for `TRIPWIRE_AGENT_API_KEY`, `TRIPWIRE_ADMIN_TOKEN`, and
`TRIPWIRE_AUDIT_HMAC_KEY` in `backend/.env`. Keep the audit key stable across restarts; a persisted log requires it
to verify existing entries. The gateway requires `X-Agent-Key`; mandate, approval, state, and audit routes require
`X-Admin-Token`. Missing server credentials fail closed. Load `backend/.env` into both the API and demo-agent
terminal environments before running the quickstart commands.

## Quickstart
```bash
cd backend && python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
cp ../.env.example .env            # add sandbox creds; leave TRIPWIRE_MODE=dry to run offline
# Generate three independent secrets with `openssl rand -hex 32`, then load .env in this and the demo terminal.
python3 -m unittest discover -s tests -t .      # 50 tests incl. the red-team evals
uvicorn app.main:app --reload                   # http://localhost:8000/docs
# in other terminals, from repo root:
python3 agent/evil_site.py
python3 agent/demo_agent.py setup
python3 agent/demo_agent.py run --direct --naive   # attack succeeds without Tripwire
python3 agent/demo_agent.py run --guarded --naive  # same attack, denied
```

## Evidence, not claims
`backend/evals/redteam_cases.json` is the spec. `test_every_rule_is_necessary` disables each rule in turn and requires an
eval case to change verdict, so no rule is decorative. See `docs/ARCHITECTURE.md` for design and known limitations.

## License
MIT (see LICENSE).
