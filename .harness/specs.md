# Hardening Specs for Tripwire - Core Logic & Evasion

## Unit 1: The API Boundary & Validation
[x] **Amount Validation:** Update `ToolCallIn` in `backend/app/main.py` and `backend/app/models.py`. Ensure amounts are cast to `Decimal`, verified as `is_finite()`, strictly `> 0`, and quantized to exactly 2 decimal places (`.quantize(Decimal('0.01'))`). Add tests catching `NaN` and `10.005`.
[x] **Agent Identity Auth:** Require an `X-Agent-Key` header in `/gateway/tool-call`. The `agent_id` must be derived from this key, ignoring any `agent_id` in the JSON payload.
[x] **Trust is Mandate-Declared:** Update `Mandate` to include a `trusted_origins` list. In `main.py`, forcefully overwrite the `trust` field of all incoming `sources` to `"untrusted"` UNLESS the source URL exactly matches an origin in `trusted_origins`.

## Unit 2: Concurrency & Idempotency (The TOCTOU Fix)
[x] **Kill-switch TOCTOU:** Refactor the `/gateway/tool-call` endpoint in `main.py`. The execution order MUST be: 1) Deterministic policy check. 2) LLM Judge (SLOW - outside DB transaction). 3) Open DB Transaction (`BEGIN EXCLUSIVE`). 4) Re-fetch mandate and verify `revoked == False`. 5) Update budget. 6) Close transaction. 7) Execute PayPal call.
[x] **Idempotency Keys:** Update `paypal.py` to derive `PayPal-Request-Id` deterministically from the internal `ticket_id` or `reservation_id` (e.g., `hash(ticket_id + retry_count)`). 
[x] **Ticket Expiry:** Add `expires_at` to the `Ticket` model. Add logic so pending tickets older than 24 hours automatically release their budget reservations.

## Unit 3: Policy Engine Resilience
[x] **Lookalike Regression:** Revert lookalike detection in `policy.py` to use Levenshtein (edit distance) for the local part of the email, and strict exact-matching for the domain part. Reject non-ASCII payees unless exactly allowlisted.
[x] **Taint Evasion:** Add a sanitization pipeline in `policy.py` before `injection_signals`. Strip zero-width characters, unquote URL encodings (`%40` to `@`), resolve HTML entities (`&#64;`), and normalize whitespace/casing.
[x] **False Positive Compound Triggers:** Modify the LLM judge/policy logic: An injection escalation should only fire if an injection phrase co-occurs with a tainted payee or amount (e.g., `(urgency OR override) AND tainted_data`).

## Unit 4: Evals, Coverage & Scale
[x] **Audit Caching:** Update `AuditLog` in `audit.py`. Cache the `head_hash` in memory/SQLite. Upon appending, only hash the new entry against the known head instead of re-reading the entire file.
[x] **Benign Evals:** Add at least 30 new realistic benign invoice phrasings to `backend/evals/redteam_cases.json`.
[x] **Necessity Test Coverage:** Update `test_every_rule_is_necessary` in `test_redteam.py` to ensure all 20 rules (including the 6 currently missing) are mapped to test cases.