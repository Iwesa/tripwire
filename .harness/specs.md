# Hardening Specs for Tripwire - Phase 2 (Async & Security Edge)

## Unit 1: Asynchronous I/O Refactor
[x] Plan tests for async HTTP clients.
[x] Refactor `backend/app/judge.py` to use `httpx.AsyncClient` instead of the synchronous `urllib.request`.
[x] Refactor `backend/app/paypal.py` to use `httpx.AsyncClient` for all PayPal sandbox calls.
[x] Update FastAPI routes in `backend/app/main.py` to `async def` and `await` the executor and judge responses to prevent event loop blocking.

## Unit 2: Edge Rate Limiting & Auth Validation
[ ] Plan tests for rate limiting and edge authentication.
[ ] Install `slowapi` and add a rate limiter to `backend/app/main.py` (e.g., 50 requests/minute per IP or `agent_id`) to protect `/gateway/tool-call`.
[ ] Update `backend/app/main.py` to strictly enforce the authentication logic currently evaluated in `backend/tests/test_auth.py`. Use FastAPI `Depends()` for the API key/token.

## Unit 3: Advanced Injection Defense
[ ] Plan tests verifying evasion defense against zero-width spaces and base64 payloads.
[ ] Refactor `backend/app/injection.py` to replace regex heuristics with an ML-based text classification pipeline (e.g., local HuggingFace `pipeline("text-classification")` or Lakera Guard API).
[ ] Verify `backend/tests/test_redteam.py` remains green and catches advanced obfuscation techniques.

## Unit 4: Audit Log Scalability
[ ] Plan tests for audit log rotation or DB storage.
[ ] Update `backend/app/audit.py` to implement file rotation (e.g., daily or size-based rotation) to prevent `.jsonl` I/O bottlenecks.
[ ] *Alternative to rotation:* Migrate the hash-chained audit ledger entirely into the new persistent layer defined in `backend/app/storage.py`. Ensure `verify()` logic still holds cryptographic integrity.