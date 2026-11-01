# Hardening Specs for Tripwire

## Unit 1: State Persistence & Concurrency Control
[x] Plan tests for persistent storage replacing in-memory dictionaries.
[x] Migrate `mandates`, `tickets`, `_spent`, and `_times` in `backend/app/main.py` and `policy.py` to SQLite (via SQLAlchemy or asyncpg).
[x] Implement row-level locking or atomic updates for budget and velocity tracking to prevent TOCTOU race conditions.
[x] Verify all tests in `test_core.py` pass with the new database backend.

## Unit 2: Zero-Trust Access Control
[x] Plan tests for API authentication.
[x] Add API key requirement (header `X-Agent-Key`) for `/gateway/tool-call`.
[x] Add strong token auth for admin endpoints (`/mandates`, `/approvals`).
[x] Update `agent/demo_agent.py` to pass the necessary auth headers.

## Unit 3: Immutable Asynchronous Auditing
[x] Refactor `backend/app/audit.py` to use `asyncio` for non-blocking disk/network writes.
[x] Upgrade SHA-256 hash-chaining to include HMAC signing using a private key defined in `.env`.
[x] Write a test verifying that manual edits to `audit.jsonl` trigger an HMAC verification failure.

## Unit 4: Robust Evasion Defense
[x] Plan tests for advanced prompt injection evasion (e.g., zero-width spaces, base64 encoding).
[x] Replace regex in `injection_signals` (`backend/app/policy.py`) with an ML-based classifier integration (e.g., Lakera Guard API or local HuggingFace pipeline).
[x] Upgrade `lookalike_of` to use vector-based semantic similarity instead of `difflib`.
[x] Verify `test_redteam.py` remains green and catches advanced obfuscation.