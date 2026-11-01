# Tech Debt & Compromises

- **Caller-Declared Trust**: Currently, agents can claim a URL is `trusted`, bypassing taint tracking. Must be moved to a `trusted_origins` list on the Mandate.
- **Judge inside Transaction**: The LLM judge runs inside the SQLite write transaction, locking the DB for up to 20 seconds. Vulnerable to race conditions/kill-switch bypass.
- **Float Validation**: `NaN` or `.005` amounts crash the engine or create execution mismatches.
- **Cosine N-Grams for Emails**: Currently fails on TLD swaps and padded subdomains. Needs edit-distance.
- **Audit File I/O**: `AuditLog` re-reads the entire file on every append. $O(N^2)$ scaling bottleneck.