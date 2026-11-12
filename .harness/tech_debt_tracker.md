# Tech Debt & Compromises

## Resolved

- [x] Caller-declared source trust is replaced by mandate-controlled `trusted_origins`.
- [x] The LLM judge runs before the write transaction; policy is re-evaluated against the stored mandate during admission.
- [x] API payment amounts reject non-finite, non-positive, and over-precision values.
- [x] Payee lookalike detection uses local-part edit distance and exact domain matching.
- [x] Audit appends cache file state and the current chain head instead of re-reading the persisted log on every append.

## Open

- **Audit append verification remains O(N)**: appends reuse cached file contents, but still verify the in-memory chain before writing. A verified-head strategy could reduce this cost, with careful handling of external file edits.
- **PayPal timeout reconciliation**: if PayPal accepts a payout but the response is lost, the reservation is released and a retry could pay twice. Reconciliation is not implemented.
