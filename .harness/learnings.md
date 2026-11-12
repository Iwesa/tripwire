# Agent Learnings & Generalizations

- *2026-10-27*: Pydantic validation errors on `/gateway/tool-call` occur if `amount` is missing. Ensure the agent schema always sends `amount` as a string, not a float, to prevent serialization precision issues.
- *2026-11-01*: Calling FastAPI route functions directly bypasses `Depends`; auth tests should inspect route dependency wiring as well as credential checks.
- *2026-11-12*: A mandate read before a slow judge is stale for every policy field, not only revocation and budget limits. Re-evaluate the full deterministic policy against the stored mandate and current accounting inside the reservation transaction, including recalculating source trust from current trusted origins.
- *(Agent: Append new edge cases and generalized findings here after resolving complex bugs)*