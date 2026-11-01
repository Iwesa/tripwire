# Agent Learnings & Generalizations

- *2026-10-27*: Pydantic validation errors on `/gateway/tool-call` occur if `amount` is missing. Ensure the agent schema always sends `amount` as a string, not a float, to prevent serialization precision issues.
- *2026-11-01*: Calling FastAPI route functions directly bypasses `Depends`; auth tests should inspect route dependency wiring as well as credential checks.
- *(Agent: Append new edge cases and generalized findings here after resolving complex bugs)*