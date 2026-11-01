# Tech Debt & Compromises

- **Regex Injection Defense**: `backend/app/injection.py` still relies on regex heuristics. Highly evadable. Scheduled for ML classifier replacement in Phase 2, Unit 3.
- **Audit Log I/O**: `backend/app/audit.py` continuously appends to a single `audit.jsonl` file. This is an I/O bottleneck and doesn't scale. Scheduled for rotation/DB migration in Phase 2, Unit 4.
- **Taint Tracking**: String provenance relies on exact matches. Paraphrased taint will evade it. (Acceptable risk until ML taint tracking is implemented).