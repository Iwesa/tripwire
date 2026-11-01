# Tech Debt & Compromises

- **Injection Detection Fallback**: Lakera Guard classification is optional and receives original, normalized, and decodable Base64 text when configured. Without `LAKERA_API_KEY`, local pattern checks remain heuristic and can be evaded; classifier failures escalate affected payments.
- **Audit Log I/O**: `backend/app/audit.py` continuously appends to a single `audit.jsonl` file. This is an I/O bottleneck and doesn't scale. Scheduled for rotation/DB migration in Phase 2, Unit 4.
- **Taint Tracking**: String provenance relies on exact matches. Paraphrased taint will evade it. (Acceptable risk until ML taint tracking is implemented).