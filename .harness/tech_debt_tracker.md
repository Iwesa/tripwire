# Tech Debt & Compromises

- **Injection Classification**: Lakera Guard is optional (`LAKERA_API_KEY`) so offline deployments use normalized local heuristics, which remain evadable. Configured deployments send untrusted source excerpts to Lakera; account for this data handling and service dependency.
- **SQLite Write Serialization**: Admission transactions serialize writes database-wide. Consider a database with row-level locking if higher write concurrency is required.
- **Synchronous HTTP Clients**: `LLMJudge` and PayPal use blocking transports offloaded to worker threads. Migrate to `httpx` async to reduce thread-pool pressure at higher throughput.
- **Taint Tracking**: String provenance relies on exact matches. Paraphrased taint will evade it.