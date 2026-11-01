---
name: redteam-scenario
description: Use when creating a new attack for the demo or evals (prompt injection page, lookalike payee, drain pattern).
---
# Add a red-team scenario
1. Decide the attack's goal (redirect payee / inflate amount / drain via many small payments / exceed mandate).
2. Add the eval case (see add-policy-rule). For web-borne attacks also add a page to `agent/evil_site.py`.
3. Make the *unguarded* path succeed on camera: `python3 agent/demo_agent.py run --direct --naive`.
4. Confirm the guarded path is denied and the dashboard shows the finding + provenance (which page tainted the payee).
5. Keep the attack realistic and local. No real third-party sites, no real money, sandbox accounts only.
