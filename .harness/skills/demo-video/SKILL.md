---
name: demo-video
description: Use when scripting, rehearsing or checking the <3 minute hackathon demo video.
---
# 3-minute demo beats (hard cap 2:50)
0:00 Problem: agents can now pay; one poisoned page can redirect the money (15s, show real PayPal sandbox balance).
0:15 Attack, NO Tripwire: naive agent pays pay@evil-site.io. Show the sandbox payout landing. (35s)
0:50 Same attack, Tripwire on: 403, three findings, provenance trace to the page. (40s)
1:30 Escalation: amount over limit -> human approves in dashboard -> payout executes. (30s)
2:00 Kill switch + tamper check: revoke agent, edit an audit row, verify turns red. (25s)
2:25 Scoreboard: red-team evals N/N blocked, 0 false positives; judge is tighten-only, fail-closed. (20s)
2:45 One-line close + repo/license/Render URL. Record in one take per beat; captions on; no secrets on screen.
