---
name: add-policy-rule
description: Use when adding or changing a Tripwire policy rule (new attack, false positive, new payment tool). Enforces the eval-first workflow.
---
# Add a policy rule (eval-first)

1. **Write the failing case first.** Append to `backend/evals/redteam_cases.json` with `kind` (attack|benign),
   `expect` (allow|escalate|deny) and a `note` saying which rule it must isolate.
   The case must be caught by the NEW rule alone - other rules must not already block it.
2. Run the suite; confirm the new case fails for the right reason.
3. Implement the rule in `backend/app/policy.py` (`_money_rules`, `_payee_rules`, or `_provenance_rules`).
   Use `add(rule_name, Decision.X, human-readable detail)`. Details are shown in the dashboard - write for a human.
4. Add the rule name to the `rules` set in `test_every_rule_is_necessary` and `expected` in `test_every_rule_is_exercised_by_a_case`.
5. Run the suite. Both mutation tests must pass (every rule is necessary + exercised).
6. Check benign cases still `allow` (scoreboard line: false positives must stay 0).
Never: loosen a verdict from the judge path, or catch a new attack with an aspirational prompt line instead of a rule.
