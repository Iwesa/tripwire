"""Eval harness: runs evals/redteam_cases.json through the real engine.
This is the project's measurable 'sensor' - run it after every policy change."""
import json
import os
import unittest
from decimal import Decimal

from app.models import ToolCall, call_from_dict, mandate_from_dict
from app.policy import PolicyEngine

CASES_PATH = os.path.join(os.path.dirname(__file__), "..", "evals", "redteam_cases.json")


class FailingClassifier:
    def __call__(self, text):
        raise OSError("classifier unavailable")


class FailingJudge:
    def judge(self, mandate, call, findings):
        raise RuntimeError("judge unavailable")


def run_case(spec: dict, case: dict, disabled=frozenset()):
    mandate = mandate_from_dict({**spec["mandate"], **case.get("mandate_overrides", {})})
    engine = PolicyEngine(
        disabled_rules=frozenset(disabled),
        injection_classifier=FailingClassifier() if case.get("classifier_error") else None,
        judge=FailingJudge() if case.get("judge_error") else None,
    )
    for prior in case.get("prior", []):
        for _ in range(prior["count"]):
            engine.record(ToolCall(mandate.agent_id, "create_payout", Decimal(prior["amount"])))
    return engine.evaluate(mandate, call_from_dict(case["call"]))


class RedTeamEval(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(CASES_PATH, encoding="utf-8") as fh:
            cls.spec = json.load(fh)

    def test_every_case_matches_expected_verdict(self):
        failures = []
        for case in self.spec["cases"]:
            v = run_case(self.spec, case)
            if v.decision.label != case["expect"]:
                failures.append(f"{case['id']}: expected {case['expect']}, got {v.decision.label} {v.to_dict()['findings']}")
        self.assertEqual(failures, [], "\n" + "\n".join(failures))

    def test_scoreboard_for_demo(self):
        attacks = [c for c in self.spec["cases"] if c["kind"] == "attack"]
        benign = [c for c in self.spec["cases"] if c["kind"] == "benign"]
        blocked = sum(run_case(self.spec, c).decision.label != "allow" for c in attacks)
        false_pos = sum(run_case(self.spec, c).decision.label == "deny" for c in benign)
        print(f"\n[scoreboard] attacks blocked/escalated: {blocked}/{len(attacks)} | benign wrongly denied: {false_pos}/{len(benign)}")
        self.assertEqual(blocked, len(attacks))
        self.assertEqual(false_pos, 0)

    def test_every_rule_is_exercised_by_a_case(self):
        """Harness principle: no aspirational rules. Each rule name must fire in at least one case."""
        fired = set()
        for case in self.spec["cases"]:
            fired |= {f.rule for f in run_case(self.spec, case).findings}
        expected = {
            "tainted_payee",
            "lookalike_payee",
            "per_tx_cap",
            "approval_threshold",
            "tool_not_allowed",
            "currency_mismatch",
            "velocity",
            "budget_exceeded",
            "injection_signal",
            "payee_missing",
            "amount_invalid",
            "kill_switch",
            "mandate_expired",
            "payee_not_allowlisted",
            "agent_mismatch",
            "amount_missing",
            "non_ascii_payee",
            "new_payee",
            "injection_classifier_error",
            "llm_judge_error",
        }
        self.assertEqual(expected - fired, set(), "rules without an eval case")

    def test_every_rule_is_necessary(self):
        """Mutation check: disabling any single rule must flip at least one case's verdict.
        A rule that nothing depends on is either dead code or an untested rule."""
        rules = {
            "tainted_payee",
            "lookalike_payee",
            "per_tx_cap",
            "approval_threshold",
            "tool_not_allowed",
            "currency_mismatch",
            "velocity",
            "budget_exceeded",
            "injection_signal",
            "payee_missing",
            "amount_invalid",
            "kill_switch",
            "mandate_expired",
            "payee_not_allowlisted",
            "agent_mismatch",
            "amount_missing",
            "non_ascii_payee",
            "new_payee",
            "injection_classifier_error",
            "llm_judge_error",
        }
        unnecessary = []
        for rule in sorted(rules):
            flipped = any(run_case(self.spec, c, {rule}).decision.label != c["expect"] for c in self.spec["cases"])
            if not flipped:
                unnecessary.append(rule)
        self.assertEqual(unnecessary, [], f"no eval case isolates these rules: {unnecessary}")


if __name__ == "__main__":
    unittest.main()
