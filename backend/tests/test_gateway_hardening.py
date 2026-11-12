"""Gateway hardening: every decision is audited, identity comes only from the API key,
and a revoked mandate can never be used - even by a request already in flight."""
import tempfile
import time
import unittest
from unittest import mock

from fastapi import HTTPException

from app.audit import AuditLog
from app.judge import JudgeResult
from app.main import MandateIn, ToolCallIn, create_app
from app.models import Decision, Verdict, call_from_dict, mandate_from_dict
from app.storage import StateStore
from tests.test_persistence import (
    AGENT_ID, AsyncDenyJudge, CountingExecutor, FailAuditEvent, call_payload, invoke, mandate_payload,
)


def make_app(case, executor=None, judge=None, audit=None, own_mandate=True):
    directory = tempfile.TemporaryDirectory()
    case.addCleanup(directory.cleanup)
    audit = audit if audit is not None else AuditLog()
    app = create_app(
        executor=executor or CountingExecutor(),
        judge=judge,
        audit=audit,
        database_url=f"sqlite:///{directory.name}/tripwire.db",
    )
    case.addCleanup(app.state.store.dispose)
    if own_mandate:
        invoke(app, "/mandates", MandateIn(**mandate_payload(approval_over="60.00")), method="POST")
    return app, audit


def evaluated(audit):
    return [entry for entry in audit.entries() if entry["event"] == "tool_call_evaluated"]


def rules(verdict_dict):
    return [finding["rule"] for finding in verdict_dict["findings"]]


class EveryDecisionIsAudited(unittest.TestCase):
    def test_policy_denial_is_audited(self):
        executor = CountingExecutor()
        app, audit = make_app(self, executor)
        payload = call_payload("30.00")
        payload["payee"] = "attacker@evil.io"
        status, body = invoke(app, "/gateway/tool-call", ToolCallIn(**payload), method="POST")
        self.assertEqual(status, 403)
        rows = evaluated(audit)
        self.assertEqual(len(rows), 1)
        verdict = rows[0]["payload"]["verdict"]
        self.assertEqual(verdict["decision"], "deny")
        self.assertIn("payee_not_allowlisted", rules(verdict))
        self.assertEqual(rows[0]["payload"]["call"]["payee"], "attacker@evil.io")
        self.assertEqual(executor.calls, 0)

    def test_judge_denial_is_audited(self):
        app, audit = make_app(self, judge=AsyncDenyJudge())
        status, _ = invoke(app, "/gateway/tool-call", ToolCallIn(**call_payload("30.00")), method="POST")
        self.assertEqual(status, 403)
        rows = evaluated(audit)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["payload"]["verdict"]["decision"], "deny")
        self.assertIn("llm_judge", rules(rows[0]["payload"]["verdict"]))

    def test_a_failing_audit_write_never_turns_a_denial_into_an_error(self):
        executor = CountingExecutor()
        app, _ = make_app(self, executor, audit=FailAuditEvent("tool_call_evaluated"))
        payload = call_payload("30.00")
        payload["payee"] = "attacker@evil.io"
        with self.assertLogs("tripwire", level="ERROR"):
            status, body = invoke(app, "/gateway/tool-call", ToolCallIn(**payload), method="POST")
        self.assertEqual(status, 403)
        self.assertEqual(body["decision"], "deny")
        self.assertEqual(executor.calls, 0)

    def test_allowed_call_is_audited_exactly_once(self):
        app, audit = make_app(self)
        status, body = invoke(app, "/gateway/tool-call", ToolCallIn(**call_payload("30.00")), method="POST")
        self.assertEqual(status, 200)
        rows = evaluated(audit)
        self.assertEqual([row["payload"]["verdict"]["decision"] for row in rows], ["allow"])


class UpdatedMandateIsRechecked(unittest.TestCase):
    def test_removed_payee_is_denied_if_mandate_changes_during_judging(self):
        class TighteningJudge:
            store = None

            async def judge(self, mandate, call, findings):
                data = self.store.get_mandate(AGENT_ID)
                data["allowed_payees"] = []
                self.store.save_mandate(data)
                return JudgeResult(Decision.ALLOW, "looks fine")

        executor = CountingExecutor()
        judge = TighteningJudge()
        app, audit = make_app(self, executor, judge=judge)
        judge.store = app.state.store

        status, body = invoke(
            app, "/gateway/tool-call", ToolCallIn(**call_payload("30.00")), method="POST"
        )

        self.assertEqual(status, 403)
        self.assertIn("payee_not_allowlisted", rules(body))
        self.assertEqual(executor.calls, 0)
        self.assertEqual([row["payload"]["verdict"]["decision"] for row in evaluated(audit)], ["deny"])


class IdentityComesOnlyFromTheKey(unittest.TestCase):
    def test_payload_agent_id_cannot_select_another_agents_mandate(self):
        executor = CountingExecutor()
        app, audit = make_app(self, executor, own_mandate=False)
        invoke(app, "/mandates", MandateIn(**mandate_payload(
            agent_id="agent-victim", budget_total="5000.00", per_tx_cap="1000.00", approval_over="1000.00",
        )), method="POST")
        payload = call_payload("30.00")
        payload["agent_id"] = "agent-victim"
        with self.assertRaises(HTTPException) as ctx:
            invoke(app, "/gateway/tool-call", ToolCallIn(**payload), method="POST")
        self.assertEqual(ctx.exception.status_code, 404)
        self.assertEqual(executor.calls, 0)
        self.assertEqual([e for e in audit.entries() if e["event"] == "tool_call_executed"], [])

    def test_agent_id_in_the_payload_is_optional_and_ignored(self):
        app, _ = make_app(self)
        payload = call_payload("30.00")
        del payload["agent_id"]
        status, body = invoke(app, "/gateway/tool-call", ToolCallIn(**payload), method="POST")
        self.assertEqual((status, body["decision"]), (200, "allow"))
        payload["agent_id"] = "someone-else"
        status, body = invoke(app, "/gateway/tool-call", ToolCallIn(**payload), method="POST")
        self.assertEqual((status, body["decision"]), (200, "allow"))


class AuthoritativeMandate(unittest.TestCase):
    def make_store(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        store = StateStore(f"sqlite:///{directory.name}/state.db")
        self.addCleanup(store.dispose)
        mandate = mandate_from_dict({**mandate_payload(), "agent_id": AGENT_ID})
        store.save_mandate(mandate.to_dict())
        return store, mandate

    def change_stored(self, store, **changes):
        data = store.get_mandate(AGENT_ID)
        data.update(changes)
        store.save_mandate(data)

    def reserve(self, store, stale, amount="30.00"):
        return store.reserve_budget(
            stale, call_from_dict(call_payload(amount)), time.time(), verdict=Verdict(Decision.ALLOW, [])
        )

    def test_revocation_in_the_database_beats_a_stale_copy(self):
        from app.storage import ReservationRefused

        store, stale = self.make_store()
        self.change_stored(store, revoked=True)
        with self.assertRaises(ReservationRefused) as ctx:
            self.reserve(store, stale)
        self.assertEqual(ctx.exception.rule, "kill_switch")
        self.assertIsInstance(ctx.exception, ValueError)  # existing callers keep working
        self.assertEqual(store.policy_state(AGENT_ID, time.time())[1], 0)

    def test_expiry_in_the_database_beats_a_stale_copy(self):
        from app.storage import ReservationRefused

        store, stale = self.make_store()
        self.change_stored(store, expires_at=1.0)
        with self.assertRaises(ReservationRefused) as ctx:
            self.reserve(store, stale)
        self.assertEqual(ctx.exception.rule, "mandate_expired")

    def test_a_missing_mandate_fails_closed(self):
        from app.storage import ReservationRefused

        store, stale = self.make_store()
        stale.agent_id = "agent-ghost"
        ghost_call = call_from_dict({**call_payload("30.00"), "agent_id": "agent-ghost"})
        with self.assertRaises(ReservationRefused) as ctx:
            store.reserve_budget(stale, ghost_call, time.time(), verdict=Verdict(Decision.ALLOW, []))
        self.assertEqual(ctx.exception.rule, "mandate_missing")

    def test_budget_and_velocity_limits_come_from_the_stored_mandate(self):
        from app.storage import ReservationRefused

        store, stale = self.make_store()
        self.change_stored(store, budget_total="10.00")
        with self.assertRaises(ReservationRefused) as ctx:
            self.reserve(store, stale, "30.00")
        self.assertEqual(ctx.exception.rule, "budget_exceeded")
        self.change_stored(store, budget_total="1000.00", max_tx_per_hour=1)
        self.reserve(store, stale, "5.00")
        with self.assertRaises(ReservationRefused) as ctx:
            self.reserve(store, stale, "5.00")
        self.assertEqual(ctx.exception.rule, "velocity")


class RefusedReservationsAreAuditedDenials(unittest.TestCase):
    def test_reservation_refusal_returns_an_audited_403_not_a_500(self):
        from app.storage import ReservationRefused

        executor = CountingExecutor()
        app, audit = make_app(self, executor)
        refusal = ReservationRefused("budget_exceeded", "budget exceeded")
        with mock.patch.object(app.state.store, "atomic_admit", side_effect=refusal):
            status, body = invoke(app, "/gateway/tool-call", ToolCallIn(**call_payload("30.00")), method="POST")
        self.assertEqual(status, 403)
        self.assertEqual(body["decision"], "deny")
        self.assertIn("budget_exceeded", rules(body))
        rows = evaluated(audit)
        self.assertEqual([row["payload"]["verdict"]["decision"] for row in rows], ["deny"])
        self.assertEqual(executor.calls, 0)

    def test_kill_switch_pressed_while_the_judge_is_thinking_stops_the_payment(self):
        class RevokingJudge:
            store = None

            async def judge(self, mandate, call, findings):
                data = self.store.get_mandate(AGENT_ID)
                data["revoked"] = True
                self.store.save_mandate(data)  # the owner hits the kill switch mid-evaluation
                return JudgeResult(Decision.ALLOW, "looks fine")

        executor = CountingExecutor()
        judge = RevokingJudge()
        app, audit = make_app(self, executor, judge=judge)
        judge.store = app.state.store
        status, body = invoke(app, "/gateway/tool-call", ToolCallIn(**call_payload("30.00")), method="POST")
        self.assertEqual(status, 403)
        self.assertIn("kill_switch", rules(body))
        self.assertEqual(executor.calls, 0)
        self.assertEqual([e for e in audit.entries() if e["event"] == "tool_call_executed"], [])
        self.assertEqual([row["payload"]["verdict"]["decision"] for row in evaluated(audit)], ["deny"])
        self.assertEqual(app.state.store.policy_state(AGENT_ID, time.time())[1], 0)


if __name__ == "__main__":
    unittest.main()
