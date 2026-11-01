import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from decimal import Decimal
import json

from fastapi import HTTPException
from fastapi.responses import JSONResponse

from app.main import ApprovalIn, MandateIn, ToolCallIn, create_app


class ImmediateExecutor:
    def execute(self, call):
        return {"ok": True, "amount": str(call.amount)}


class BlockingExecutor:
    def __init__(self):
        self.started = threading.Event()
        self.release = threading.Event()
        self.calls = 0
        self.lock = threading.Lock()

    def execute(self, call):
        with self.lock:
            self.calls += 1
            first = self.calls == 1
        if first:
            self.started.set()
            if not self.release.wait(timeout=5):
                raise TimeoutError("test executor was not released")
        return {"ok": True, "amount": str(call.amount)}


class FailOnceExecutor:
    def __init__(self):
        self.calls = 0

    def execute(self, call):
        self.calls += 1
        if self.calls == 1:
            raise ValueError("simulated executor failure")
        return {"ok": True, "amount": str(call.amount)}


def mandate_payload(**overrides):
    payload = {
        "agent_id": "agent-1",
        "task": "pay the approved vendor",
        "budget_total": "100.00",
        "per_tx_cap": "60.00",
        "approval_over": "25.00",
        "allowed_tools": ["create_payout"],
        "allowed_payees": ["ap@example.com"],
        "max_tx_per_hour": 5,
        "ttl_seconds": 3600,
    }
    payload.update(overrides)
    return payload


def call_payload(amount="30.00"):
    return {
        "agent_id": "agent-1",
        "tool": "create_payout",
        "amount": amount,
        "currency": "USD",
        "payee": "ap@example.com",
    }


def invoke(app, path, *args, method="GET", **kwargs):
    endpoint = next(
        route.endpoint for route in app.routes
        if route.path == path and method in route.methods
    )
    result = endpoint(*args, **kwargs)
    if isinstance(result, JSONResponse):
        return result.status_code, json.loads(result.body)
    return 200, result


class PersistentState(unittest.TestCase):
    def test_mandates_tickets_and_accounting_survive_app_restart(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as cleanup:
            database_url = f"sqlite:///{directory}/tripwire.db"
            first_app = create_app(executor=ImmediateExecutor(), database_url=database_url)
            cleanup.callback(first_app.state.store.dispose)
            self.assertEqual(invoke(first_app, "/mandates", MandateIn(**mandate_payload()), method="POST")[0], 200)
            status, escalation = invoke(
                first_app, "/gateway/tool-call", ToolCallIn(**call_payload()), method="POST"
            )
            self.assertEqual(status, 202)
            ticket_id = escalation["ticket_id"]

            second_app = create_app(executor=ImmediateExecutor(), database_url=database_url)
            cleanup.callback(second_app.state.store.dispose)
            mandates = invoke(second_app, "/mandates")[1]
            self.assertEqual(mandates[0]["agent_id"], "agent-1")
            pending = invoke(second_app, "/approvals", status="pending")[1]
            self.assertEqual([ticket["id"] for ticket in pending], [ticket_id])
            approval_status, approval = invoke(
                second_app, "/approvals/{ticket_id}/approve", ticket_id, ApprovalIn(), method="POST"
            )
            self.assertEqual(approval_status, 200)
            self.assertEqual(approval["status"], "approved")

            third_app = create_app(executor=ImmediateExecutor(), database_url=database_url)
            cleanup.callback(third_app.state.store.dispose)
            state = invoke(third_app, "/state/{agent_id}", "agent-1")[1]
            self.assertEqual(state["spent"], "30.00")
            self.assertEqual(state["tx_last_hour"], 1)
            approved = invoke(third_app, "/approvals", status="approved")[1]
            self.assertEqual([ticket["id"] for ticket in approved], [ticket_id])

    def test_concurrent_calls_cannot_overspend_budget(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as cleanup:
            database_url = f"sqlite:///{directory}/tripwire.db"
            executor = BlockingExecutor()
            app = create_app(executor=executor, database_url=database_url)
            cleanup.callback(app.state.store.dispose)
            self.assertEqual(
                invoke(app, "/mandates", MandateIn(**mandate_payload(approval_over="60.00")), method="POST")[0],
                200,
            )
            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(
                    invoke, app, "/gateway/tool-call", ToolCallIn(**call_payload("60.00")), method="POST"
                )
                self.assertTrue(executor.started.wait(timeout=5), "first call did not reach executor")
                try:
                    second = invoke(
                        app, "/gateway/tool-call", ToolCallIn(**call_payload("60.00")), method="POST"
                    )
                finally:
                    executor.release.set()
                first_result = first.result(timeout=5)

            self.assertEqual(first_result[0], 200)
            self.assertEqual(second[0], 403)
            self.assertEqual(executor.calls, 1)
            state = invoke(app, "/state/{agent_id}", "agent-1")[1]
            self.assertEqual(Decimal(state["spent"]), Decimal("60.00"))

    def test_failed_execution_releases_its_reservation(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as cleanup:
            database_url = f"sqlite:///{directory}/tripwire.db"
            executor = FailOnceExecutor()
            app = create_app(executor=executor, database_url=database_url)
            cleanup.callback(app.state.store.dispose)
            invoke(
                app,
                "/mandates",
                MandateIn(**mandate_payload(approval_over="60.00")),
                method="POST",
            )
            request = ToolCallIn(**call_payload("60.00"))
            with self.assertRaises(HTTPException):
                invoke(app, "/gateway/tool-call", request, method="POST")

            state_after_failure = invoke(app, "/state/{agent_id}", "agent-1")[1]
            self.assertEqual(state_after_failure["spent"], "0")
            self.assertEqual(state_after_failure["tx_last_hour"], 0)
            status, result = invoke(app, "/gateway/tool-call", request, method="POST")
            self.assertEqual(status, 200)
            self.assertEqual(result["decision"], "allow")


if __name__ == "__main__":
    unittest.main()