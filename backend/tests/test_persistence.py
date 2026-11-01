import asyncio
import inspect
import os
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from decimal import Decimal
import json
from unittest.mock import patch

from fastapi import HTTPException
from fastapi.responses import JSONResponse
from starlette.requests import Request

from app.audit import AuditLog
from app.main import ApprovalIn, MandateIn, ToolCallIn, _audit_call, create_app
from app.judge import JudgeResult
from app.models import Decision, call_from_dict


class ImmediateExecutor:
    def execute(self, call):
        return {"ok": True, "amount": str(call.amount)}


class AsyncExecutor:
    async def execute(self, call):
        await asyncio.sleep(0)
        return {"ok": True, "amount": str(call.amount)}


class AsyncDenyJudge:
    async def judge(self, mandate, call, findings):
        await asyncio.sleep(0)
        return JudgeResult(Decision.DENY, "asynchronous test denial")


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


class CountingExecutor:
    def __init__(self, error=None):
        self.calls = 0
        self.error = error

    def execute(self, call):
        self.calls += 1
        if self.error:
            raise self.error
        return {"ok": True, "amount": str(call.amount)}


class FailAuditEvent(AuditLog):
    def __init__(self, event):
        super().__init__()
        self.event_to_fail = event

    async def append(self, event, agent_id, payload):
        if event == self.event_to_fail:
            raise OSError("simulated audit write failure")
        return await super().append(event, agent_id, payload)


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
    signature = inspect.signature(endpoint)
    bound = signature.bind_partial(*args, **kwargs)
    if "request" in signature.parameters and not isinstance(bound.arguments.get("request"), Request):
        body = bound.arguments.pop("request", None)
        if body is not None and "body" not in bound.arguments and "body" in signature.parameters:
            bound.arguments["body"] = body
        bound.arguments["request"] = Request({
            "type": "http",
            "method": method,
            "path": path,
            "headers": [],
            "client": ("127.0.0.1", 50000),
            "server": ("testserver", 80),
            "scheme": "http",
            "query_string": b"",
            "http_version": "1.1",
            "root_path": "",
        })
    result = endpoint(*bound.args, **bound.kwargs)
    if inspect.isawaitable(result):
        result = asyncio.run(result)
    if isinstance(result, JSONResponse):
        return result.status_code, json.loads(result.body)
    return 200, result


class PersistentState(unittest.TestCase):
    def test_api_routes_are_async(self):
        app = create_app(database_url="sqlite://")
        self.addCleanup(app.state.store.dispose)
        endpoints = {
            route.endpoint.__name__: route.endpoint
            for route in app.routes
            if hasattr(route, "endpoint")
        }

        for name in ("health", "list_mandates", "state", "approvals", "audit_list", "audit_verify", "tool_call"):
            with self.subTest(endpoint=name):
                self.assertTrue(inspect.iscoroutinefunction(endpoints[name]))

    def test_nested_database_and_audit_paths_are_created(self):
        with tempfile.TemporaryDirectory() as directory:
            nested = os.path.join(directory, "state", "deep")
            db_url = f"sqlite:///{os.path.join(nested, 'tripwire.db')}"
            audit_path = os.path.join(nested, "logs", "audit.jsonl")
            with patch.dict(
                os.environ,
                {
                    "TRIPWIRE_AUDIT_PATH": audit_path,
                    "TRIPWIRE_AUDIT_HMAC_KEY": "audit-key-" + "a" * 48,
                },
                clear=False,
            ):
                app = create_app(
                    database_url=db_url,
                    agent_api_key="agent-key-" + "a" * 48,
                    admin_token="admin-token-" + "b" * 48,
                )
                invoke(
                    app,
                    "/mandates",
                    MandateIn(**mandate_payload()),
                    method="POST",
                )
                app.state.store.dispose()

            self.assertTrue(os.path.isdir(os.path.dirname(db_url.replace("sqlite:///", ""))))
            self.assertTrue(os.path.isdir(os.path.dirname(audit_path)))
            self.assertTrue(os.path.exists(db_url.replace("sqlite:///", "")))
            self.assertTrue(os.path.exists(audit_path))

    def test_gateway_awaits_async_executor(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as cleanup:
            app = create_app(
                executor=AsyncExecutor(),
                database_url=f"sqlite:///{directory}/tripwire.db",
            )
            cleanup.callback(app.state.store.dispose)
            invoke(app, "/mandates", MandateIn(**mandate_payload()), method="POST")

            status, result = invoke(app, "/gateway/tool-call", ToolCallIn(**call_payload("10.00")), method="POST")

            self.assertEqual(status, 200)
            self.assertEqual(result["result"]["amount"], "10.00")

    def test_gateway_awaits_async_judge_before_execution(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as cleanup:
            executor = CountingExecutor()
            app = create_app(
                executor=executor,
                judge=AsyncDenyJudge(),
                database_url=f"sqlite:///{directory}/tripwire.db",
            )
            cleanup.callback(app.state.store.dispose)
            invoke(app, "/mandates", MandateIn(**mandate_payload()), method="POST")

            status, result = invoke(app, "/gateway/tool-call", ToolCallIn(**call_payload("10.00")), method="POST")

            self.assertEqual(status, 403)
            self.assertEqual(result["decision"], "deny")
            self.assertEqual(executor.calls, 0)

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


class AuditRequestIntegrity(unittest.TestCase):
    def make_app(self, executor, audit):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        app = create_app(
            executor=executor,
            audit=audit,
            database_url=f"sqlite:///{directory.name}/tripwire.db",
        )
        self.addCleanup(app.state.store.dispose)
        invoke(
            app,
            "/mandates",
            MandateIn(**mandate_payload(approval_over="60.00")),
            method="POST",
        )
        return app

    def make_escalated_app(self, executor, audit):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        app = create_app(
            executor=executor,
            audit=audit,
            database_url=f"sqlite:///{directory.name}/tripwire.db",
        )
        self.addCleanup(app.state.store.dispose)
        invoke(app, "/mandates", MandateIn(**mandate_payload()), method="POST")
        status, response = invoke(
            app, "/gateway/tool-call", ToolCallIn(**call_payload("30.00")), method="POST"
        )
        self.assertEqual(status, 202)
        return app, response["ticket_id"]

    def test_execution_intent_is_logged_before_external_action(self):
        audit = AuditLog()
        executor = CountingExecutor(error=RuntimeError("unexpected executor failure"))
        app = self.make_app(executor, audit)

        with self.assertRaisesRegex(RuntimeError, "unexpected executor failure"):
            invoke(app, "/gateway/tool-call", ToolCallIn(**call_payload("30.00")), method="POST")

        events = [entry["event"] for entry in audit.entries()]
        self.assertIn("tool_call_execution_started", events)
        self.assertIn("execution_failed", events)
        self.assertEqual(executor.calls, 1)

    def test_failed_intent_write_prevents_external_action(self):
        audit = FailAuditEvent("tool_call_execution_started")
        executor = CountingExecutor()
        app = self.make_app(executor, audit)

        with self.assertRaisesRegex(OSError, "simulated audit write failure"):
            invoke(app, "/gateway/tool-call", ToolCallIn(**call_payload("30.00")), method="POST")

        self.assertEqual(executor.calls, 0)
        state = invoke(app, "/state/{agent_id}", "agent-1")[1]
        self.assertEqual(state["spent"], "0")

    def test_successful_action_has_durable_intent_if_completion_write_fails(self):
        audit = FailAuditEvent("tool_call_executed")
        executor = CountingExecutor()
        app = self.make_app(executor, audit)

        with self.assertRaisesRegex(OSError, "simulated audit write failure"):
            invoke(app, "/gateway/tool-call", ToolCallIn(**call_payload("30.00")), method="POST")

        self.assertEqual(executor.calls, 1)
        events = [entry["event"] for entry in audit.entries()]
        self.assertIn("tool_call_execution_started", events)
        self.assertNotIn("tool_call_executed", events)

    def test_external_success_with_bookkeeping_failure_is_audited(self):
        audit = AuditLog()
        executor = CountingExecutor()
        app = self.make_app(executor, audit)

        with patch("app.main.PolicyEngine.commit_reservation",
                   side_effect=RuntimeError("simulated spend bookkeeping failure")):
            with self.assertRaisesRegex(RuntimeError, "bookkeeping failure"):
                invoke(app, "/gateway/tool-call", ToolCallIn(**call_payload("30.00")), method="POST")

        self.assertEqual(executor.calls, 1)
        events = [entry["event"] for entry in audit.entries()]
        self.assertIn("execution_bookkeeping_failed", events)

    def test_failed_approval_audit_write_restores_pending_ticket(self):
        audit = FailAuditEvent("approval_resolved")
        executor = CountingExecutor()
        app, ticket_id = self.make_escalated_app(executor, audit)

        with self.assertRaisesRegex(OSError, "simulated audit write failure"):
            invoke(app, "/approvals/{ticket_id}/approve", ticket_id, ApprovalIn(), method="POST")

        pending = invoke(app, "/approvals", status="pending")[1]
        self.assertEqual([ticket["id"] for ticket in pending], [ticket_id])
        self.assertEqual(executor.calls, 0)
        self.assertEqual(invoke(app, "/state/{agent_id}", "agent-1")[1]["spent"], "30.00")

    def test_concurrent_approval_requests_execute_ticket_once(self):
        audit = AuditLog()
        executor = CountingExecutor()
        app, ticket_id = self.make_escalated_app(executor, audit)
        original_get_ticket = app.state.store.get_ticket
        barrier = threading.Barrier(2)

        def synchronized_get_ticket(current_ticket_id):
            record = original_get_ticket(current_ticket_id)
            barrier.wait(timeout=5)
            return record

        app.state.store.get_ticket = synchronized_get_ticket
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(
                    invoke,
                    app,
                    "/approvals/{ticket_id}/approve",
                    ticket_id,
                    ApprovalIn(),
                    method="POST",
                )
                for _ in range(2)
            ]
            successful = 0
            for future in futures:
                try:
                    successful += future.result(timeout=10)[0] == 200
                except HTTPException as error:
                    self.assertEqual(error.status_code, 409)

        self.assertEqual(successful, 1)
        self.assertEqual(executor.calls, 1)

    def test_reservation_release_error_does_not_skip_execution_failure_audit(self):
        audit = AuditLog()
        executor = CountingExecutor(error=ValueError("simulated executor failure"))
        app = self.make_app(executor, audit)

        with patch("app.main.PolicyEngine.release_reservation",
                   side_effect=RuntimeError("simulated release failure")):
            with self.assertRaisesRegex(RuntimeError, "reservation release failed"):
                invoke(app, "/gateway/tool-call", ToolCallIn(**call_payload("30.00")), method="POST")

        events = [entry["event"] for entry in audit.entries()]
        self.assertIn("execution_failed", events)


class AsyncExecutionCancellation(unittest.IsolatedAsyncioTestCase):
    async def test_cancelled_request_waits_for_terminal_execution_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = AuditLog()
            executor = BlockingExecutor()
            app = create_app(
                executor=executor,
                audit=audit,
                database_url=f"sqlite:///{directory}/tripwire.db",
            )
            try:
                create_mandate = next(
                    route.endpoint for route in app.routes
                    if route.path == "/mandates" and "POST" in route.methods
                )
                gateway = next(
                    route.endpoint for route in app.routes
                    if route.path == "/gateway/tool-call" and "POST" in route.methods
                )
                await create_mandate(MandateIn(**mandate_payload(approval_over="60.00")))
                gateway_request = Request({
                    "type": "http",
                    "method": "POST",
                    "path": "/gateway/tool-call",
                    "headers": [],
                    "client": ("127.0.0.1", 50000),
                    "server": ("testserver", 80),
                    "scheme": "http",
                    "query_string": b"",
                    "http_version": "1.1",
                    "root_path": "",
                })
                request = asyncio.create_task(
                    gateway(request=gateway_request, body=ToolCallIn(**call_payload("30.00")))
                )
                self.assertTrue(await asyncio.to_thread(executor.started.wait, 2))
                request.cancel()
                await asyncio.sleep(0)
                executor.release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(request, timeout=5)
                events = [entry["event"] for entry in audit.entries()]
                self.assertIn("tool_call_execution_started", events)
                self.assertIn("tool_call_executed", events)
            finally:
                executor.release.set()
                app.state.store.dispose()


class AuditRedaction(unittest.TestCase):
    def test_audit_call_omits_free_text_and_redacts_credentials(self):
        call = call_from_dict({
            "agent_id": "agent-1",
            "tool": "create_payout",
            "amount": "30.00",
            "payee": "ap@example.com",
            "args": {
                "api_key": "arg-secret",
                "memo": "Bearer memo-secret",
                "callback_url": "https://service.test/callback?signature=query-secret&code=oauth-secret&item=42",
                "invoice": "INV-42",
            },
            "sources": [{
                "url": "https://vendor.test/invoice?access_token=url-secret&ref=INV-42",
                "trust": "untrusted",
                "excerpt": "password=source-secret",
            }],
            "agent_note": "token=note-secret",
        })

        serialized = json.dumps(_audit_call(call))
        for secret in (
            "arg-secret", "memo-secret", "query-secret", "oauth-secret", "url-secret",
            "source-secret", "note-secret"
        ):
            self.assertNotIn(secret, serialized)
        self.assertIn("INV-42", serialized)
        self.assertIn("[REDACTED]", serialized)


if __name__ == "__main__":
    unittest.main()