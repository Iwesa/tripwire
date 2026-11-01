import contextlib
import importlib.util
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.main import agent_id_from_key, create_app


AGENT_KEY = "agent-key-" + "a" * 48
ADMIN_TOKEN = "admin-token-" + "b" * 48
DEMO_AGENT_PATH = Path(__file__).resolve().parents[2] / "agent" / "demo_agent.py"
DEMO_SPEC = importlib.util.spec_from_file_location("tripwire_demo_agent", DEMO_AGENT_PATH)
demo_agent = importlib.util.module_from_spec(DEMO_SPEC)
DEMO_SPEC.loader.exec_module(demo_agent)


class ApiAuthentication(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.app = create_app(
            database_url=f"sqlite:///{self.directory.name}/tripwire.db",
            agent_api_key=AGENT_KEY,
            admin_token=ADMIN_TOKEN,
        )
        self.addCleanup(self.directory.cleanup)
        self.addCleanup(self.app.state.store.dispose)
        self.guards = self.app.state.auth_dependencies

    def route_dependencies(self, path, method):
        route = next(
            route for route in self.app.routes
            if route.path == path and method in route.methods
        )
        return [dependency.call for dependency in route.dependant.dependencies]

    def assert_rejected(self, guard, value, status_code):
        with self.assertRaises(HTTPException) as raised:
            guard(value)
        self.assertEqual(raised.exception.status_code, status_code)

    def test_gateway_requires_agent_key(self):
        self.assertIn(self.guards["agent"], self.route_dependencies("/gateway/tool-call", "POST"))
        self.assert_rejected(self.guards["agent"], None, 401)
        self.assert_rejected(self.guards["agent"], "wrong-key", 401)
        self.assert_rejected(self.guards["agent"], "無効な鍵", 401)
        self.assertIsNone(self.guards["agent"](AGENT_KEY))

    def test_gateway_auth_is_enforced_over_http(self):
        body = {
            "agent_id": "agent-1",
            "tool": "create_payout",
            "amount": "10.00",
            "currency": "USD",
            "payee": "ap@example.com",
        }
        with TestClient(self.app) as client:
            missing = client.post("/gateway/tool-call", json=body)
            wrong = client.post("/gateway/tool-call", json=body, headers={"X-Agent-Key": "wrong"})
            valid = client.post("/gateway/tool-call", json=body, headers={"X-Agent-Key": AGENT_KEY})

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(wrong.status_code, 401)
        self.assertEqual(valid.status_code, 404)

    def test_gateway_ignores_payload_agent_id_and_honors_trusted_origins(self):
        agent_id = agent_id_from_key(AGENT_KEY)
        with TestClient(self.app) as client:
            mandate = client.post(
                "/mandates",
                json={
                    "agent_id": agent_id,
                    "task": "pay approved invoices",
                    "budget_total": "100.00",
                    "per_tx_cap": "50.00",
                    "approval_over": "25.00",
                    "allowed_tools": ["create_payout"],
                    "allowed_payees": ["ap@example.com"],
                    "max_tx_per_hour": 10,
                    "ttl_seconds": 3600,
                    "trusted_origins": ["https://trusted.example.com"],
                },
                headers={"X-Admin-Token": ADMIN_TOKEN},
            )
            self.assertEqual(mandate.status_code, 200)
            response = client.post(
                "/gateway/tool-call",
                json={
                    "agent_id": "wrong-agent",
                    "tool": "create_payout",
                    "amount": "10.00",
                    "currency": "USD",
                    "payee": "ap@example.com",
                    "sources": [
                        {"url": "https://trusted.example.com/invoice", "trust": "trusted", "excerpt": "invoice"},
                        {"url": "https://evil.example.com/invoice", "trust": "untrusted", "excerpt": "invoice"},
                    ],
                },
                headers={"X-Agent-Key": AGENT_KEY},
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn("decision", response.json())

    def test_admin_routes_require_strong_admin_token(self):
        protected_routes = [
            ("/mandates", "POST"),
            ("/mandates", "GET"),
            ("/mandates/{agent_id}/revoke", "POST"),
            ("/approvals", "GET"),
            ("/approvals/{ticket_id}/approve", "POST"),
            ("/approvals/{ticket_id}/deny", "POST"),
            ("/state/{agent_id}", "GET"),
            ("/audit", "GET"),
            ("/audit/verify", "GET"),
        ]
        for path, method in protected_routes:
            with self.subTest(path=path, method=method):
                self.assertIn(self.guards["admin"], self.route_dependencies(path, method))
        self.assert_rejected(self.guards["admin"], None, 401)
        self.assert_rejected(self.guards["admin"], "wrong-token", 401)
        self.assertIsNone(self.guards["admin"](ADMIN_TOKEN))

    def test_admin_auth_is_enforced_over_http(self):
        with TestClient(self.app) as client:
            missing = client.get("/mandates")
            wrong = client.get("/mandates", headers={"X-Admin-Token": "wrong"})
            valid = client.get("/mandates", headers={"X-Admin-Token": ADMIN_TOKEN})

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(wrong.status_code, 401)
        self.assertEqual(valid.status_code, 200)

    def test_unconfigured_authentication_fails_closed(self):
        app = create_app(database_url="sqlite:///:memory:")
        self.addCleanup(app.state.store.dispose)
        self.assert_rejected(app.state.auth_dependencies["agent"], AGENT_KEY, 503)
        self.assert_rejected(app.state.auth_dependencies["admin"], ADMIN_TOKEN, 503)

    def test_configured_secrets_must_be_at_least_32_bytes(self):
        with self.assertRaisesRegex(ValueError, "at least 32 bytes"):
            create_app(database_url="sqlite:///:memory:", agent_api_key="too-short")
        with self.assertRaisesRegex(ValueError, "at least 32 bytes"):
            create_app(database_url="sqlite:///:memory:", admin_token="too-short")

    def test_demo_agent_sends_agent_and_admin_credentials(self):
        with patch.dict(os.environ, {"TRIPWIRE_AGENT_API_KEY": AGENT_KEY}):
            with patch.object(demo_agent, "http_json", return_value=(200, {})) as request:
                demo_agent.Agent(guarded=True).pay("10.00", "ap@example.com")
            self.assertEqual(request.call_args.kwargs["headers"], {"X-Agent-Key": AGENT_KEY})

        with patch.dict(os.environ, {"TRIPWIRE_ADMIN_TOKEN": ADMIN_TOKEN}):
            with patch.object(sys, "argv", [str(DEMO_AGENT_PATH), "setup"]):
                with patch.object(demo_agent, "http_json", return_value=(200, {})) as request:
                    with contextlib.redirect_stdout(io.StringIO()):
                        demo_agent.main()
            self.assertEqual(request.call_args.kwargs["headers"], {"X-Admin-Token": ADMIN_TOKEN})

    def test_unconfigured_authentication_fails_closed_over_http(self):
        directory = tempfile.TemporaryDirectory()
        app = create_app(database_url=f"sqlite:///{directory.name}/tripwire.db")
        try:
            with TestClient(app) as client:
                agent_response = client.post(
                    "/gateway/tool-call",
                    json={"agent_id": "agent-1", "tool": "create_payout"},
                    headers={"X-Agent-Key": AGENT_KEY},
                )
                admin_response = client.get("/mandates", headers={"X-Admin-Token": ADMIN_TOKEN})

            self.assertEqual(agent_response.status_code, 503)
            self.assertEqual(admin_response.status_code, 503)
        finally:
            app.state.store.dispose()
            directory.cleanup()


class GatewayRateLimiting(unittest.TestCase):
    def test_gateway_is_limited_to_50_requests_per_minute_per_client_ip(self):
        directory = tempfile.TemporaryDirectory()
        app = create_app(
            database_url=f"sqlite:///{directory.name}/tripwire.db",
            agent_api_key=AGENT_KEY,
            admin_token=ADMIN_TOKEN,
        )
        self.addCleanup(directory.cleanup)
        self.addCleanup(app.state.store.dispose)
        mandate = {
            "agent_id": "agent-1",
            "task": "pay approved invoices",
            "budget_total": "1000.00",
            "per_tx_cap": "50.00",
            "approval_over": "50.00",
            "allowed_tools": ["create_payout"],
            "allowed_payees": ["ap@example.com"],
            "max_tx_per_hour": 1000,
            "ttl_seconds": 3600,
        }
        call = {
            "agent_id": "agent-1",
            "tool": "create_payout",
            "amount": "1.00",
            "currency": "USD",
            "payee": "ap@example.com",
        }
        with TestClient(app) as client:
            created = client.post(
                "/mandates", json=mandate, headers={"X-Admin-Token": ADMIN_TOKEN}
            )
            self.assertEqual(created.status_code, 200)
            responses = [
                client.post(
                    "/gateway/tool-call", json=call, headers={"X-Agent-Key": AGENT_KEY}
                )
                for _ in range(51)
            ]

        self.assertEqual(sum(response.status_code == 429 for response in responses), 1)
        self.assertEqual(responses[-1].status_code, 429)


if __name__ == "__main__":
    unittest.main()
