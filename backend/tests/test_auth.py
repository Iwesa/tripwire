import contextlib
import importlib.util
import io
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app.main import create_app


AGENT_KEY = "agent-key-" + "a" * 48
ADMIN_TOKEN = "admin-token-" + "b" * 48
DEMO_AGENT_PATH = Path(__file__).resolve().parents[2] / "agent" / "demo_agent.py"
DEMO_SPEC = importlib.util.spec_from_file_location("tripwire_demo_agent", DEMO_AGENT_PATH)
demo_agent = importlib.util.module_from_spec(DEMO_SPEC)
DEMO_SPEC.loader.exec_module(demo_agent)


class ApiAuthentication(unittest.TestCase):
    def setUp(self):
        self.app = create_app(
            database_url="sqlite:///:memory:",
            agent_api_key=AGENT_KEY,
            admin_token=ADMIN_TOKEN,
        )
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
        self.assertIsNone(self.guards["agent"](AGENT_KEY))

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


if __name__ == "__main__":
    unittest.main()
