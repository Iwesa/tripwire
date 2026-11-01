"""Executors: the only code that actually moves (sandbox) money.

Invariant: SANDBOX ONLY. PayPalClient refuses to run against anything but the sandbox host.
UNVERIFIED against live sandbox from the authoring environment (no network) - run
`python scripts/paypal_smoke.py` (docs/PLAN.md, Day 1) before relying on it.
"""
from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from .models import ToolCall

SANDBOX_BASE = "https://api-m.sandbox.paypal.com"


class PayPalError(RuntimeError):
    def __init__(self, status: int, body: str):
        super().__init__(f"PayPal HTTP {status}: {body[:400]}")
        self.status = status


class DryRunExecutor:
    """No network. Used by tests and for offline demo mode."""

    def execute(self, call: ToolCall) -> dict:
        return {"dry_run": True, "id": f"DRY-{uuid.uuid4().hex[:12].upper()}", "tool": call.tool,
                "amount": None if call.amount is None else str(call.amount), "payee": call.payee}


class PayPalClient:
    def __init__(self, client_id: str, secret: str, base_url: str = SANDBOX_BASE, timeout: float = 20.0):
        if "sandbox" not in base_url:
            raise ValueError("Tripwire is sandbox-only: refusing non-sandbox PayPal base URL")
        self.client_id, self.secret = client_id, secret
        self.base_url, self.timeout = base_url.rstrip("/"), timeout
        self._token: str | None = None
        self._token_exp = 0.0

    # -- http ------------------------------------------------------------
    def _raw(self, method: str, path: str, headers: dict, body: bytes | None) -> dict:
        req = urllib.request.Request(self.base_url + path, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:  # noqa: S310 - sandbox https
                raw = r.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            raise PayPalError(e.code, e.read().decode("utf-8", "replace")) from e

    def _auth(self) -> str:
        if self._token and time.time() < self._token_exp - 30:
            return self._token
        basic = base64.b64encode(f"{self.client_id}:{self.secret}".encode()).decode()
        data = self._raw(
            "POST", "/v1/oauth2/token",
            {"Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded"},
            urllib.parse.urlencode({"grant_type": "client_credentials"}).encode(),
        )
        self._token = data["access_token"]
        self._token_exp = time.time() + int(data.get("expires_in", 300))
        return self._token

    def _call(self, method: str, path: str, payload: dict | None = None) -> dict:
        headers = {
            "Authorization": f"Bearer {self._auth()}",
            "Content-Type": "application/json",
            "PayPal-Request-Id": uuid.uuid4().hex,  # idempotency
        }
        return self._raw(method, path, headers, json.dumps(payload or {}).encode())

    # -- tools -----------------------------------------------------------
    def execute(self, call: ToolCall) -> dict:
        amt = None if call.amount is None else f"{call.amount:.2f}"
        if call.tool == "create_payout":
            return self._call("POST", "/v1/payments/payouts", {
                "sender_batch_header": {"sender_batch_id": uuid.uuid4().hex,
                                        "email_subject": "Payment via Tripwire-guarded agent"},
                "items": [{"recipient_type": "EMAIL", "receiver": call.payee,
                           "amount": {"value": amt, "currency": call.currency},
                           "note": call.agent_note[:100] or "agent payout",
                           "sender_item_id": uuid.uuid4().hex[:16]}],
            })
        if call.tool == "create_order":
            unit = {"amount": {"currency_code": call.currency, "value": amt},
                    "description": call.agent_note[:120] or "agent order"}
            if call.payee:
                unit["payee"] = {"email_address": call.payee}
            return self._call("POST", "/v2/checkout/orders", {"intent": "CAPTURE", "purchase_units": [unit]})
        if call.tool == "capture_order":
            return self._call("POST", f"/v2/checkout/orders/{call.args['order_id']}/capture")
        if call.tool == "create_refund":
            body = {"amount": {"value": amt, "currency_code": call.currency}} if amt else {}
            return self._call("POST", f"/v2/payments/captures/{call.args['capture_id']}/refund", body)
        raise ValueError(f"executor has no implementation for tool '{call.tool}'")
