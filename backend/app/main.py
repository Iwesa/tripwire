"""Tripwire HTTP API. Thin by design: all decisions live in policy.py (unit-tested).

NOTE: written without FastAPI available in the authoring sandbox - run
`uvicorn app.main:app --reload` and hit /docs on Day 1 to confirm it boots.
"""
from __future__ import annotations

import os
import hmac
import time
import uuid
from dataclasses import dataclass, field
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .audit import AuditLog
from .judge import LLMJudge, NullJudge
from .models import Decision, Finding, ToolCall, Verdict, call_from_dict, mandate_from_dict
from .paypal import DryRunExecutor, PayPalClient, PayPalError
from .policy import PolicyEngine
from .storage import StateStore


# ---------- request schemas ----------
class SourceIn(BaseModel):
    url: str
    trust: Literal["trusted", "untrusted"] = "untrusted"
    excerpt: str = ""


class MandateIn(BaseModel):
    agent_id: str
    task: str
    currency: str = "USD"
    budget_total: str = "100.00"
    per_tx_cap: str = "50.00"
    approval_over: str = "25.00"
    allowed_tools: list[str] = ["create_payout"]
    allowed_payees: list[str] = []
    payee_mode: Literal["allowlist", "approve_new"] = "allowlist"
    max_tx_per_hour: int = 5
    ttl_seconds: int | None = 3600


class ToolCallIn(BaseModel):
    agent_id: str
    tool: str
    amount: str | None = None
    currency: str = "USD"
    payee: str | None = None
    args: dict = {}
    sources: list[SourceIn] = []
    agent_note: str = ""


class ApprovalIn(BaseModel):
    approver: str = "owner"


@dataclass
class Ticket:
    id: str
    call: ToolCall
    verdict: Verdict
    created: float
    status: str = "pending"  # pending | approved | denied
    resolved_by: str | None = None
    result: dict | None = field(default=None)
    reservation_id: int | None = None

    def to_dict(self) -> dict:
        return {"id": self.id, "status": self.status, "created": self.created, "resolved_by": self.resolved_by,
                "call": self.call.to_dict(), "verdict": self.verdict.to_dict(), "result": self.result}

    def to_record(self) -> dict:
        return {**self.to_dict(), "_reservation_id": self.reservation_id}


def _ticket_from_record(record: dict) -> Ticket:
    findings = [
        Finding(item["rule"], Decision[item["decision"].upper()], item["detail"])
        for item in record["verdict"]["findings"]
    ]
    verdict = Verdict(Decision[record["verdict"]["decision"].upper()], findings)
    return Ticket(
        record["id"],
        call_from_dict(record["call"]),
        verdict,
        record["created"],
        record["status"],
        record.get("resolved_by"),
        record.get("result"),
        record.get("_reservation_id"),
    )


def _default_executor():
    cid, sec = os.getenv("PAYPAL_CLIENT_ID"), os.getenv("PAYPAL_CLIENT_SECRET")
    if os.getenv("TRIPWIRE_MODE", "dry") == "live" and cid and sec:
        return PayPalClient(cid, sec)
    return DryRunExecutor()


def _configured_secret(name: str, supplied: str | None) -> str | None:
    value = supplied if supplied is not None else os.getenv(name)
    if not value:
        return None
    if len(value.encode("utf-8")) < 32:
        raise ValueError(f"{name} must be at least 32 bytes")
    return value


def create_app(executor=None, judge=None, audit: AuditLog | None = None, clock=time.time,
               database_url: str | None = None, agent_api_key: str | None = None,
               admin_token: str | None = None) -> FastAPI:
    agent_api_key = _configured_secret("TRIPWIRE_AGENT_API_KEY", agent_api_key)
    admin_token = _configured_secret("TRIPWIRE_ADMIN_TOKEN", admin_token)
    judge = judge or (LLMJudge() if os.getenv("ANTHROPIC_API_KEY") else NullJudge())
    audit = audit or AuditLog(os.getenv("TRIPWIRE_AUDIT_PATH"))
    executor = executor or _default_executor()
    store = StateStore(database_url or os.getenv("TRIPWIRE_DATABASE_URL", "sqlite:///tripwire.db"))
    engine = PolicyEngine(judge=judge, clock=clock, state_store=store)

    app = FastAPI(title="Tripwire", description="Spend firewall for AI agents (PayPal sandbox)")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=os.getenv("TRIPWIRE_CORS", "http://localhost:5173").split(","),
        allow_methods=["*"], allow_headers=["*"],
    )
    app.state.store = store

    def _authorize(presented: str | None, expected: str | None) -> None:
        if expected is None:
            raise HTTPException(503, "authentication is not configured")
        if presented is None or not hmac.compare_digest(presented, expected):
            raise HTTPException(401, "missing or invalid credentials")

    def require_agent_key(x_agent_key: str | None = Header(default=None, alias="X-Agent-Key")) -> None:
        _authorize(x_agent_key, agent_api_key)

    def require_admin_token(x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")) -> None:
        _authorize(x_admin_token, admin_token)

    app.state.auth_dependencies = {"agent": require_agent_key, "admin": require_admin_token}

    def _parse_dict(data: dict, builder):
        try:
            return builder(data)
        except (ValueError, KeyError) as e:
            raise HTTPException(422, str(e)) from e

    def _parse(model: BaseModel, builder):
        return _parse_dict(model.model_dump(), builder)

    def _execute(call: ToolCall, via: str, reservation_id: int | None = None) -> dict:
        try:
            result = executor.execute(call)
        except Exception as e:
            if reservation_id is not None:
                engine.release_reservation(reservation_id)
            if not isinstance(e, (PayPalError, ValueError)):
                raise
            audit.append("execution_failed", call.agent_id, {"call": call.to_dict(), "error": str(e)[:300]})
            raise HTTPException(502, f"execution failed: {e}") from e
        if reservation_id is None:
            engine.record(call)
        else:
            engine.commit_reservation(reservation_id)
        audit.append("tool_call_executed", call.agent_id, {"via": via, "call": call.to_dict(), "result": result})
        return result

    def _public_ticket(record: dict) -> dict:
        return _ticket_from_record(record).to_dict()

    @app.get("/health")
    def health():
        return {"ok": True, "executor": type(executor).__name__, "judge": type(judge).__name__}

    # ---- mandates ----
    @app.post("/mandates", dependencies=[Depends(require_admin_token)])
    def create_mandate(body: MandateIn):
        data = body.model_dump()
        ttl = data.pop("ttl_seconds")
        data["expires_at"] = clock() + ttl if ttl else None
        m = _parse_dict(data, mandate_from_dict)
        store.save_mandate(m.to_dict())
        audit.append("mandate_created", m.agent_id, m.to_dict())
        return m.to_dict()

    @app.get("/mandates", dependencies=[Depends(require_admin_token)])
    def list_mandates():
        return store.list_mandates()

    @app.post("/mandates/{agent_id}/revoke", dependencies=[Depends(require_admin_token)])
    def revoke(agent_id: str):
        data = store.get_mandate(agent_id)
        if data is None:
            raise HTTPException(404, "unknown agent")
        m = _parse_dict(data, mandate_from_dict)
        m.revoked = True
        store.save_mandate(m.to_dict())
        for record in store.list_tickets("pending"):
            if record["call"]["agent_id"] == agent_id:
                record["status"], record["resolved_by"] = "denied", "kill_switch"
                reservation_id = record.get("_reservation_id")
                if reservation_id is not None:
                    engine.release_reservation(reservation_id)
                store.save_ticket(record)
        audit.append("mandate_revoked", agent_id, {"by": "owner"})
        return {"agent_id": agent_id, "revoked": True}

    @app.get("/state/{agent_id}", dependencies=[Depends(require_admin_token)])
    def state(agent_id: str):
        data = store.get_mandate(agent_id)
        if data is None:
            raise HTTPException(404, "unknown agent")
        m = _parse_dict(data, mandate_from_dict)
        spent, recent = store.policy_state(agent_id, clock())
        return {"agent_id": agent_id, "spent": str(spent), "remaining": str(m.budget_total - spent),
                "tx_last_hour": recent, "revoked": m.revoked}

    # ---- the gateway: every agent tool call goes through here ----
    @app.post("/gateway/tool-call", dependencies=[Depends(require_agent_key)])
    def tool_call(body: ToolCallIn):
        call = _parse(body, call_from_dict)
        data = store.get_mandate(call.agent_id)
        if data is None:
            raise HTTPException(404, "no mandate for this agent")
        m = _parse_dict(data, mandate_from_dict)
        verdict, reservation_id = engine.evaluate_and_reserve(m, call, reserve_escalations=True)
        audit.append("tool_call_evaluated", call.agent_id, {"call": call.to_dict(), "verdict": verdict.to_dict()})

        if verdict.decision == Decision.DENY:
            return JSONResponse(status_code=403, content={"decision": "deny", **verdict.to_dict()})
        if verdict.decision == Decision.ESCALATE:
            t = Ticket(uuid.uuid4().hex[:10], call, verdict, clock(), reservation_id=reservation_id)
            store.save_ticket(t.to_record())
            audit.append("approval_requested", call.agent_id, {"ticket": t.id})
            return JSONResponse(status_code=202, content={"decision": "escalate", "ticket_id": t.id, **verdict.to_dict()})
        result = _execute(call, via="auto", reservation_id=reservation_id)
        return {"decision": "allow", "result": result, **verdict.to_dict()}

    # ---- human approvals ----
    @app.get("/approvals", dependencies=[Depends(require_admin_token)])
    def approvals(status: str | None = None):
        return [_public_ticket(record) for record in store.list_tickets(status)]

    def _resolve(ticket_id: str, approve: bool, who: str) -> dict:
        record = store.get_ticket(ticket_id)
        if record is None:
            raise HTTPException(404, "unknown ticket")
        t = _ticket_from_record(record)
        if t.status != "pending":
            raise HTTPException(409, f"ticket already {t.status}")
        mandate_data = store.get_mandate(t.call.agent_id)
        m = _parse_dict(mandate_data, mandate_from_dict) if mandate_data is not None else None
        if approve and (m is None or m.revoked):
            raise HTTPException(409, "mandate revoked; cannot approve")
        t.status, t.resolved_by = ("approved" if approve else "denied"), who
        if not approve and t.reservation_id is not None:
            engine.release_reservation(t.reservation_id)
        store.save_ticket(t.to_record())
        audit.append("approval_resolved", t.call.agent_id, {"ticket": t.id, "status": t.status, "by": who})
        if approve:
            t.result = _execute(t.call, via=f"human:{who}", reservation_id=t.reservation_id)
            store.save_ticket(t.to_record())
        return t.to_dict()

    @app.post("/approvals/{ticket_id}/approve", dependencies=[Depends(require_admin_token)])
    def approve(ticket_id: str, body: ApprovalIn = ApprovalIn()):
        return _resolve(ticket_id, True, body.approver)

    @app.post("/approvals/{ticket_id}/deny", dependencies=[Depends(require_admin_token)])
    def deny(ticket_id: str, body: ApprovalIn = ApprovalIn()):
        return _resolve(ticket_id, False, body.approver)

    # ---- audit ----
    @app.get("/audit", dependencies=[Depends(require_admin_token)])
    def audit_list(limit: int = 100, agent_id: str | None = None):
        return audit.entries(limit=limit, agent_id=agent_id)

    @app.get("/audit/verify", dependencies=[Depends(require_admin_token)])
    def audit_verify():
        ok, bad = audit.verify()
        return {"ok": ok, "first_bad_seq": bad, "entries": len(audit.entries())}

    return app


app = create_app()
