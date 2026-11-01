"""Tripwire HTTP API. Thin by design: all decisions live in policy.py (unit-tested).

NOTE: written without FastAPI available in the authoring sandbox - run
`uvicorn app.main:app --reload` and hit /docs on Day 1 to confirm it boots.
"""
from __future__ import annotations

import asyncio
import os
import hmac
import inspect
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from .audit import AuditLog
from .injection import LakeraGuardClassifier
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


_AUDIT_SECRET_KEY_PARTS = (
    "password", "passwd", "secret", "token", "apikey", "authorization", "cookie",
    "credential", "clientid", "privatekey", "signingkey", "signature",
)
_AUDIT_SECRET_VALUE = re.compile(
    r"(?i)\b((?:bearer\s+)|(?:api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"password|passwd|secret|authorization)\s*[:=]\s*)[^\s,;&]+"
)
_AUDIT_URL = re.compile(r"https?://[^\s<>\"')]+")
_AUDIT_SAFE_QUERY_KEYS = frozenset({"id", "ref", "page", "source", "invoice", "lang", "item"})


def _is_audit_secret_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())
    return normalized in {"key", "sig"} or any(part in normalized for part in _AUDIT_SECRET_KEY_PARTS)


def _redact_audit_value(value):
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if _is_audit_secret_key(str(key)) else _redact_audit_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_audit_value(item) for item in value]
    if isinstance(value, str):
        value = _AUDIT_SECRET_VALUE.sub(r"\1[REDACTED]", value)
        return _AUDIT_URL.sub(lambda match: _audit_url(match.group(0)), value)
    return value


def _audit_url(url: str) -> str:
    parts = urlsplit(url)
    query = [
        (key, _redact_audit_value(value)
         if key.lower() in _AUDIT_SAFE_QUERY_KEYS and not _is_audit_secret_key(key)
         else "[REDACTED]")
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
    ]
    return urlunsplit((parts.scheme, parts.netloc.rsplit("@", 1)[-1], parts.path,
                       urlencode(query, doseq=True), _redact_audit_value(parts.fragment)))


def _audit_call(call: ToolCall) -> dict:
    record = call.to_dict()
    record["args"] = _redact_audit_value(record.get("args", {}))
    record.pop("agent_note", None)
    record["sources"] = [
        {"url": _audit_url(source["url"]), "trust": source["trust"]}
        for source in record["sources"]
    ]
    return _redact_audit_value(record)


def create_app(executor=None, judge=None, audit: AuditLog | None = None, clock=time.time,
               database_url: str | None = None, agent_api_key: str | None = None,
               admin_token: str | None = None) -> FastAPI:
    agent_api_key = _configured_secret("TRIPWIRE_AGENT_API_KEY", agent_api_key)
    admin_token = _configured_secret("TRIPWIRE_ADMIN_TOKEN", admin_token)
    judge = judge or (LLMJudge() if os.getenv("ANTHROPIC_API_KEY") else NullJudge())
    audit = audit or AuditLog(os.getenv("TRIPWIRE_AUDIT_PATH"))
    executor = executor or _default_executor()
    store = StateStore(database_url or os.getenv("TRIPWIRE_DATABASE_URL", "sqlite:///tripwire.db"))
    injection_classifier = (
        LakeraGuardClassifier(os.environ["LAKERA_API_KEY"])
        if os.getenv("LAKERA_API_KEY")
        else None
    )
    engine = PolicyEngine(
        judge=judge,
        clock=clock,
        state_store=store,
        injection_classifier=injection_classifier,
    )

    app = FastAPI(title="Tripwire", description="Spend firewall for AI agents (PayPal sandbox)")
    limiter = Limiter(key_func=get_remote_address)
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    if isinstance(executor, PayPalClient):
        app.add_event_handler("shutdown", executor.aclose)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=os.getenv("TRIPWIRE_CORS", "http://localhost:5173").split(","),
        allow_methods=["*"], allow_headers=["*"],
    )
    app.state.store = store

    def _authorize(presented: str | None, expected: str | None) -> None:
        if expected is None:
            raise HTTPException(503, "authentication is not configured")
        if presented is None or not hmac.compare_digest(
            presented.encode("utf-8"), expected.encode("utf-8")
        ):
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

    async def _execute(call: ToolCall, via: str, reservation_id: int | None = None) -> dict:
        try:
            await audit.append("tool_call_execution_started", call.agent_id,
                               {"via": via, "call": _audit_call(call)})
        except BaseException:
            if reservation_id is not None:
                try:
                    await asyncio.shield(asyncio.to_thread(engine.release_reservation, reservation_id))
                except BaseException:
                    pass
            raise

        async def execute_and_record() -> dict:
            try:
                if inspect.iscoroutinefunction(executor.execute):
                    result = await executor.execute(call)
                else:
                    result = await asyncio.to_thread(executor.execute, call)
                    if inspect.isawaitable(result):
                        result = await result
            except Exception as e:
                release_error = None
                if reservation_id is not None:
                    try:
                        await asyncio.to_thread(engine.release_reservation, reservation_id)
                    except Exception as cleanup_error:
                        release_error = cleanup_error
                failure = {
                    "call": _audit_call(call),
                    "error": _redact_audit_value(str(e)[:300]),
                }
                if release_error is not None:
                    failure["reservation_release_error"] = _redact_audit_value(str(release_error)[:300])
                await audit.append("execution_failed", call.agent_id, failure)
                if release_error is not None:
                    raise RuntimeError("execution failed and reservation release failed") from release_error
                if isinstance(e, (PayPalError, ValueError)):
                    raise HTTPException(502, f"execution failed: {e}") from e
                raise

            try:
                if reservation_id is None:
                    await asyncio.to_thread(engine.record, call)
                else:
                    await asyncio.to_thread(engine.commit_reservation, reservation_id)
            except Exception as e:
                await audit.append(
                    "execution_bookkeeping_failed",
                    call.agent_id,
                    {
                        "via": via,
                        "call": _audit_call(call),
                        "executor_completed": True,
                        "result": _redact_audit_value(result),
                        "error": _redact_audit_value(str(e)[:300]),
                    },
                )
                raise
            await audit.append("tool_call_executed", call.agent_id,
                               {"via": via, "call": _audit_call(call),
                                "result": _redact_audit_value(result)})
            return result

        execution = asyncio.create_task(execute_and_record())
        try:
            return await asyncio.shield(execution)
        except asyncio.CancelledError:
            try:
                await asyncio.shield(execution)
            except BaseException:
                pass
            raise

    def _public_ticket(record: dict) -> dict:
        return _ticket_from_record(record).to_dict()

    @app.get("/health")
    async def health():
        return {"ok": True, "executor": type(executor).__name__, "judge": type(judge).__name__}

    # ---- mandates ----
    @app.post("/mandates", dependencies=[Depends(require_admin_token)])
    async def create_mandate(body: MandateIn):
        data = body.model_dump()
        ttl = data.pop("ttl_seconds")
        data["expires_at"] = clock() + ttl if ttl else None
        m = _parse_dict(data, mandate_from_dict)
        await asyncio.to_thread(store.save_mandate, m.to_dict())
        await audit.append("mandate_created", m.agent_id, _redact_audit_value(m.to_dict()))
        return m.to_dict()

    @app.get("/mandates", dependencies=[Depends(require_admin_token)])
    async def list_mandates():
        return await asyncio.to_thread(store.list_mandates)

    @app.post("/mandates/{agent_id}/revoke", dependencies=[Depends(require_admin_token)])
    async def revoke(agent_id: str):
        data = await asyncio.to_thread(store.get_mandate, agent_id)
        if data is None:
            raise HTTPException(404, "unknown agent")
        m = _parse_dict(data, mandate_from_dict)
        m.revoked = True
        await asyncio.to_thread(store.save_mandate, m.to_dict())
        records = await asyncio.to_thread(store.list_tickets, "pending")
        for record in records:
            if record["call"]["agent_id"] == agent_id:
                record["status"], record["resolved_by"] = "denied", "kill_switch"
                reservation_id = record.get("_reservation_id")
                if reservation_id is not None:
                    await asyncio.to_thread(engine.release_reservation, reservation_id)
                await asyncio.to_thread(store.save_ticket, record)
        await audit.append("mandate_revoked", agent_id, {"by": "owner"})
        return {"agent_id": agent_id, "revoked": True}

    @app.get("/state/{agent_id}", dependencies=[Depends(require_admin_token)])
    async def state(agent_id: str):
        data = await asyncio.to_thread(store.get_mandate, agent_id)
        if data is None:
            raise HTTPException(404, "unknown agent")
        m = _parse_dict(data, mandate_from_dict)
        spent, recent = await asyncio.to_thread(store.policy_state, agent_id, clock())
        return {"agent_id": agent_id, "spent": str(spent), "remaining": str(m.budget_total - spent),
                "tx_last_hour": recent, "revoked": m.revoked}

    # ---- the gateway: every agent tool call goes through here ----
    @app.post("/gateway/tool-call", dependencies=[Depends(require_agent_key)])
    @limiter.limit("50/minute")
    async def tool_call(request: Request, body: ToolCallIn):
        call = _parse(body, call_from_dict)
        data = await asyncio.to_thread(store.get_mandate, call.agent_id)
        if data is None:
            raise HTTPException(404, "no mandate for this agent")
        m = _parse_dict(data, mandate_from_dict)
        verdict, reservation_id = await engine.evaluate_and_reserve_async(
            m, call, reserve_escalations=True
        )
        try:
            await audit.append("tool_call_evaluated", call.agent_id,
                               {"call": _audit_call(call),
                                "verdict": _redact_audit_value(verdict.to_dict())})
        except Exception:
            if reservation_id is not None:
                await asyncio.to_thread(engine.release_reservation, reservation_id)
            raise

        if verdict.decision == Decision.DENY:
            return JSONResponse(status_code=403, content={"decision": "deny", **verdict.to_dict()})
        if verdict.decision == Decision.ESCALATE:
            t = Ticket(uuid.uuid4().hex[:10], call, verdict, clock(), reservation_id=reservation_id)
            await asyncio.to_thread(store.save_ticket, t.to_record())
            await audit.append("approval_requested", call.agent_id, {"ticket": t.id})
            return JSONResponse(status_code=202, content={"decision": "escalate", "ticket_id": t.id, **verdict.to_dict()})
        result = await _execute(call, via="auto", reservation_id=reservation_id)
        return {"decision": "allow", "result": result, **verdict.to_dict()}

    # ---- human approvals ----
    @app.get("/approvals", dependencies=[Depends(require_admin_token)])
    async def approvals(status: str | None = None):
        records = await asyncio.to_thread(store.list_tickets, status)
        return [_public_ticket(record) for record in records]

    async def _resolve(ticket_id: str, approve: bool, who: str) -> dict:
        record = await asyncio.to_thread(store.get_ticket, ticket_id)
        if record is None:
            raise HTTPException(404, "unknown ticket")
        t = _ticket_from_record(record)
        if t.status != "pending":
            raise HTTPException(409, f"ticket already {t.status}")
        mandate_data = await asyncio.to_thread(store.get_mandate, t.call.agent_id)
        m = _parse_dict(mandate_data, mandate_from_dict) if mandate_data is not None else None
        if approve and (m is None or m.revoked):
            raise HTTPException(409, "mandate revoked; cannot approve")
        new_status = "approved" if approve else "denied"
        record, resolution_error = await asyncio.to_thread(
            store.claim_ticket_resolution, ticket_id, new_status, who, clock()
        )
        if record is None:
            if resolution_error == "unknown ticket":
                raise HTTPException(404, resolution_error)
            raise HTTPException(409, resolution_error)
        t = _ticket_from_record(record)
        try:
            await audit.append("approval_resolved", t.call.agent_id,
                               {"ticket": t.id, "status": t.status, "by": who})
        except BaseException:
            await asyncio.shield(asyncio.to_thread(store.restore_pending_ticket, t.id, who))
            raise
        if not approve and t.reservation_id is not None:
            await asyncio.to_thread(engine.release_reservation, t.reservation_id)
        if approve:
            t.result = await _execute(t.call, via=f"human:{who}", reservation_id=t.reservation_id)
            await asyncio.to_thread(store.save_ticket, t.to_record())
        return t.to_dict()

    @app.post("/approvals/{ticket_id}/approve", dependencies=[Depends(require_admin_token)])
    async def approve(ticket_id: str, body: ApprovalIn = ApprovalIn()):
        return await _resolve(ticket_id, True, body.approver)

    @app.post("/approvals/{ticket_id}/deny", dependencies=[Depends(require_admin_token)])
    async def deny(ticket_id: str, body: ApprovalIn = ApprovalIn()):
        return await _resolve(ticket_id, False, body.approver)

    # ---- audit ----
    @app.get("/audit", dependencies=[Depends(require_admin_token)])
    async def audit_list(limit: int = 100, agent_id: str | None = None):
        try:
            return await asyncio.to_thread(audit.entries, limit=limit, agent_id=agent_id)
        except RuntimeError as e:
            raise HTTPException(503, "audit integrity verification failed") from e

    @app.get("/audit/verify", dependencies=[Depends(require_admin_token)])
    async def audit_verify():
        ok, bad, count = await asyncio.to_thread(audit.verify_with_count)
        return {"ok": ok, "first_bad_seq": bad, "entries": count}

    return app


app = create_app()
