"""Plain-dataclass domain models. Deliberately dependency-free so the safety
core can be unit-tested anywhere; FastAPI/pydantic only live at the edge."""
from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from enum import IntEnum

# Tools that move money. Everything else is treated as read-only.
MONEY_MOVING = frozenset({"create_payout", "create_order", "capture_order", "create_refund"})
# PayPal's MCP server names -> our canonical names.
TOOL_ALIASES = {"pay_order": "capture_order"}


def normalize_tool(name: str) -> str:
    return TOOL_ALIASES.get(name, name)


class Decision(IntEnum):
    """Ordered so max() == 'tightest'. A judge may only ever raise this."""

    ALLOW = 0
    ESCALATE = 1
    DENY = 2

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Source:
    """A piece of context the agent read before proposing the call."""

    url: str
    trust: str = "untrusted"  # "trusted" | "untrusted"
    excerpt: str = ""


@dataclass
class Mandate:
    """What a human authorised an agent to do. The guide (feed-forward)."""

    agent_id: str
    task: str
    currency: str = "USD"
    budget_total: Decimal = Decimal("100")
    per_tx_cap: Decimal = Decimal("50")
    approval_over: Decimal = Decimal("25")
    allowed_tools: frozenset = frozenset({"create_payout"})
    allowed_payees: frozenset = frozenset()
    payee_mode: str = "allowlist"  # "allowlist" (deny new) | "approve_new" (escalate new)
    max_tx_per_hour: int = 5
    trusted_origins: frozenset = frozenset()
    expires_at: float | None = None
    revoked: bool = False

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "task": self.task,
            "currency": self.currency,
            "budget_total": str(self.budget_total),
            "per_tx_cap": str(self.per_tx_cap),
            "approval_over": str(self.approval_over),
            "allowed_tools": sorted(self.allowed_tools),
            "allowed_payees": sorted(self.allowed_payees),
            "payee_mode": self.payee_mode,
            "max_tx_per_hour": self.max_tx_per_hour,
            "trusted_origins": sorted(self.trusted_origins),
            "expires_at": self.expires_at,
            "revoked": self.revoked,
        }


@dataclass
class ToolCall:
    agent_id: str
    tool: str
    amount: Decimal | None = None
    currency: str = "USD"
    payee: str | None = None
    args: dict = field(default_factory=dict)
    sources: list[Source] = field(default_factory=list)
    agent_note: str = ""

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "tool": self.tool,
            "amount": None if self.amount is None else str(self.amount),
            "currency": self.currency,
            "payee": self.payee,
            "args": self.args,
            "sources": [
                {"url": s.url, "trust": s.trust, "excerpt": s.excerpt[:500]} for s in self.sources
            ],
            "agent_note": self.agent_note,
        }


@dataclass(frozen=True)
class Finding:
    rule: str
    decision: Decision
    detail: str

    def to_dict(self) -> dict:
        return {"rule": self.rule, "decision": self.decision.label, "detail": self.detail}


@dataclass
class Verdict:
    decision: Decision
    findings: list[Finding]

    def to_dict(self) -> dict:
        return {"decision": self.decision.label, "findings": [f.to_dict() for f in self.findings]}


def _money(v) -> Decimal | None:
    if v is None:
        return None
    try:
        value = Decimal(str(v))
    except InvalidOperation as e:
        raise ValueError(f"invalid amount: {v!r}") from e
    if not value.is_finite():
        raise ValueError(f"non-finite amount: {v!r}")
    quantized = value.quantize(Decimal("0.01"))
    if value != quantized:
        raise ValueError(f"amount must be quantized to 2 decimal places: {v!r}")
    return quantized


def mandate_from_dict(d: dict) -> Mandate:
    return Mandate(
        agent_id=d["agent_id"],
        task=d.get("task", ""),
        currency=d.get("currency", "USD"),
        budget_total=_money(d.get("budget_total", "100")),
        per_tx_cap=_money(d.get("per_tx_cap", "50")),
        approval_over=_money(d.get("approval_over", "25")),
        allowed_tools=frozenset(normalize_tool(t) for t in d.get("allowed_tools", ["create_payout"])),
        allowed_payees=frozenset(p.lower() for p in d.get("allowed_payees", [])),
        payee_mode=d.get("payee_mode", "allowlist"),
        max_tx_per_hour=int(d.get("max_tx_per_hour", 5)),
        trusted_origins=frozenset(str(origin).strip() for origin in d.get("trusted_origins", [])),
        expires_at=d.get("expires_at"),
        revoked=bool(d.get("revoked", False)),
    )


def call_from_dict(d: dict) -> ToolCall:
    return ToolCall(
        agent_id=d["agent_id"],
        tool=normalize_tool(d["tool"]),
        amount=_money(d.get("amount")),
        currency=d.get("currency", "USD"),
        payee=d.get("payee"),
        args=dict(d.get("args") or {}),
        sources=[
            Source(s["url"], s.get("trust", "untrusted"), s.get("excerpt", ""))
            for s in d.get("sources", [])
        ],
        agent_note=d.get("agent_note", ""),
    )
