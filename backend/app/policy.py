"""Tripwire policy engine.

Design rules (see CLAUDE.md invariants):
  1. Deterministic rules decide. They cannot be talked out of a verdict.
  2. An LLM judge may only TIGHTEN a verdict (allow -> escalate -> deny), never loosen.
  3. Fail closed: missing data, judge errors, odd inputs => stricter, not looser.
  4. Every rule must trace to an attack case in evals/redteam_cases.json.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import inspect
import math
import re
import time
import unicodedata
from collections import Counter
from decimal import Decimal
from typing import Callable

from .models import MONEY_MOVING, Decision, Finding, Mandate, ToolCall, Verdict

# --- injection detection --------------------------------------------------
INJECTION_PATTERNS: dict[str, re.Pattern] = {
    name: re.compile(rx, re.I | re.S)
    for name, rx in {
        "override_instructions": r"\b(ignore|disregard|forget)\b.{0,30}\b(previous|prior|above|earlier|all)\b.{0,30}\b(instructions?|rules?|prompts?)\b",
        "role_hijack": r"\byou are now\b|\bact as (an? )?(admin|administrator|developer|system)\b|\bnew (system )?instructions?\b",
        "secrecy": r"\b(do not|don't|never)\b.{0,20}\b(tell|inform|alert|notify|mention)\b.{0,20}\b(user|human|owner)\b",
        "urgent_payment": r"\b(send|pay|transfer|wire|refund|payout)\b.{0,60}\b(immediately|right now|urgent|asap)\b",
        "tool_directive": r"\b(call|invoke|use|execute)\b.{0,20}\b(create_payout|create_order|capture_order|create_refund|pay_order)\b",
    }.items()
}

_BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/_-])")


def _normalize_untrusted_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    return "".join(char for char in normalized if unicodedata.category(char) != "Cf")


def _separated_untrusted_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    return "".join(" " if unicodedata.category(char) == "Cf" else char for char in normalized)


def _decoded_texts(text: str) -> list[str]:
    decoded = []
    for match in _BASE64_TOKEN.finditer(text):
        token = match.group(0)
        try:
            raw = base64.b64decode(
                token + "=" * (-len(token) % 4),
                altchars=b"-_",
                validate=True,
            )
            candidate = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        printable = sum(char.isprintable() or char.isspace() for char in candidate)
        if candidate and printable / len(candidate) >= 0.85:
            decoded.append(candidate)
        if len(decoded) == 32:
            break
    return decoded


def injection_signals(text: str, classifier: Callable[[str], bool] | None = None) -> list[str]:
    """Detect known injection phrases after normalization and optional classification."""
    source = str(text or "")
    normalized = _normalize_untrusted_text(source)
    variants = [
        normalized,
        _separated_untrusted_text(source),
        *(_normalize_untrusted_text(item) for item in _decoded_texts(normalized)),
    ]
    signals = [name for name, rx in INJECTION_PATTERNS.items() if any(rx.search(item) for item in variants)]
    if classifier is not None:
        classified = classifier("\n".join(variants))
        if inspect.isawaitable(classified):
            classified.close()
            raise RuntimeError("asynchronous injection classifier requires evaluate_async")
        if classified:
            signals.append("prompt_injection")
    return signals


# --- lookalike payee detection -------------------------------------------
_HOMOGLYPHS = str.maketrans({"1": "l", "0": "o", "5": "s", "3": "e", "$": "s"})
_LOOKALIKE_THRESHOLD = 0.85


def _norm(s: str) -> str:
    return s.lower().translate(_HOMOGLYPHS).replace("rn", "m").replace("vv", "w")


def _character_vector(value: str) -> Counter:
    return Counter(
        (size, value[index : index + size])
        for size in (2, 3)
        for index in range(len(value) - size + 1)
    )


def _cosine_similarity(left: Counter, right: Counter) -> float:
    if not left or not right:
        return 0.0
    dot = sum(left[gram] * right[gram] for gram in left.keys() & right.keys())
    left_norm = math.sqrt(sum(weight * weight for weight in left.values()))
    right_norm = math.sqrt(sum(weight * weight for weight in right.values()))
    return dot / (left_norm * right_norm)


def lookalike_of(payee: str, allowed) -> str | None:
    """Return the allowlisted payee this one imitates, if any."""
    p = _norm(payee)
    p_vector = _character_vector(p)
    for a in allowed:
        if payee.lower() == a.lower():
            continue
        candidate = _norm(a)
        if p == candidate or _cosine_similarity(p_vector, _character_vector(candidate)) >= _LOOKALIKE_THRESHOLD:
            return a
    return None


class PolicyEngine:
    def __init__(self, judge=None, clock: Callable[[], float] = time.time,
                 disabled_rules: frozenset = frozenset(), state_store=None,
                 injection_classifier: Callable[[str], bool] | None = None):
        self.judge = judge
        self.clock = clock
        self.state_store = state_store
        self.injection_classifier = injection_classifier
        # Test-only: lets the eval suite prove every rule is necessary (see test_every_rule_is_necessary).
        self.disabled_rules = disabled_rules
        self._spent: dict[str, Decimal] = {}
        self._times: dict[str, list[float]] = {}

    # -- state ------------------------------------------------------------
    def spent(self, agent_id: str) -> Decimal:
        if self.state_store is not None:
            return self.state_store.policy_state(agent_id, self.clock())[0]
        return self._spent.get(agent_id, Decimal("0"))

    def recent_count(self, agent_id: str, window: float = 3600) -> int:
        now = self.clock()
        if self.state_store is not None:
            return self.state_store.policy_state(agent_id, now, window)[1]
        return sum(1 for t in self._times.get(agent_id, []) if now - t < window)

    def record(self, call: ToolCall) -> None:
        """Call after a money-moving action actually executes (or is approved)."""
        if self.state_store is not None:
            self.state_store.record(call, self.clock())
            return
        if call.tool in MONEY_MOVING and call.amount is not None:
            self._spent[call.agent_id] = self.spent(call.agent_id) + call.amount
        self._times.setdefault(call.agent_id, []).append(self.clock())

    def evaluate_and_reserve(self, mandate: Mandate, call: ToolCall,
                             reserve_escalations: bool = False) -> tuple[Verdict, int | None]:
        if self.state_store is None:
            return self.evaluate(mandate, call), None
        return self.state_store.atomic_admit(
            mandate,
            call,
            self.clock(),
            lambda m, c, state: self.evaluate(m, c, state),
            allow_escalate=reserve_escalations,
        )

    async def evaluate_async(
        self,
        mandate: Mandate,
        call: ToolCall,
        state: tuple[Decimal, int] | None = None,
    ) -> Verdict:
        verdict, additional = await self._evaluate_external(mandate, call, state)
        return self._combine(verdict, additional)

    async def evaluate_and_reserve_async(
        self,
        mandate: Mandate,
        call: ToolCall,
        reserve_escalations: bool = False,
    ) -> tuple[Verdict, int | None]:
        if self.state_store is None:
            return await self.evaluate_async(mandate, call), None

        _, additional = await self._evaluate_external(mandate, call)

        def evaluator(m, c, state):
            verdict = self.evaluate(
                m, c, state, include_judge=False, include_classifier=False
            )
            return self._combine(verdict, additional)

        return await asyncio.to_thread(
            self.state_store.atomic_admit,
            mandate,
            call,
            self.clock(),
            evaluator,
            allow_escalate=reserve_escalations,
        )

    async def _evaluate_external(
        self,
        mandate: Mandate,
        call: ToolCall,
        state: tuple[Decimal, int] | None = None,
    ) -> tuple[Verdict, list[Finding]]:
        verdict = await asyncio.to_thread(
            self.evaluate,
            mandate,
            call,
            state,
            include_judge=False,
            include_classifier=False,
        )
        if verdict.decision == Decision.DENY:
            return verdict, []

        additional: list[Finding] = []
        is_money = call.tool in MONEY_MOVING
        if self.injection_classifier is not None:
            for source in call.sources:
                if source.trust != "untrusted":
                    continue
                try:
                    flagged = await self._invoke_async(
                        self.injection_classifier, source.excerpt or ""
                    )
                except Exception as error:
                    additional.append(Finding(
                        "injection_classifier_error",
                        Decision.ESCALATE,
                        f"injection classifier unavailable, failing closed: {type(error).__name__}",
                    ))
                    continue
                if flagged and is_money and not any(
                    item.rule == "injection_signal" for item in verdict.findings
                ):
                    additional.append(Finding(
                        "injection_signal",
                        Decision.ESCALATE,
                        f"untrusted source {source.url} flagged by injection classifier",
                    ))

        current = self._combine(verdict, additional)
        if self.judge is not None and is_money and current.decision < Decision.DENY:
            try:
                result = await self._invoke_async(
                    self.judge.judge, mandate, call, tuple(current.findings)
                )
                additional.append(Finding("llm_judge", result.decision, result.rationale))
            except Exception as error:
                additional.append(Finding(
                    "llm_judge_error",
                    Decision.ESCALATE,
                    f"judge unavailable, failing closed: {type(error).__name__}",
                ))
        return verdict, additional

    @staticmethod
    async def _invoke_async(function, *args):
        if (inspect.iscoroutinefunction(function)
                or inspect.iscoroutinefunction(getattr(function, "__call__", None))):
            return await function(*args)
        result = await asyncio.to_thread(function, *args)
        if inspect.isawaitable(result):
            return await result
        return result

    @staticmethod
    def _combine(verdict: Verdict, additional: list[Finding]) -> Verdict:
        findings = [*verdict.findings, *additional]
        decision = max((item.decision for item in findings), default=Decision.ALLOW)
        return Verdict(decision, findings)

    def commit_reservation(self, reservation_id: int) -> None:
        self.state_store.commit_reservation(reservation_id)

    def release_reservation(self, reservation_id: int) -> None:
        self.state_store.release_reservation(reservation_id)

    # -- evaluation -------------------------------------------------------
    def evaluate(
        self,
        mandate: Mandate,
        call: ToolCall,
        state: tuple[Decimal, int] | None = None,
        *,
        include_judge: bool = True,
        include_classifier: bool = True,
    ) -> Verdict:
        f: list[Finding] = []

        def add(rule: str, decision: Decision, detail: str) -> None:
            if rule not in self.disabled_rules:
                f.append(Finding(rule, decision, detail))

        # 0. hard gates
        if mandate.revoked:
            add("kill_switch", Decision.DENY, "mandate revoked by owner")
            return self._verdict(f)
        if mandate.expires_at is not None and mandate.expires_at < self.clock():
            add("mandate_expired", Decision.DENY, "mandate has expired")
            return self._verdict(f)
        if call.agent_id != mandate.agent_id:
            add("agent_mismatch", Decision.DENY, "call agent does not match mandate agent")
            return self._verdict(f)
        if call.tool not in mandate.allowed_tools:
            add("tool_not_allowed", Decision.DENY, f"tool '{call.tool}' is not in this mandate")
            return self._verdict(f)

        is_money = call.tool in MONEY_MOVING

        if is_money:
            self._money_rules(mandate, call, add, state)
            self._payee_rules(mandate, call, add)

        self._provenance_rules(
            mandate, call, is_money, add, include_classifier=include_classifier
        )

        # LLM judge: advisory, tighten-only, fail-closed.
        if (include_judge and self.judge is not None and is_money
                and max((x.decision for x in f), default=Decision.ALLOW) < Decision.DENY):
            try:
                jr = self.judge.judge(mandate, call, tuple(f))
                if inspect.isawaitable(jr):
                    jr.close()
                    raise RuntimeError("asynchronous judge requires evaluate_async")
                add("llm_judge", jr.decision, jr.rationale)
            except Exception as e:  # noqa: BLE001 - judge failure must never loosen
                add("llm_judge_error", Decision.ESCALATE, f"judge unavailable, failing closed: {type(e).__name__}")

        return self._verdict(f)

    # -- rule groups ------------------------------------------------------
    def _money_rules(self, m: Mandate, c: ToolCall, add,
                     state: tuple[Decimal, int] | None = None) -> None:
        if c.amount is None:
            add("amount_missing", Decision.DENY, "money-moving call without a verifiable amount")
            return
        if not c.amount.is_finite():
            add("amount_invalid", Decision.DENY, f"non-finite amount {c.amount}")
            return
        if c.amount <= 0:
            add("amount_invalid", Decision.DENY, f"non-positive amount {c.amount}")
            return
        if c.amount != c.amount.quantize(Decimal("0.01")):
            add("amount_invalid", Decision.DENY, f"amount must be quantized to 2 decimal places: {c.amount}")
            return
        if c.currency != m.currency:
            add("currency_mismatch", Decision.DENY, f"{c.currency} != mandate currency {m.currency}")
        if c.amount > m.per_tx_cap:
            add("per_tx_cap", Decision.DENY, f"{c.amount} exceeds per-transaction cap {m.per_tx_cap}")
        spent = state[0] if state is not None else self.spent(c.agent_id)
        if spent + c.amount > m.budget_total:
            add("budget_exceeded", Decision.DENY, f"spent {spent} + {c.amount} > budget {m.budget_total}")
        n = state[1] if state is not None else self.recent_count(c.agent_id)
        if n >= m.max_tx_per_hour:
            add("velocity", Decision.DENY, f"{n} transactions in the last hour (max {m.max_tx_per_hour})")
        if m.per_tx_cap >= c.amount > m.approval_over:
            add("approval_threshold", Decision.ESCALATE, f"{c.amount} > auto-approve limit {m.approval_over}")

    def _payee_rules(self, m: Mandate, c: ToolCall, add) -> None:
        if not c.payee:
            add("payee_missing", Decision.DENY, "money-moving call without a declared payee")
            return
        if c.payee.lower() in m.allowed_payees:
            return
        imitated = lookalike_of(c.payee, m.allowed_payees)
        if imitated:
            add("lookalike_payee", Decision.DENY, f"'{c.payee}' imitates allowlisted payee '{imitated}'")
        elif m.payee_mode == "allowlist":
            add("payee_not_allowlisted", Decision.DENY, f"'{c.payee}' is not an approved payee")
        else:
            add("new_payee", Decision.ESCALATE, f"first payment to '{c.payee}' needs human approval")

    def _provenance_rules(
        self, m: Mandate, c: ToolCall, is_money: bool, add, *, include_classifier: bool
    ) -> None:
        """Taint tracking: where did the payee/amount come from?"""
        for s in c.sources:
            if s.trust != "untrusted":
                continue
            ex = (s.excerpt or "").lower()
            try:
                signals = injection_signals(
                    s.excerpt, self.injection_classifier if include_classifier else None
                )
            except Exception as error:  # classifier outages must not silently allow untrusted input
                signals = []
                add(
                    "injection_classifier_error",
                    Decision.ESCALATE,
                    f"injection classifier unavailable, failing closed: {type(error).__name__}",
                )
            payee_tainted = bool(c.payee) and c.payee.lower() in ex
            amount_tainted = c.amount is not None and str(c.amount) in ex
            allowlisted = bool(c.payee) and c.payee.lower() in m.allowed_payees

            if is_money and payee_tainted and not allowlisted:
                sev = "with injection patterns " + str(signals) if signals else "unverified"
                add("tainted_payee", Decision.DENY, f"payee came from untrusted content at {s.url} ({sev})")
            elif is_money and signals:
                tag = " (payee/amount echoed from it)" if (payee_tainted or amount_tainted) else ""
                add("injection_signal", Decision.ESCALATE, f"untrusted source {s.url} contains {signals}{tag}")

    @staticmethod
    def _verdict(findings: list[Finding]) -> Verdict:
        decision = max((x.decision for x in findings), default=Decision.ALLOW)
        return Verdict(decision, findings)
