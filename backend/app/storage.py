"""SQLite-backed state for mandates, approvals, and policy accounting."""
from __future__ import annotations

import atexit
import json
from contextlib import contextmanager
from decimal import Decimal
from typing import Iterator

from sqlalchemy import Column, Float, Integer, MetaData, String, Table, Text, create_engine, delete, select, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import Connection, Engine

from .models import MONEY_MOVING, Mandate, ToolCall, Verdict


class StateStore:
    def __init__(self, database_url: str):
        self.engine: Engine = create_engine(
            database_url,
            connect_args={"check_same_thread": False, "timeout": 30},
        )
        self.metadata = MetaData()
        self.mandates = Table(
            "mandates",
            self.metadata,
            Column("agent_id", String, primary_key=True),
            Column("data", Text, nullable=False),
        )
        self.tickets = Table(
            "tickets",
            self.metadata,
            Column("id", String, primary_key=True),
            Column("agent_id", String, nullable=False, index=True),
            Column("status", String, nullable=False, index=True),
            Column("created", Float, nullable=False),
            Column("data", Text, nullable=False),
        )
        self.policy_events = Table(
            "policy_events",
            self.metadata,
            Column("id", Integer, primary_key=True, autoincrement=True),
            Column("agent_id", String, nullable=False, index=True),
            Column("happened_at", Float, nullable=False, index=True),
            Column("amount", String),
            Column("status", String, nullable=False),
        )
        self.metadata.create_all(self.engine)
        atexit.register(self.dispose)

    @contextmanager
    def _write(self) -> Iterator[Connection]:
        connection = self.engine.connect()
        try:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def save_mandate(self, data: dict) -> None:
        statement = sqlite_insert(self.mandates).values(
            agent_id=data["agent_id"], data=json.dumps(data)
        )
        statement = statement.on_conflict_do_update(
            index_elements=[self.mandates.c.agent_id], set_={"data": statement.excluded.data}
        )
        with self._write() as connection:
            connection.execute(statement)

    def get_mandate(self, agent_id: str) -> dict | None:
        with self.engine.connect() as connection:
            value = connection.execute(
                select(self.mandates.c.data).where(self.mandates.c.agent_id == agent_id)
            ).scalar_one_or_none()
        return None if value is None else json.loads(value)

    def list_mandates(self) -> list[dict]:
        with self.engine.connect() as connection:
            values = connection.execute(select(self.mandates.c.data)).scalars().all()
        return [json.loads(value) for value in values]

    def save_ticket(self, data: dict) -> None:
        statement = sqlite_insert(self.tickets).values(
            id=data["id"],
            agent_id=data["call"]["agent_id"],
            status=data["status"],
            created=data["created"],
            data=json.dumps(data),
        )
        statement = statement.on_conflict_do_update(
            index_elements=[self.tickets.c.id],
            set_={
                "status": statement.excluded.status,
                "created": statement.excluded.created,
                "data": statement.excluded.data,
            },
        )
        with self._write() as connection:
            connection.execute(statement)

    def list_tickets(self, status: str | None = None) -> list[dict]:
        query = select(self.tickets.c.data).order_by(self.tickets.c.created.desc())
        if status is not None:
            query = query.where(self.tickets.c.status == status)
        with self.engine.connect() as connection:
            values = connection.execute(query).scalars().all()
        return [json.loads(value) for value in values]

    def get_ticket(self, ticket_id: str) -> dict | None:
        with self.engine.connect() as connection:
            value = connection.execute(
                select(self.tickets.c.data).where(self.tickets.c.id == ticket_id)
            ).scalar_one_or_none()
        return None if value is None else json.loads(value)

    def claim_ticket_resolution(self, ticket_id: str, status: str, resolved_by: str,
                                now: float) -> tuple[dict | None, str | None]:
        if status not in {"approved", "denied"}:
            raise ValueError(f"invalid resolution status: {status}")
        with self._write() as connection:
            row = connection.execute(
                select(self.tickets.c.status, self.tickets.c.data)
                .where(self.tickets.c.id == ticket_id)
            ).one_or_none()
            if row is None:
                return None, "unknown ticket"
            current_status, value = row
            if current_status != "pending":
                return None, f"ticket already {current_status}"

            record = json.loads(value)
            if status == "approved":
                mandate_value = connection.execute(
                    select(self.mandates.c.data)
                    .where(self.mandates.c.agent_id == record["call"]["agent_id"])
                ).scalar_one_or_none()
                if mandate_value is None:
                    return None, "mandate revoked; cannot approve"
                mandate = json.loads(mandate_value)
                if mandate.get("revoked"):
                    return None, "mandate revoked; cannot approve"
                expires_at = mandate.get("expires_at")
                if expires_at is not None and expires_at < now:
                    return None, "mandate expired; cannot approve"

            record["status"], record["resolved_by"] = status, resolved_by
            result = connection.execute(
                update(self.tickets)
                .where(self.tickets.c.id == ticket_id, self.tickets.c.status == "pending")
                .values(status=status, data=json.dumps(record))
            )
            if result.rowcount != 1:
                return None, "ticket resolution already claimed"
            return record, None

    def restore_pending_ticket(self, ticket_id: str, resolved_by: str) -> None:
        with self._write() as connection:
            row = connection.execute(
                select(self.tickets.c.status, self.tickets.c.data)
                .where(self.tickets.c.id == ticket_id)
            ).one_or_none()
            if row is None:
                raise RuntimeError("ticket disappeared during resolution rollback")
            status, value = row
            record = json.loads(value)
            if status not in {"approved", "denied"} or record.get("resolved_by") != resolved_by:
                raise RuntimeError("ticket resolution changed before rollback")
            record["status"], record["resolved_by"] = "pending", None
            result = connection.execute(
                update(self.tickets)
                .where(self.tickets.c.id == ticket_id, self.tickets.c.status == status)
                .values(status="pending", data=json.dumps(record))
            )
            if result.rowcount != 1:
                raise RuntimeError("ticket resolution rollback was not applied")

    def policy_state(self, agent_id: str, now: float, window: float = 3600) -> tuple[Decimal, int]:
        with self.engine.connect() as connection:
            rows = connection.execute(
                select(self.policy_events.c.amount, self.policy_events.c.happened_at).where(
                    self.policy_events.c.agent_id == agent_id
                )
            ).all()
        spent = sum((Decimal(amount) for amount, _ in rows if amount is not None), Decimal("0"))
        recent = sum(1 for _, happened_at in rows if now - happened_at < window)
        return spent, recent

    def atomic_admit(self, mandate: Mandate, call: ToolCall, now: float, evaluator,
                     allow_escalate: bool = False) -> tuple[Verdict, int | None]:
        with self._write() as connection:
            rows = connection.execute(
                select(self.policy_events.c.amount, self.policy_events.c.happened_at).where(
                    self.policy_events.c.agent_id == call.agent_id
                )
            ).all()
            spent = sum((Decimal(amount) for amount, _ in rows if amount is not None), Decimal("0"))
            recent = sum(1 for _, happened_at in rows if now - happened_at < 3600)
            verdict = evaluator(mandate, call, (spent, recent))
            should_reserve = verdict.decision.value == 0 or (
                allow_escalate and verdict.decision.value < 2
            )
            if not should_reserve:
                return verdict, None

            amount = str(call.amount) if call.tool in MONEY_MOVING and call.amount is not None else None
            result = connection.execute(
                self.policy_events.insert().values(
                    agent_id=call.agent_id,
                    happened_at=now,
                    amount=amount,
                    status="reserved",
                )
            )
            return verdict, result.inserted_primary_key[0]

    def record(self, call: ToolCall, now: float) -> None:
        amount = str(call.amount) if call.tool in MONEY_MOVING and call.amount is not None else None
        with self._write() as connection:
            connection.execute(
                self.policy_events.insert().values(
                    agent_id=call.agent_id, happened_at=now, amount=amount, status="committed"
                )
            )

    def commit_reservation(self, reservation_id: int) -> None:
        with self._write() as connection:
            connection.execute(
                update(self.policy_events)
                .where(self.policy_events.c.id == reservation_id)
                .values(status="committed")
            )

    def release_reservation(self, reservation_id: int) -> None:
        with self._write() as connection:
            connection.execute(
                delete(self.policy_events).where(self.policy_events.c.id == reservation_id)
            )

    def dispose(self) -> None:
        self.engine.dispose()