"""Tamper-evident audit log: every entry commits to the previous one (SHA-256 chain).
Editing, deleting or reordering any past entry breaks verification from that point on."""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from typing import Callable

GENESIS = "0" * 64


def _canonical(body: dict) -> str:
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)


def _digest(prev_hash: str, body: dict) -> str:
    return hashlib.sha256((prev_hash + _canonical(body)).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: str | None = None, clock: Callable[[], float] = time.time):
        self.path = path
        self.clock = clock
        self._lock = threading.Lock()
        self._entries: list[dict] = []
        if path and os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                self._entries = [json.loads(line) for line in fh if line.strip()]

    def append(self, event: str, agent_id: str, payload: dict) -> dict:
        # normalise so in-memory and reloaded entries hash identically
        payload = json.loads(json.dumps(payload, default=str))
        with self._lock:
            prev = self._entries[-1]["hash"] if self._entries else GENESIS
            body = {
                "seq": len(self._entries),
                "ts": round(self.clock(), 3),
                "event": event,
                "agent_id": agent_id,
                "payload": payload,
            }
            entry = {**body, "prev_hash": prev, "hash": _digest(prev, body)}
            self._entries.append(entry)
            if self.path:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, default=str) + "\n")
            return entry

    def entries(self, limit: int | None = None, agent_id: str | None = None) -> list[dict]:
        with self._lock:
            rows = [e for e in self._entries if agent_id is None or e["agent_id"] == agent_id]
        return rows[-limit:] if limit else rows

    def verify(self) -> tuple[bool, int | None]:
        """Return (ok, first_bad_seq)."""
        prev = GENESIS
        with self._lock:
            for i, e in enumerate(self._entries):
                body = {k: e[k] for k in ("seq", "ts", "event", "agent_id", "payload")}
                if e["seq"] != i or e["prev_hash"] != prev or e["hash"] != _digest(prev, body):
                    return False, i
                prev = e["hash"]
        return True, None
