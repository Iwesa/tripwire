"""Tamper-evident audit log: every entry commits to the previous one (SHA-256 chain).
Editing, deleting or reordering any past entry breaks verification from that point on."""
from __future__ import annotations

import hashlib
import hmac
import asyncio
import json
import os
import secrets
import threading
import time
from contextlib import contextmanager
from typing import Callable

GENESIS = "0" * 64
DEFAULT_MAX_BYTES = 10 * 1024 * 1024
_FILE_LOCKS: dict[str, threading.Lock] = {}
_FILE_LOCKS_GUARD = threading.Lock()


def _canonical(body: dict) -> str:
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)


def _digest(prev_hash: str, body: dict) -> str:
    return hashlib.sha256((prev_hash + _canonical(body)).encode("utf-8")).hexdigest()


def _signature(key: bytes, entry: dict) -> str:
    signed = {name: value for name, value in entry.items() if name != "hmac"}
    return hmac.new(key, _canonical(signed).encode("utf-8"), hashlib.sha256).hexdigest()


def _process_file_lock(path: str) -> threading.Lock:
    normalized = os.path.normcase(os.path.abspath(path))
    with _FILE_LOCKS_GUARD:
        return _FILE_LOCKS.setdefault(normalized, threading.Lock())


class AuditLog:
    def __init__(self, path: str | None = None, clock: Callable[[], float] = time.time,
                 hmac_key: str | bytes | None = None, max_bytes: int = DEFAULT_MAX_BYTES):
        if max_bytes <= 0:
            raise ValueError("audit rotation size must be greater than zero")
        self.path = path
        if self.path:
            directory = os.path.dirname(self.path)
            if directory:
                os.makedirs(directory, exist_ok=True)
        self.max_bytes = max_bytes
        self.clock = clock
        self._lock = threading.Lock()
        self._file_thread_lock = _process_file_lock(path) if path else None
        self._write_failed = False
        if hmac_key is None:
            hmac_key = os.getenv("TRIPWIRE_AUDIT_HMAC_KEY")
        if isinstance(hmac_key, str):
            hmac_key = hmac_key.encode("utf-8")
        if not hmac_key:
            if path:
                raise ValueError("TRIPWIRE_AUDIT_HMAC_KEY is required for a persisted audit log")
            hmac_key = secrets.token_bytes(32)
        if len(hmac_key) < 32:
            raise ValueError("audit HMAC key must be at least 32 bytes")
        self._hmac_key = hmac_key
        self._entries: list[dict] = []
        if path and os.path.exists(path):
            with self._file_lock():
                self._entries, _, _ = self._read_file_entries()

    @contextmanager
    def _file_lock(self):
        if self.path is None:
            yield
            return
        lock_path = self.path + ".lock"
        with self._file_thread_lock:
            with open(lock_path, "a+b") as lock_file:
                if os.name == "nt":
                    import msvcrt

                    lock_file.seek(0, os.SEEK_END)
                    if lock_file.tell() == 0:
                        lock_file.write(b"\0")
                        lock_file.flush()
                    lock_file.seek(0)
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
                    try:
                        yield
                    finally:
                        lock_file.seek(0)
                        msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                    try:
                        yield
                    finally:
                        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def _read_file_entries(self) -> tuple[list[dict], int | None, int]:
        entries = []
        if self.path is None:
            return entries, None, 0
        parse_error = None
        count = 0
        for file_path in self._audit_file_paths():
            with open(file_path, "rb") as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    count += 1
                    try:
                        entries.append(json.loads(line))
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        if parse_error is None:
                            parse_error = count - 1
        return entries, parse_error, count

    def _audit_file_paths(self) -> list[str]:
        if self.path is None:
            return []
        directory = os.path.dirname(self.path) or "."
        prefix = os.path.basename(self.path) + "."
        archived = []
        for name in os.listdir(directory):
            if not name.startswith(prefix):
                continue
            suffix = name[len(prefix):]
            if suffix.isdigit():
                archived.append((int(suffix), os.path.join(directory, name)))
        return [
            file_path for _, file_path in sorted(archived, reverse=True)
        ] + ([self.path] if os.path.exists(self.path) else [])

    async def append(self, event: str, agent_id: str, payload: dict) -> dict:
        return await asyncio.to_thread(self._append_sync, event, agent_id, payload)

    def _append_sync(self, event: str, agent_id: str, payload: dict) -> dict:
        # normalise so in-memory and reloaded entries hash identically
        payload = json.loads(json.dumps(payload, default=str))
        with self._lock:
            if self._write_failed:
                raise RuntimeError("audit integrity is uncertain after a failed write")
            if self.path:
                with self._file_lock():
                    self._entries, parse_error, _ = self._read_file_entries()
                    valid, bad_seq = self._verify_entries(self._entries)
                    if parse_error is not None:
                        valid, bad_seq = False, parse_error
                    if not valid:
                        raise RuntimeError(f"audit integrity failure at sequence {bad_seq}")
                    entry = self._create_entry(event, agent_id, payload)
                    try:
                        self._write_entry(entry)
                    except OSError:
                        self._write_failed = True
                        raise
                    self._entries.append(entry)
                    return entry
            valid, bad_seq = self._verify_entries(self._entries)
            if not valid:
                raise RuntimeError(f"audit integrity failure at sequence {bad_seq}")
            entry = self._create_entry(event, agent_id, payload)
            self._entries.append(entry)
            return entry

    def _create_entry(self, event: str, agent_id: str, payload: dict) -> dict:
        prev = self._entries[-1]["hash"] if self._entries else GENESIS
        body = {
            "seq": len(self._entries),
            "ts": round(self.clock(), 3),
            "event": event,
            "agent_id": agent_id,
            "payload": payload,
        }
        entry = {**body, "prev_hash": prev, "hash": _digest(prev, body)}
        entry["hmac"] = _signature(self._hmac_key, entry)
        return entry

    def _write_entry(self, entry: dict) -> None:
        serialized = json.dumps(entry, default=str) + "\n"
        if os.path.exists(self.path) and os.path.getsize(self.path):
            if os.path.getsize(self.path) + len(serialized.encode("utf-8")) > self.max_bytes:
                archived = self._audit_file_paths()[:-1]
                for archived_path in archived:
                    suffix = int(archived_path.rsplit(".", 1)[1])
                    os.replace(archived_path, f"{self.path}.{suffix + 1}")
                os.replace(self.path, f"{self.path}.1")
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(serialized)
            fh.flush()
            os.fsync(fh.fileno())

    def entries(self, limit: int | None = None, agent_id: str | None = None) -> list[dict]:
        with self._lock:
            valid, bad_seq, entries, _ = self._verified_entries_locked()
            if not valid:
                raise RuntimeError(f"audit integrity failure at sequence {bad_seq}")
            rows = [e for e in entries if agent_id is None or e["agent_id"] == agent_id]
            selected = rows[-limit:] if limit else rows
            return json.loads(json.dumps(selected))

    def _verified_entries_locked(self) -> tuple[bool, int | None, list[dict], int]:
        parse_error = None
        count = len(self._entries)
        if self.path:
            with self._file_lock():
                self._entries, parse_error, count = self._read_file_entries()
        valid, bad_seq = self._verify_entries(self._entries)
        if parse_error is not None:
            valid, bad_seq = False, parse_error
        if self._write_failed:
            valid, bad_seq = False, len(self._entries)
        return valid, bad_seq, self._entries, count

    def _verify_entries(self, entries: list[dict]) -> tuple[bool, int | None]:
        prev = GENESIS
        for i, entry in enumerate(entries):
            try:
                if not isinstance(entry, dict):
                    return False, i
                body = {k: entry[k] for k in ("seq", "ts", "event", "agent_id", "payload")}
                if not hmac.compare_digest(entry.get("hmac", ""), _signature(self._hmac_key, entry)):
                    return False, i
                if entry["seq"] != i or entry["prev_hash"] != prev or entry["hash"] != _digest(prev, body):
                    return False, i
            except (AttributeError, KeyError, TypeError, ValueError):
                return False, i
            prev = entry["hash"]
        return True, None

    def verify_with_count(self) -> tuple[bool, int | None, int]:
        """Verify one disk snapshot and return its entry count."""
        with self._lock:
            valid, bad_seq, _, count = self._verified_entries_locked()
            return valid, bad_seq, count

    def verify(self) -> tuple[bool, int | None]:
        """Return (ok, first_bad_seq), checking HMACs before the hash chain."""
        valid, bad_seq, _ = self.verify_with_count()
        return valid, bad_seq
