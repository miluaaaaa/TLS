#!/usr/bin/env python3
"""HTTP transport state for the TLS multi-user control plane.

The registry owns users, installations, sessions, groups, and authorization.
This module owns only the network-facing agent credential and command/event
queues.  It never stores a Codex transcript or a local socket path.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Iterable

from tls_multi_registry import Registry, RegistryError


DEFAULT_REGISTRY_DB = Path.home() / ".local/state/tls-multi/multi.sqlite3"
DEFAULT_TRANSPORT_DB = Path.home() / ".local/state/tls-multi/agent.sqlite3"
SESSION_ID = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$", re.IGNORECASE)
SESSION_STATUS = {"unknown", "idle", "running", "offline"}
COMMAND_STATUS = {"queued", "inflight", "completed", "failed"}
EVENT_STATUS = {"pending", "claimed", "sent", "failed"}
DEFAULT_SESSION_FRESHNESS_SECONDS = 30


class TransportError(RegistryError):
    """Expected transport input or state error."""


def now() -> int:
    return int(time.time())


def _registry_path(path: str | Path | None = None) -> Path:
    return Path(path) if path is not None else Path(
        os.environ.get("TLS_MULTI_DB", str(DEFAULT_REGISTRY_DB))
    )


def _transport_path(path: str | Path | None = None) -> Path:
    return Path(path) if path is not None else Path(
        os.environ.get("TLS_MULTI_TRANSPORT_DB", str(DEFAULT_TRANSPORT_DB))
    )


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _new_token() -> str:
    return "tlsa_" + secrets.token_urlsafe(32)


def _text(value: object, field: str, limit: int = 240, required: bool = True) -> str:
    result = str(value or "").strip()
    if required and not result:
        raise TransportError(f"{field} 不能为空")
    if len(result) > limit:
        raise TransportError(f"{field} 过长")
    return result


def _json_object(value: object, field: str, limit: int = 16000) -> tuple[dict[str, Any], str]:
    if not isinstance(value, dict):
        raise TransportError(f"{field} 必须是 JSON 对象")
    try:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise TransportError(f"{field} 不是可序列化的 JSON 对象") from exc
    if len(encoded) > limit:
        raise TransportError(f"{field} 过长")
    return value, encoded


SCHEMA = """
CREATE TABLE IF NOT EXISTS agent_credentials (
    installation_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS agent_commands (
    command_id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL UNIQUE,
    installation_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    open_id TEXT NOT NULL,
    chat_id TEXT NOT NULL DEFAULT '',
    task_id TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('queued', 'inflight', 'completed', 'failed')),
    lease_until INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    result_json TEXT NOT NULL DEFAULT '{}',
    last_error TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_agent_commands_ready
    ON agent_commands(installation_id, status, lease_until, created_at);

CREATE TABLE IF NOT EXISTS agent_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    command_id TEXT NOT NULL UNIQUE,
    installation_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'claimed', 'sent', 'failed')),
    lease_until INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    last_error TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_agent_events_ready
    ON agent_events(status, next_attempt_at, lease_until, event_id);
"""


class TransportStore:
    """Small SQLite-backed queue shared by the gateway and Feishu ingress."""

    def __init__(
        self,
        registry_path: str | Path | None = None,
        transport_path: str | Path | None = None,
    ) -> None:
        self.registry = Registry(_registry_path(registry_path))
        self.path = _transport_path(transport_path)

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.executescript(SCHEMA)
        connection.commit()
        return connection

    def init(self) -> dict[str, Any]:
        with self._connect() as connection:
            connection.commit()
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        return {"path": str(self.path), "schema_version": 1}

    def _credential(self, token: str) -> sqlite3.Row:
        token = _text(token, "agent token", 240)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM agent_credentials WHERE token_hash = ? AND status = 'active'",
                (_token_hash(token),),
            ).fetchone()
        if row is None:
            raise TransportError("agent token 无效或已停用")
        return row

    def _session(self, session_id: str) -> dict[str, Any]:
        sid = _text(session_id, "session_id", 80).lower()
        if not SESSION_ID.fullmatch(sid):
            raise TransportError("session_id 必须是 Codex UUID")
        for item in self.registry.list_sessions():
            if str(item.get("session_id", "")).lower() == sid:
                return item
        raise TransportError(f"找不到 session: {sid}")

    def pair(
        self,
        code: str,
        *,
        name: str = "用户端 TLS Agent",
        hostname: str = "",
    ) -> dict[str, Any]:
        """Consume a one-time registry pairing code and issue an agent token."""

        pairing = self.registry.consume_pairing(code)
        user_id = str(pairing["user_id"])
        installation_id = str(pairing.get("installation_id") or "")
        if installation_id:
            owned = [item for item in self.registry.list_sessions() if item.get("user_id") == user_id]
            # The registry validates the ownership when the pairing code is created;
            # this check only prevents issuing a token for an unknown installation.
            installations = {
                str(item.get("installation_id", ""))
                for item in owned
            }
            if installations and installation_id not in installations:
                raise TransportError("配对安装实例不属于当前用户")
        else:
            installation = self.registry.add_installation(
                user_id,
                _text(name, "installation name", 120),
                hostname=_text(hostname, "hostname", 240, required=False),
            )
            installation_id = str(installation["installation_id"])
        token = _new_token()
        timestamp = now()
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO agent_credentials(installation_id, user_id, token_hash, status, created_at, last_seen_at) "
                "VALUES (?, ?, ?, 'active', ?, ?) "
                "ON CONFLICT(installation_id) DO UPDATE SET user_id = excluded.user_id, "
                "token_hash = excluded.token_hash, status = 'active', last_seen_at = excluded.last_seen_at",
                (installation_id, user_id, _token_hash(token), timestamp, timestamp),
            )
        return {
            "installation_id": installation_id,
            "user_id": user_id,
            "token": token,
        }

    def heartbeat(self, token: str, sessions: Iterable[object]) -> dict[str, Any]:
        credential = self._credential(token)
        installation_id = str(credential["installation_id"])
        accepted: list[dict[str, Any]] = []
        existing = {
            str(item["session_id"]).lower(): item
            for item in self.registry.list_sessions()
            if str(item.get("installation_id", "")) == installation_id
        }
        for raw in sessions:
            if not isinstance(raw, dict):
                raise TransportError("sessions 必须是对象列表")
            sid = _text(raw.get("session_id"), "session_id", 80).lower()
            if not SESSION_ID.fullmatch(sid):
                raise TransportError("session_id 必须是 Codex UUID")
            label = _text(raw.get("label"), "label", 160, required=False)
            workspace = _text(raw.get("workspace"), "workspace", 500, required=False)
            status = _text(raw.get("status", "unknown"), "status")
            if status not in SESSION_STATUS:
                raise TransportError(f"status 必须是 {sorted(SESSION_STATUS)} 之一")
            if sid not in existing:
                item = self.registry.add_session(
                    installation_id,
                    sid,
                    label=label,
                    workspace=workspace,
                    status=status,
                )
            else:
                item = self.registry.update_session(
                    sid,
                    label=label,
                    workspace=workspace,
                    status=status,
                )
            accepted.append(item)
        timestamp = now()
        with self._connect() as connection:
            connection.execute(
                "UPDATE agent_credentials SET last_seen_at = ? WHERE installation_id = ?",
                (timestamp, installation_id),
            )
        return {"installation_id": installation_id, "sessions": accepted, "last_seen_at": timestamp}

    def info(self, token: str) -> dict[str, Any]:
        credential = self._credential(token)
        installation_id = str(credential["installation_id"])
        sessions = [
            item for item in self.registry.list_sessions()
            if str(item.get("installation_id", "")) == installation_id
        ]
        return {
            "installation_id": installation_id,
            "user_id": str(credential["user_id"]),
            "last_seen_at": int(credential["last_seen_at"] or 0),
            "sessions": sessions,
        }

    def session_availability(
        self,
        session_id: str,
        *,
        max_age: int = DEFAULT_SESSION_FRESHNESS_SECONDS,
    ) -> dict[str, Any]:
        """Return a fail-closed liveness snapshot for a shared Session.

        The registry status alone can be stale between heartbeats.  A command
        is only considered deliverable while the owning Agent has reported an
        idle/running status within the freshness window.
        """

        if max_age < 1 or max_age > 3600:
            raise TransportError("max_age 必须在 1 到 3600 之间")
        session = self._session(session_id)
        status = str(session.get("status", "unknown"))
        last_seen_at = int(session.get("last_seen_at") or 0)
        age = max(0, now() - last_seen_at) if last_seen_at else None
        online = status in {"idle", "running"} and age is not None and age <= max_age
        return {
            "session_id": str(session.get("session_id", "")),
            "status": status,
            "last_seen_at": last_seen_at,
            "age_seconds": age,
            "online": online,
        }

    def enqueue(
        self,
        *,
        message_id: str,
        open_id: str,
        chat_id: str,
        session_id: str,
        text: str,
        action: str = "write",
        task_id: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        message_id = _text(message_id, "message_id", 160)
        open_id = _text(open_id, "open_id", 160)
        text = _text(text, "text", 12000)
        session = self._session(session_id)
        installation_id = str(session["installation_id"])
        claimed = self.registry.claim_command(
            message_id,
            open_id,
            chat_id,
            str(session["session_id"]),
            action=action,
            task_id=task_id,
        )
        if not claimed:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT * FROM agent_commands WHERE message_id = ?", (message_id,)
                ).fetchone()
            if row is None:
                return {"duplicate": True, "message_id": message_id}
            return {"duplicate": True, "command_id": str(row["command_id"]), "message_id": message_id}
        payload: dict[str, Any] = {
            "message_id": message_id,
            "open_id": open_id,
            "chat_id": str(chat_id or "")[:160],
            "session_id": str(session["session_id"]),
            "text": text,
        }
        if task_id:
            payload["task_id"] = str(task_id)
        if extra:
            payload.update(extra)
        _, payload_json = _json_object(payload, "command payload")
        command_id = "cmd_" + uuid.uuid4().hex
        timestamp = now()
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO agent_commands(command_id, message_id, installation_id, session_id, open_id, chat_id, "
                "task_id, action, payload_json, status, lease_until, attempts, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', 0, 0, ?, ?)",
                (
                    command_id,
                    message_id,
                    installation_id,
                    str(session["session_id"]),
                    open_id,
                    str(chat_id or "")[:160],
                    str(task_id or "")[:160],
                    action,
                    payload_json,
                    timestamp,
                    timestamp,
                ),
            )
        return {
            "queued": True,
            "command_id": command_id,
            "message_id": message_id,
            "installation_id": installation_id,
            "session_id": str(session["session_id"]),
        }

    def poll(self, token: str, *, limit: int = 10, lease_seconds: int = 120) -> list[dict[str, Any]]:
        credential = self._credential(token)
        installation_id = str(credential["installation_id"])
        if limit < 1 or limit > 50:
            raise TransportError("limit 必须在 1 到 50 之间")
        if lease_seconds < 10 or lease_seconds > 3600:
            raise TransportError("lease_seconds 必须在 10 到 3600 之间")
        timestamp = now()
        result: list[dict[str, Any]] = []
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT * FROM agent_commands WHERE installation_id = ? AND "
                "((status = 'queued') OR (status = 'inflight' AND lease_until < ?)) "
                "ORDER BY created_at, command_id LIMIT ?",
                (installation_id, timestamp, limit),
            ).fetchall()
            for row in rows:
                connection.execute(
                    "UPDATE agent_commands SET status = 'inflight', lease_until = ?, attempts = attempts + 1, "
                    "updated_at = ? WHERE command_id = ?",
                    (timestamp + lease_seconds, timestamp, row["command_id"]),
                )
                try:
                    payload = json.loads(row["payload_json"])
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise TransportError("command payload 数据损坏") from exc
                result.append(
                    {
                        "command_id": str(row["command_id"]),
                        "message_id": str(row["message_id"]),
                        "session_id": str(row["session_id"]),
                        "action": str(row["action"]),
                        "attempts": int(row["attempts"] or 0) + 1,
                        "payload": payload,
                    }
                )
            connection.commit()
        return result

    def release(
        self,
        token: str,
        command_id: str,
        *,
        attempts: int = 0,
        reason: str = "",
    ) -> dict[str, Any]:
        credential = self._credential(token)
        command_id = _text(command_id, "command_id", 100)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM agent_commands WHERE command_id = ? AND installation_id = ?",
                (command_id, credential["installation_id"]),
            ).fetchone()
            if row is None:
                raise TransportError("找不到 command")
            if attempts and (
                row["status"] != "inflight"
                or int(row["attempts"] or 0) != attempts
            ):
                raise TransportError("command lease lost")
            connection.execute(
                "UPDATE agent_commands SET status = 'queued', lease_until = 0, updated_at = ?, last_error = ? "
                "WHERE command_id = ?",
                (now(), _text(reason, "reason", 500, required=False), command_id),
            )
            return dict(connection.execute(
                "SELECT * FROM agent_commands WHERE command_id = ?", (command_id,)
            ).fetchone())

    def renew(
        self,
        token: str,
        command_id: str,
        *,
        attempts: int = 0,
        lease_seconds: int = 120,
    ) -> dict[str, Any]:
        """Extend an in-flight command lease owned by this Agent attempt."""

        credential = self._credential(token)
        command_id = _text(command_id, "command_id", 100)
        if attempts < 0:
            raise TransportError("attempts 无效")
        if lease_seconds < 10 or lease_seconds > 3600:
            raise TransportError("lease_seconds 必须在 10 到 3600 之间")
        timestamp = now()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM agent_commands WHERE command_id = ? AND installation_id = ?",
                (command_id, credential["installation_id"]),
            ).fetchone()
            if row is None:
                raise TransportError("找不到 command")
            if row["status"] in {"completed", "failed"}:
                return dict(row)
            if row["status"] != "inflight" or (attempts and int(row["attempts"] or 0) != attempts):
                raise TransportError("command lease lost")
            connection.execute(
                "UPDATE agent_commands SET lease_until = ?, updated_at = ? "
                "WHERE command_id = ? AND installation_id = ? AND status = 'inflight'",
                (timestamp + lease_seconds, timestamp, command_id, credential["installation_id"]),
            )
            updated = connection.execute(
                "SELECT * FROM agent_commands WHERE command_id = ?", (command_id,)
            ).fetchone()
            if updated is None:
                raise TransportError("找不到 command")
            return dict(updated)

    def complete(
        self,
        token: str,
        command_id: str,
        *,
        attempts: int = 0,
        status: str,
        result: dict[str, Any] | None = None,
        error: str = "",
    ) -> dict[str, Any]:
        credential = self._credential(token)
        command_id = _text(command_id, "command_id", 100)
        status = _text(status, "status")
        if status not in {"completed", "failed"}:
            raise TransportError("完成状态必须是 completed 或 failed")
        result_value = {} if result is None else result
        _, result_json = _json_object(result_value, "result")
        timestamp = now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM agent_commands WHERE command_id = ? AND installation_id = ?",
                (command_id, credential["installation_id"]),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise TransportError("找不到 command")
            if row["status"] in {"completed", "failed"}:
                connection.rollback()
                return dict(row)
            if attempts and (
                row["status"] != "inflight"
                or int(row["attempts"] or 0) != attempts
            ):
                connection.rollback()
                raise TransportError("command lease lost")
            connection.execute(
                "UPDATE agent_commands SET status = ?, lease_until = 0, updated_at = ?, result_json = ?, last_error = ? "
                "WHERE command_id = ?",
                (status, timestamp, result_json, _text(error, "error", 500, required=False), command_id),
            )
            payload = json.loads(row["payload_json"])
            event_payload = {
                "command_id": command_id,
                "message_id": str(row["message_id"]),
                "open_id": str(row["open_id"]),
                "chat_id": str(row["chat_id"]),
                "session_id": str(row["session_id"]),
                "task_id": str(row["task_id"]),
                "status": status,
                "request": payload,
                "result": result_value,
                "error": str(error or "")[:500],
            }
            event_type = "command.completed" if status == "completed" else "command.failed"
            connection.execute(
                "INSERT OR IGNORE INTO agent_events(command_id, installation_id, session_id, event_type, payload_json, "
                "status, lease_until, attempts, next_attempt_at, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, 'pending', 0, 0, ?, ?, ?)",
                (
                    command_id,
                    str(credential["installation_id"]),
                    str(row["session_id"]),
                    event_type,
                    json.dumps(event_payload, ensure_ascii=False, separators=(",", ":")),
                    timestamp,
                    timestamp,
                    timestamp,
                ),
            )
            connection.commit()
        try:
            self.registry.complete_command(str(row["message_id"]), status)
        except RegistryError:
            # The transport event remains durable even if a legacy command row
            # was removed during a migration.
            pass
        return {
            "command_id": command_id,
            "message_id": str(row["message_id"]),
            "status": status,
        }

    def next_event(self) -> dict[str, Any] | None:
        timestamp = now()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM agent_events WHERE "
                "((status IN ('pending', 'failed') AND next_attempt_at <= ?) OR "
                "(status = 'claimed' AND lease_until < ?)) ORDER BY event_id LIMIT 1",
                (timestamp, timestamp),
            ).fetchone()
            if row is None:
                return None
            result = dict(row)
            try:
                result["payload"] = json.loads(result.pop("payload_json"))
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise TransportError("agent event payload 数据损坏") from exc
            return result

    def claim_event(self, event_id: int, *, lease_seconds: int = 120) -> dict[str, Any] | None:
        if event_id < 1:
            raise TransportError("event_id 无效")
        if lease_seconds < 10 or lease_seconds > 3600:
            raise TransportError("lease_seconds 必须在 10 到 3600 之间")
        timestamp = now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM agent_events WHERE event_id = ?", (event_id,)
            ).fetchone()
            if row is None:
                connection.rollback()
                raise TransportError("找不到 event")
            if row["status"] == "sent" or (
                row["status"] == "claimed" and int(row["lease_until"] or 0) >= timestamp
            ):
                connection.rollback()
                return None
            connection.execute(
                "UPDATE agent_events SET status = 'claimed', lease_until = ?, attempts = attempts + 1, updated_at = ? "
                "WHERE event_id = ?",
                (timestamp + lease_seconds, timestamp, event_id),
            )
            connection.commit()
            updated = connection.execute(
                "SELECT * FROM agent_events WHERE event_id = ?", (event_id,)
            ).fetchone()
            if updated is None:
                return None
            result = dict(updated)
            result["payload"] = json.loads(result.pop("payload_json"))
            return result

    def complete_event(
        self,
        event_id: int,
        *,
        status: str = "sent",
        error: str = "",
        retry_after: int = 60,
    ) -> dict[str, Any]:
        if status not in {"sent", "failed"}:
            raise TransportError("event 完成状态必须是 sent 或 failed")
        if retry_after < 1 or retry_after > 86400:
            raise TransportError("retry_after 必须在 1 到 86400 秒之间")
        timestamp = now()
        with self._connect() as connection:
            if status == "sent":
                connection.execute(
                    "UPDATE agent_events SET status = 'sent', lease_until = 0, updated_at = ?, last_error = '' "
                    "WHERE event_id = ?",
                    (timestamp, event_id),
                )
            else:
                connection.execute(
                    "UPDATE agent_events SET status = 'failed', lease_until = 0, updated_at = ?, "
                    "next_attempt_at = ?, last_error = ? WHERE event_id = ?",
                    (timestamp, timestamp + retry_after, _text(error, "error", 500, required=False), event_id),
                )
            row = connection.execute(
                "SELECT * FROM agent_events WHERE event_id = ?", (event_id,)
            ).fetchone()
            if row is None:
                raise TransportError("找不到 event")
            return dict(row)
