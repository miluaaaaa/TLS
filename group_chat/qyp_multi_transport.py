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

from qyp_multi_registry import Registry, RegistryError


DEFAULT_REGISTRY_DB = Path.home() / ".local/state/tls-group-chat/multi.sqlite3"
DEFAULT_TRANSPORT_DB = Path.home() / ".local/state/tls-group-chat/agent.sqlite3"
SESSION_ID = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$", re.IGNORECASE)
SESSION_STATUS = {"unknown", "idle", "running", "offline"}
COMMAND_STATUS = {"queued", "waiting_recovery", "inflight", "completed", "failed"}
EVENT_STATUS = {"pending", "claimed", "sent", "failed"}
DEFAULT_SESSION_FRESHNESS_SECONDS = 30
DEFAULT_RECOVERY_SCAN_SECONDS = 5
PROTOCOL_VERSION = "2"
DEFAULT_RELEASE_ID = "tls-group-chat-v1"
TRANSPORT_SCHEMA_VERSION = 2
RECOVERY_ACTIVE = {"awaiting_guardian", "detected", "claimed", "launching"}
RECOVERY_TERMINAL = {"recovered", "failed", "cancelled_live"}
DEFAULT_RECOVERY_LEASE_SECONDS = 30
DEFAULT_RECOVERY_DEADLINE_SECONDS = 120
RECOVERY_RETRY_DELAYS = (10, 30, 60)


class TransportError(RegistryError):
    """Expected transport input or state error."""


def now() -> int:
    return int(time.time())


def _registry_path(path: str | Path | None = None) -> Path:
    return Path(path) if path is not None else Path(
        os.environ.get("QYP_TLS_MULTI_DB", str(DEFAULT_REGISTRY_DB))
    )


def _transport_path(path: str | Path | None = None) -> Path:
    return Path(path) if path is not None else Path(
        os.environ.get("QYP_TLS_MULTI_TRANSPORT_DB", str(DEFAULT_TRANSPORT_DB))
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
    last_seen_at INTEGER NOT NULL DEFAULT 0,
    protocol_version TEXT NOT NULL DEFAULT '',
    release_id TEXT NOT NULL DEFAULT ''
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
    status TEXT NOT NULL CHECK (status IN ('queued', 'waiting_recovery', 'inflight', 'completed', 'failed')),
    lease_until INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    result_json TEXT NOT NULL DEFAULT '{}',
    last_error TEXT NOT NULL DEFAULT '',
    writer_epoch INTEGER NOT NULL DEFAULT 0,
    recovery_deadline_at INTEGER NOT NULL DEFAULT 0,
    transcript_proof TEXT NOT NULL DEFAULT '',
    turn_id TEXT NOT NULL DEFAULT ''
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

CREATE TABLE IF NOT EXISTS agent_completion_notifications (
    notification_id TEXT PRIMARY KEY,
    event_key TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    conversation TEXT NOT NULL,
    user_message TEXT NOT NULL,
    answer TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'claimed', 'sent', 'failed')),
    lease_until INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    last_error TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_agent_completion_notifications_ready
    ON agent_completion_notifications(status, next_attempt_at, lease_until, created_at);

CREATE TABLE IF NOT EXISTS recovery_tickets (
    ticket_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('awaiting_guardian', 'detected', 'claimed', 'launching', 'recovered', 'failed', 'cancelled_live')),
    reason TEXT NOT NULL,
    writer_epoch INTEGER NOT NULL DEFAULT 0,
    lease_owner TEXT NOT NULL DEFAULT '',
    lease_until INTEGER NOT NULL DEFAULT 0,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL DEFAULT 0,
    deadline_at INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    resolved_at INTEGER NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_recovery_ticket_one_active_session
    ON recovery_tickets(session_id) WHERE status IN ('awaiting_guardian', 'detected', 'claimed', 'launching');

CREATE TABLE IF NOT EXISTS session_writers (
    session_id TEXT PRIMARY KEY,
    writer_epoch INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS session_health (
    session_id TEXT PRIMARY KEY,
    installation_id TEXT NOT NULL,
    last_live_at INTEGER NOT NULL DEFAULT 0,
    offline_since INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS recovery_attempts (
    attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id TEXT NOT NULL,
    attempt_no INTEGER NOT NULL,
    event TEXT NOT NULL,
    writer_epoch INTEGER NOT NULL DEFAULT 0,
    lease_owner TEXT NOT NULL DEFAULT '',
    evidence_json TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_recovery_attempts_ticket
    ON recovery_attempts(ticket_id, attempt_id);

CREATE TABLE IF NOT EXISTS repair_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    installation_id TEXT NOT NULL DEFAULT '',
    session_id TEXT NOT NULL DEFAULT '',
    command_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK (status IN ('open', 'resolved', 'failed')),
    details_json TEXT NOT NULL DEFAULT '{}',
    occurrences INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    resolved_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS transport_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
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
        os.chmod(self.path, 0o600)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        self._migrate(connection)
        connection.executescript(SCHEMA)
        connection.execute(
            "INSERT INTO transport_meta(key, value) VALUES ('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (str(TRANSPORT_SCHEMA_VERSION),),
        )
        connection.commit()
        return connection

    def _migrate(self, connection: sqlite3.Connection) -> None:
        """Transactionally rebuild the two v1 tables whose CHECK clauses changed."""

        command_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'agent_commands'"
        ).fetchone()
        ticket_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'recovery_tickets'"
        ).fetchone()
        credential_columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(agent_credentials)")
        }
        old_commands = command_sql is not None and "waiting_recovery" not in str(command_sql[0])
        old_tickets = ticket_sql is not None and "cancelled_live" not in str(ticket_sql[0])
        missing_protocol = bool(credential_columns) and "protocol_version" not in credential_columns
        missing_release = bool(credential_columns) and "release_id" not in credential_columns
        missing_ticket_deadlines = bool(ticket_sql) and connection.execute(
            "SELECT 1 FROM recovery_tickets WHERE status IN ('awaiting_guardian','detected') "
            "AND deadline_at = 0 LIMIT 1"
        ).fetchone() is not None if ticket_sql is not None and not old_tickets else False
        if not old_commands and not old_tickets and not missing_protocol and not missing_release and not missing_ticket_deadlines:
            return
        connection.execute("BEGIN IMMEDIATE")
        try:
            if missing_protocol:
                connection.execute("ALTER TABLE agent_credentials ADD COLUMN protocol_version TEXT NOT NULL DEFAULT ''")
            if missing_release:
                connection.execute("ALTER TABLE agent_credentials ADD COLUMN release_id TEXT NOT NULL DEFAULT ''")
            if old_commands:
                connection.execute("DROP INDEX IF EXISTS idx_agent_commands_ready")
                connection.execute("ALTER TABLE agent_commands RENAME TO agent_commands_v1")
                connection.execute(
                    "CREATE TABLE agent_commands ("
                    "command_id TEXT PRIMARY KEY, message_id TEXT NOT NULL UNIQUE, installation_id TEXT NOT NULL, "
                    "session_id TEXT NOT NULL, open_id TEXT NOT NULL, chat_id TEXT NOT NULL DEFAULT '', "
                    "task_id TEXT NOT NULL DEFAULT '', action TEXT NOT NULL, payload_json TEXT NOT NULL, "
                    "status TEXT NOT NULL CHECK (status IN ('queued','waiting_recovery','inflight','completed','failed')), "
                    "lease_until INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0, "
                    "created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, result_json TEXT NOT NULL DEFAULT '{}', "
                    "last_error TEXT NOT NULL DEFAULT '', writer_epoch INTEGER NOT NULL DEFAULT 0, "
                    "recovery_deadline_at INTEGER NOT NULL DEFAULT 0, transcript_proof TEXT NOT NULL DEFAULT '', "
                    "turn_id TEXT NOT NULL DEFAULT '')"
                )
                connection.execute(
                    "INSERT INTO agent_commands(command_id,message_id,installation_id,session_id,open_id,chat_id,task_id,"
                    "action,payload_json,status,lease_until,attempts,created_at,updated_at,result_json,last_error) "
                    "SELECT command_id,message_id,installation_id,session_id,open_id,chat_id,task_id,action,payload_json,"
                    "status,lease_until,attempts,created_at,updated_at,result_json,last_error FROM agent_commands_v1"
                )
                connection.execute("DROP TABLE agent_commands_v1")
            if old_tickets:
                connection.execute("DROP INDEX IF EXISTS idx_recovery_ticket_one_active_user")
                connection.execute("DROP INDEX IF EXISTS idx_recovery_ticket_one_active_session")
                connection.execute("ALTER TABLE recovery_tickets RENAME TO recovery_tickets_v1")
                connection.execute(
                    "CREATE TABLE recovery_tickets (ticket_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, "
                    "installation_id TEXT NOT NULL, session_id TEXT NOT NULL, "
                    "status TEXT NOT NULL CHECK (status IN ('awaiting_guardian','detected','claimed','launching','recovered','failed','cancelled_live')), "
                    "reason TEXT NOT NULL, writer_epoch INTEGER NOT NULL DEFAULT 0, lease_owner TEXT NOT NULL DEFAULT '', "
                    "lease_until INTEGER NOT NULL DEFAULT 0, attempt_count INTEGER NOT NULL DEFAULT 0, "
                    "next_attempt_at INTEGER NOT NULL DEFAULT 0, deadline_at INTEGER NOT NULL DEFAULT 0, "
                    "last_error TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, "
                    "resolved_at INTEGER NOT NULL DEFAULT 0)"
                )
                connection.execute(
                    "INSERT INTO recovery_tickets(ticket_id,user_id,installation_id,session_id,status,reason,created_at,updated_at,resolved_at) "
                    "SELECT ticket_id,user_id,installation_id,session_id,"
                    "CASE status WHEN 'recovering' THEN 'detected' ELSE status END,reason,created_at,updated_at,resolved_at "
                    "FROM recovery_tickets_v1"
                )
                connection.execute("DROP TABLE recovery_tickets_v1")
            if old_tickets or missing_ticket_deadlines:
                timestamp = now()
                connection.execute(
                    "UPDATE recovery_tickets SET next_attempt_at = ?, deadline_at = ?, updated_at = ? "
                    "WHERE status IN ('awaiting_guardian','detected') AND deadline_at = 0",
                    (timestamp, timestamp + DEFAULT_RECOVERY_DEADLINE_SECONDS, timestamp),
                )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise

    def init(self) -> dict[str, Any]:
        with self._connect() as connection:
            connection.commit()
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        return {"path": str(self.path), "schema_version": TRANSPORT_SCHEMA_VERSION}

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

    def heartbeat(
        self,
        token: str,
        sessions: Iterable[object],
        *,
        protocol_version: str = "",
        release_id: str = "",
    ) -> dict[str, Any]:
        credential = self._credential(token)
        installation_id = str(credential["installation_id"])
        accepted: list[dict[str, Any]] = []
        recovery_proofs: dict[str, tuple[str, int]] = {}
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
            model = _text(raw.get("model", "unknown"), "model", 160, required=False) or "unknown"
            effort = _text(raw.get("effort", "unknown"), "effort", 80, required=False) or "unknown"
            if status not in SESSION_STATUS:
                raise TransportError(f"status 必须是 {sorted(SESSION_STATUS)} 之一")
            recovery_ticket_id = str(raw.get("recovery_ticket_id", ""))[:100]
            if recovery_ticket_id:
                recovery_proofs[recovery_ticket_id] = (sid, int(raw.get("writer_epoch", 0) or 0))
            if sid not in existing:
                item = self.registry.add_session(
                    installation_id,
                    sid,
                    label=label,
                    workspace=workspace,
                    status=status,
                    model=model,
                    effort=effort,
                    share_with_groups=False,
                )
            else:
                item = self.registry.update_session(
                    sid,
                    label=label,
                    workspace=workspace,
                    status=status,
                    model=model,
                    effort=effort,
                )
            accepted.append(item)
        timestamp = now()
        with self._connect() as connection:
            connection.execute(
                "UPDATE agent_credentials SET last_seen_at = ?, protocol_version = ?, release_id = ? "
                "WHERE installation_id = ?",
                (timestamp, str(protocol_version)[:40], str(release_id)[:120], installation_id),
            )
            for item in accepted:
                sid = str(item.get("session_id", ""))
                status = str(item.get("status", "unknown"))
                if status in {"idle", "running"}:
                    connection.execute(
                        "INSERT INTO session_health(session_id,installation_id,last_live_at,offline_since,updated_at) "
                        "VALUES (?,?,?,0,?) ON CONFLICT(session_id) DO UPDATE SET installation_id=excluded.installation_id, "
                        "last_live_at=excluded.last_live_at, offline_since=0, updated_at=excluded.updated_at",
                        (sid, installation_id, timestamp, timestamp),
                    )
                elif status == "offline":
                    connection.execute(
                        "INSERT INTO session_health(session_id,installation_id,last_live_at,offline_since,updated_at) "
                        "VALUES (?,?,0,?,?) ON CONFLICT(session_id) DO UPDATE SET installation_id=excluded.installation_id, "
                        "offline_since=CASE WHEN session_health.offline_since=0 THEN excluded.offline_since ELSE session_health.offline_since END, "
                        "updated_at=excluded.updated_at",
                        (sid, installation_id, timestamp, timestamp),
                    )
            if str(protocol_version) == PROTOCOL_VERSION:
                connection.execute(
                    "UPDATE recovery_tickets SET status = 'detected', updated_at = ?, "
                    "next_attempt_at = CASE WHEN deadline_at = 0 THEN ? ELSE next_attempt_at END, "
                    "deadline_at = CASE WHEN deadline_at = 0 THEN ? ELSE deadline_at END "
                    "WHERE installation_id = ? AND status = 'awaiting_guardian' "
                    "AND (deadline_at = 0 OR deadline_at > ?)",
                    (timestamp, timestamp, timestamp + DEFAULT_RECOVERY_DEADLINE_SECONDS, installation_id, timestamp),
                )
            recovery_tickets = [
                dict(row) for row in connection.execute(
                    "SELECT ticket_id, session_id, status, reason, writer_epoch, attempt_count, "
                    "next_attempt_at, deadline_at, created_at FROM recovery_tickets "
                    "WHERE installation_id = ? AND status = 'detected' AND next_attempt_at <= ? "
                    "AND deadline_at > ? ORDER BY created_at",
                    (installation_id, timestamp, timestamp),
                )
            ] if str(protocol_version) == PROTOCOL_VERSION else []
            recovery_heartbeats: list[str] = []
            for ticket_id, (session_id, writer_epoch) in recovery_proofs.items():
                matched = connection.execute(
                    "SELECT 1 FROM recovery_tickets WHERE ticket_id = ? AND installation_id = ? "
                    "AND session_id = ? AND status = 'launching' AND writer_epoch = ?",
                    (ticket_id, installation_id, session_id, writer_epoch),
                ).fetchone()
                if matched is not None:
                    recovery_heartbeats.append(ticket_id)
            self._record_repair_on_connection(
                connection,
                "protocol-mismatch",
                str(credential["installation_id"]),
                status="resolved" if str(protocol_version) == PROTOCOL_VERSION else "open",
                details={"reason": "agent-gateway-protocol-mismatch", "agent_protocol_version": str(protocol_version), "gateway_protocol_version": PROTOCOL_VERSION},
            )
        return {
            "installation_id": installation_id,
            "sessions": accepted,
            "last_seen_at": timestamp,
            "protocol_version": PROTOCOL_VERSION,
            "release_id": os.environ.get("TLS_RELEASE_ID", DEFAULT_RELEASE_ID),
            "recovery_compatible": str(protocol_version) == PROTOCOL_VERSION,
            "recovery_tickets": recovery_tickets,
            "recovery_heartbeats": recovery_heartbeats,
        }

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
            "protocol_version": PROTOCOL_VERSION,
            "agent_protocol_version": str(credential["protocol_version"] or ""),
            "agent_release_id": str(credential["release_id"] or ""),
        }

    def request_channel(
        self,
        token: str,
        task_id: str,
        from_run_id: str,
        to_run_id: str,
        capabilities: list[str],
        *,
        ttl_seconds: int = 3600,
    ) -> dict[str, Any]:
        credential = self._credential(token)
        return self.registry.request_agent_channel(
            task_id,
            from_run_id,
            to_run_id,
            capabilities,
            requested_by=str(credential["user_id"]),
            ttl_seconds=ttl_seconds,
        )

    def accept_channel(self, token: str, channel_id: str, accepting_run_id: str) -> dict[str, Any]:
        credential = self._credential(token)
        return self.registry.accept_agent_channel(
            channel_id,
            accepting_run_id,
            accepted_by=str(credential["user_id"]),
        )

    def revoke_channel(self, token: str, channel_id: str) -> dict[str, Any]:
        credential = self._credential(token)
        return self.registry.revoke_agent_channel(
            channel_id,
            revoked_by=str(credential["user_id"]),
        )

    def list_channels(self, token: str, task_id: str) -> list[dict[str, Any]]:
        credential = self._credential(token)
        return self.registry.list_agent_channels(
            task_id,
            user_reference=str(credential["user_id"]),
        )

    def send_channel_message(
        self,
        token: str,
        channel_id: str,
        sender_run_id: str,
        message_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        credential = self._credential(token)
        return self.registry.send_agent_channel_message(
            channel_id,
            sender_run_id,
            message_id,
            payload,
            sent_by=str(credential["user_id"]),
        )

    def poll_channel_messages(
        self,
        token: str,
        channel_id: str,
        recipient_run_id: str,
        *,
        limit: int = 20,
        lease_seconds: int = 120,
    ) -> list[dict[str, Any]]:
        credential = self._credential(token)
        return self.registry.poll_agent_channel_messages(
            channel_id,
            recipient_run_id,
            requested_by=str(credential["user_id"]),
            limit=limit,
            lease_seconds=lease_seconds,
        )

    def ack_channel_message(
        self,
        token: str,
        message_id: str,
        recipient_run_id: str,
        *,
        status: str = "acknowledged",
    ) -> dict[str, Any]:
        credential = self._credential(token)
        return self.registry.ack_agent_channel_message(
            message_id,
            recipient_run_id,
            status=status,
            acknowledged_by=str(credential["user_id"]),
        )

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
        recovery_ticket = self._ensure_recovery_ticket(session, online=online, age=age, max_age=max_age)
        return {
            "session_id": str(session.get("session_id", "")),
            "status": status,
            "last_seen_at": last_seen_at,
            "age_seconds": age,
            "online": online,
            "recovery_ticket": recovery_ticket,
        }

    def _ensure_recovery_ticket(
        self,
        session: dict[str, Any],
        *,
        online: bool,
        age: int | None,
        max_age: int,
    ) -> dict[str, Any] | None:
        """Create or refresh one recovery ticket for an expired live Session.

        Explicitly offline or never-live Sessions are not auto-restarted.  The
        ticket is scoped to one Session, so repeated scans cannot create a restart
        storm while independent managed Sessions can recover concurrently.
        """

        user_id = str(session.get("user_id", ""))
        installation_id = str(session.get("installation_id", ""))
        session_id = str(session.get("session_id", ""))
        status = str(session.get("status", "unknown"))
        expired_live_session = (
            not online
            and status in {"idle", "running"}
            and age is not None
            and age > max_age
        )
        if not expired_live_session:
            return None
        timestamp = now()
        with self._connect() as connection:
            guardian = connection.execute(
                "SELECT last_seen_at, protocol_version FROM agent_credentials "
                "WHERE installation_id = ? AND status = 'active'",
                (installation_id,),
            ).fetchone()
            guardian_age = (
                max(0, timestamp - int(guardian["last_seen_at"] or 0))
                if guardian is not None and int(guardian["last_seen_at"] or 0)
                else None
            )
            compatible = guardian is not None and str(guardian["protocol_version"] or "") == PROTOCOL_VERSION
            ticket_status = "detected" if guardian_age is not None and guardian_age <= max_age and compatible else "awaiting_guardian"
            connection.execute(
                "INSERT OR IGNORE INTO recovery_tickets(ticket_id, user_id, installation_id, session_id, status, reason, "
                "next_attempt_at, deadline_at, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, 'heartbeat-expired', ?, ?, ?, ?)",
                ("recovery_" + uuid.uuid4().hex, user_id, installation_id, session_id, ticket_status,
                 timestamp, timestamp + DEFAULT_RECOVERY_DEADLINE_SECONDS, timestamp, timestamp),
            )
            row = connection.execute(
                "SELECT ticket_id, status, session_id, reason, created_at, updated_at FROM recovery_tickets "
                "WHERE session_id = ? AND status IN ('awaiting_guardian', 'detected', 'claimed', 'launching') "
                "ORDER BY created_at DESC LIMIT 1",
                (session_id,),
            ).fetchone()
            if row is None or str(row["session_id"]) != session_id:
                return None
            if str(row["status"]) == "awaiting_guardian" and ticket_status == "detected":
                connection.execute(
                    "UPDATE recovery_tickets SET status = 'detected', updated_at = ?, "
                    "next_attempt_at = CASE WHEN deadline_at = 0 THEN ? ELSE next_attempt_at END, "
                    "deadline_at = CASE WHEN deadline_at = 0 THEN ? ELSE deadline_at END WHERE ticket_id = ?",
                    (timestamp, timestamp, timestamp + DEFAULT_RECOVERY_DEADLINE_SECONDS, row["ticket_id"]),
                )
            row = connection.execute(
                "SELECT ticket_id, status, session_id, reason, created_at, updated_at "
                "FROM recovery_tickets WHERE ticket_id = ?",
                (row["ticket_id"],),
            ).fetchone()
        return dict(row) if row is not None else None

    def scan_recovery_tickets(
        self,
        *,
        max_age: int = DEFAULT_SESSION_FRESHNESS_SECONDS,
    ) -> list[dict[str, Any]]:
        """Find expired live Sessions without waiting for a Feishu command."""

        if max_age < 1 or max_age > 3600:
            raise TransportError("max_age 必须在 1 到 3600 之间")
        timestamp = now()
        tickets: list[dict[str, Any]] = []
        with self._connect() as connection:
            connection.execute(
                "UPDATE recovery_tickets SET status = CASE WHEN attempt_count >= 3 OR deadline_at <= ? "
                "THEN 'failed' ELSE 'detected' END, lease_owner = '', lease_until = 0, updated_at = ?, "
                "resolved_at = CASE WHEN attempt_count >= 3 OR deadline_at <= ? THEN ? ELSE 0 END, "
                "last_error = CASE WHEN attempt_count >= 3 OR deadline_at <= ? THEN 'recovery-deadline-exhausted' ELSE 'recovery-lease-expired' END "
                "WHERE status IN ('claimed', 'launching') AND lease_until < ?",
                (timestamp, timestamp, timestamp, timestamp, timestamp, timestamp),
            )
            connection.execute(
                "UPDATE recovery_tickets SET status = 'failed', updated_at = ?, resolved_at = ?, "
                "last_error = 'recovery-deadline-exhausted' WHERE status IN ('awaiting_guardian', 'detected') "
                "AND deadline_at > 0 AND deadline_at <= ?",
                (timestamp, timestamp, timestamp),
            )
            expired_commands = connection.execute(
                "SELECT * FROM agent_commands WHERE status = 'waiting_recovery' "
                "AND recovery_deadline_at > 0 AND recovery_deadline_at <= ?", (timestamp,)
            ).fetchall()
            for command in expired_commands:
                self._fail_waiting_command(connection, command, "recovery-deadline-exhausted")
        with sqlite3.connect(self.registry.path) as registry_connection:
            routed_sessions = {
                str(row[0]).lower()
                for row in registry_connection.execute("SELECT session_id FROM session_slots")
            }
        for session in self.registry.list_sessions():
            if str(session.get("session_id", "")).lower() not in routed_sessions:
                continue
            last_seen_at = int(session.get("last_seen_at") or 0)
            age = max(0, timestamp - last_seen_at) if last_seen_at else None
            with self._connect() as connection:
                health = connection.execute(
                    "SELECT * FROM session_health WHERE session_id = ?", (str(session.get("session_id", "")),)
                ).fetchone()
            if str(session.get("status", "unknown")) == "offline" and health is not None and int(health["offline_since"] or 0):
                offline_age = max(0, timestamp - int(health["offline_since"]))
                if offline_age > max_age and int(health["last_live_at"] or 0):
                    session = dict(session)
                    session["status"] = "running"
                    age = offline_age
            online = (
                str(session.get("status", "unknown")) in {"idle", "running"}
                and age is not None
                and age <= max_age
            )
            ticket = self._ensure_recovery_ticket(session, online=online, age=age, max_age=max_age)
            if ticket is not None:
                tickets.append(ticket)
        return tickets

    @staticmethod
    def _attempt(
        connection: sqlite3.Connection,
        ticket: sqlite3.Row,
        event: str,
        evidence: dict[str, Any] | None = None,
    ) -> None:
        connection.execute(
            "INSERT INTO recovery_attempts(ticket_id, attempt_no, event, writer_epoch, lease_owner, evidence_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ticket["ticket_id"], int(ticket["attempt_count"] or 0), event,
             int(ticket["writer_epoch"] or 0), str(ticket["lease_owner"] or ""),
             json.dumps(evidence or {}, ensure_ascii=False, separators=(",", ":")), now()),
        )

    @staticmethod
    def _record_repair_on_connection(
        connection: sqlite3.Connection,
        event_type: str,
        installation_id: str,
        *,
        session_id: str = "",
        command_id: str = "",
        status: str = "open",
        details: dict[str, Any] | None = None,
    ) -> None:
        detail_json = json.dumps(details or {}, ensure_ascii=False, separators=(",", ":"))
        reason = str((details or {}).get("reason", ""))[:240]
        fingerprint = hashlib.sha256(
            "\x00".join((event_type, installation_id, session_id, command_id, reason)).encode("utf-8")
        ).hexdigest()
        timestamp = now()
        connection.execute(
            "INSERT INTO repair_events(fingerprint,event_type,installation_id,session_id,command_id,status,details_json,created_at,updated_at,resolved_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(fingerprint) DO UPDATE SET "
            "status=excluded.status, details_json=excluded.details_json, occurrences=repair_events.occurrences+1, "
            "updated_at=excluded.updated_at, resolved_at=excluded.resolved_at",
            (fingerprint, event_type, installation_id, session_id, command_id, status, detail_json,
             timestamp, timestamp, timestamp if status in {"resolved", "failed"} else 0),
        )

    @staticmethod
    def _fail_waiting_command(connection: sqlite3.Connection, command: sqlite3.Row, error: str) -> None:
        timestamp = now()
        connection.execute(
            "UPDATE agent_commands SET status = 'failed', recovery_deadline_at = 0, last_error = ?, updated_at = ? "
            "WHERE command_id = ? AND status = 'waiting_recovery'",
            (error[:500], timestamp, command["command_id"]),
        )
        request = json.loads(command["payload_json"])
        payload = {
            "command_id": str(command["command_id"]), "message_id": str(command["message_id"]),
            "open_id": str(command["open_id"]), "chat_id": str(command["chat_id"]),
            "session_id": str(command["session_id"]), "task_id": str(command["task_id"]),
            "status": "failed", "request": request, "result": {}, "error": error[:500],
        }
        connection.execute(
            "INSERT INTO agent_events(command_id,installation_id,session_id,event_type,payload_json,status,lease_until,attempts,next_attempt_at,created_at,updated_at) "
            "VALUES (?,?,?,'command.failed',?,'pending',0,0,?,?,?) ON CONFLICT(command_id) DO NOTHING",
            (command["command_id"], command["installation_id"], command["session_id"],
             json.dumps(payload, ensure_ascii=False, separators=(",", ":")), timestamp, timestamp, timestamp),
        )

    def claim_recovery(
        self,
        token: str,
        ticket_id: str,
        lease_owner: str,
        *,
        lease_seconds: int = DEFAULT_RECOVERY_LEASE_SECONDS,
    ) -> dict[str, Any]:
        credential = self._credential(token)
        if str(credential["protocol_version"] or "") != PROTOCOL_VERSION:
            raise TransportError("recovery protocol mismatch")
        ticket_id = _text(ticket_id, "ticket_id", 100)
        lease_owner = _text(lease_owner, "lease_owner", 160)
        if lease_seconds < 10 or lease_seconds > 120:
            raise TransportError("recovery lease_seconds 无效")
        timestamp = now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            ticket = connection.execute(
                "SELECT * FROM recovery_tickets WHERE ticket_id = ? AND installation_id = ?",
                (ticket_id, credential["installation_id"]),
            ).fetchone()
            if ticket is None:
                raise TransportError("找不到 recovery ticket")
            if ticket["status"] != "detected" or int(ticket["next_attempt_at"] or 0) > timestamp:
                raise TransportError("recovery ticket 不可 claim")
            if int(ticket["deadline_at"] or 0) <= timestamp or int(ticket["attempt_count"] or 0) >= 3:
                raise TransportError("recovery ticket 已耗尽")
            writer = connection.execute(
                "SELECT writer_epoch FROM session_writers WHERE session_id = ?", (ticket["session_id"],)
            ).fetchone()
            epoch = int(writer["writer_epoch"] or 0) + 1 if writer is not None else 1
            connection.execute(
                "INSERT INTO session_writers(session_id, writer_epoch, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(session_id) DO UPDATE SET writer_epoch = excluded.writer_epoch, updated_at = excluded.updated_at",
                (ticket["session_id"], epoch, timestamp),
            )
            connection.execute(
                "UPDATE recovery_tickets SET status = 'claimed', writer_epoch = ?, lease_owner = ?, "
                "lease_until = ?, attempt_count = attempt_count + 1, updated_at = ? WHERE ticket_id = ?",
                (epoch, lease_owner, timestamp + lease_seconds, timestamp, ticket_id),
            )
            updated = connection.execute("SELECT * FROM recovery_tickets WHERE ticket_id = ?", (ticket_id,)).fetchone()
            self._attempt(connection, updated, "claimed")
            connection.execute(
                "UPDATE agent_commands SET writer_epoch = ? WHERE session_id = ? "
                "AND status IN ('queued', 'waiting_recovery', 'inflight')",
                (epoch, ticket["session_id"]),
            )
            connection.commit()
            return dict(updated)

    def renew_recovery(
        self, token: str, ticket_id: str, lease_owner: str, writer_epoch: int,
        *, lease_seconds: int = DEFAULT_RECOVERY_LEASE_SECONDS,
    ) -> dict[str, Any]:
        credential = self._credential(token)
        timestamp = now()
        with self._connect() as connection:
            ticket = connection.execute(
                "SELECT * FROM recovery_tickets WHERE ticket_id = ? AND installation_id = ?",
                (_text(ticket_id, "ticket_id", 100), credential["installation_id"]),
            ).fetchone()
            if ticket is None or ticket["status"] not in {"claimed", "launching"} or str(ticket["lease_owner"]) != lease_owner or int(ticket["writer_epoch"]) != writer_epoch:
                raise TransportError("recovery lease lost")
            connection.execute(
                "UPDATE recovery_tickets SET lease_until = ?, updated_at = ? WHERE ticket_id = ?",
                (timestamp + lease_seconds, timestamp, ticket_id),
            )
            return dict(connection.execute("SELECT * FROM recovery_tickets WHERE ticket_id = ?", (ticket_id,)).fetchone())

    def report_recovery(
        self, token: str, ticket_id: str, event: str, *, lease_owner: str = "",
        writer_epoch: int = 0, evidence: dict[str, Any] | None = None, error: str = "",
    ) -> dict[str, Any]:
        credential = self._credential(token)
        event = _text(event, "event", 40)
        timestamp = now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            ticket = connection.execute(
                "SELECT * FROM recovery_tickets WHERE ticket_id = ? AND installation_id = ?",
                (_text(ticket_id, "ticket_id", 100), credential["installation_id"]),
            ).fetchone()
            if ticket is None:
                raise TransportError("找不到 recovery ticket")
            if event == "cancelled_live":
                if ticket["status"] != "detected":
                    raise TransportError("recovery ticket 状态冲突")
                status, resolved = "cancelled_live", timestamp
            else:
                if ticket["status"] not in {"claimed", "launching"} or str(ticket["lease_owner"]) != lease_owner or int(ticket["writer_epoch"]) != writer_epoch:
                    raise TransportError("recovery lease lost")
                if event == "launching":
                    status, resolved = "launching", 0
                elif event == "recovered":
                    status, resolved = "recovered", timestamp
                elif event == "launch_failed":
                    attempts = int(ticket["attempt_count"] or 0)
                    exhausted = attempts >= 3 or int(ticket["deadline_at"] or 0) <= timestamp
                    status, resolved = ("failed", timestamp) if exhausted else ("detected", 0)
                else:
                    raise TransportError("recovery event 无效")
            delay = RECOVERY_RETRY_DELAYS[min(max(int(ticket["attempt_count"] or 1) - 1, 0), 2)] if event == "launch_failed" and status == "detected" else 0
            connection.execute(
                "UPDATE recovery_tickets SET status = ?, lease_until = 0, next_attempt_at = ?, last_error = ?, "
                "updated_at = ?, resolved_at = ? WHERE ticket_id = ?",
                (status, timestamp + delay, str(error)[:500], timestamp, resolved, ticket_id),
            )
            updated = connection.execute("SELECT * FROM recovery_tickets WHERE ticket_id = ?", (ticket_id,)).fetchone()
            self._attempt(connection, updated, event, evidence)
            self._record_repair_on_connection(
                connection, "session-recovery", str(credential["installation_id"]),
                session_id=str(ticket["session_id"]), status="resolved" if status in {"recovered", "cancelled_live"} else "failed" if status == "failed" else "open",
                details={"reason": str(ticket["reason"]), "ticket_id": ticket_id, "event": event, "writer_epoch": writer_epoch},
            )
            if status in {"recovered", "cancelled_live"}:
                connection.execute(
                    "UPDATE agent_commands SET status = 'queued', recovery_deadline_at = 0, updated_at = ? "
                    "WHERE session_id = ? AND status = 'waiting_recovery'",
                    (timestamp, ticket["session_id"]),
                )
            elif status == "failed":
                waiting = connection.execute(
                    "SELECT * FROM agent_commands WHERE session_id = ? AND status = 'waiting_recovery'",
                    (ticket["session_id"],),
                ).fetchall()
                for command in waiting:
                    self._fail_waiting_command(connection, command, "recovery-failed")
            connection.commit()
            return dict(updated)

    def record_repair_event(
        self,
        token: str,
        event_type: str,
        *,
        session_id: str = "",
        command_id: str = "",
        status: str = "open",
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        credential = self._credential(token)
        event_type = _text(event_type, "event_type", 120)
        session_id = _text(session_id, "session_id", 80, required=False).lower()
        command_id = _text(command_id, "command_id", 100, required=False)
        if status not in {"open", "resolved", "failed"}:
            raise TransportError("repair event status 无效")
        detail_value, detail_json = _json_object(details or {}, "details", 4000)
        reason = str(detail_value.get("reason", ""))[:240]
        fingerprint = hashlib.sha256(
            "\x00".join((event_type, str(credential["installation_id"]), session_id, command_id, reason)).encode("utf-8")
        ).hexdigest()
        timestamp = now()
        resolved_at = timestamp if status in {"resolved", "failed"} else 0
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO repair_events(fingerprint,event_type,installation_id,session_id,command_id,status,details_json,created_at,updated_at,resolved_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(fingerprint) DO UPDATE SET "
                "status=excluded.status, details_json=excluded.details_json, occurrences=repair_events.occurrences+1, "
                "updated_at=excluded.updated_at, resolved_at=excluded.resolved_at",
                (fingerprint, event_type, str(credential["installation_id"]), session_id, command_id,
                 status, detail_json, timestamp, timestamp, resolved_at),
            )
            row = connection.execute("SELECT * FROM repair_events WHERE fingerprint = ?", (fingerprint,)).fetchone()
        return dict(row)

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
        private_scope: bool = False,
    ) -> dict[str, Any]:
        message_id = _text(message_id, "message_id", 160)
        open_id = _text(open_id, "open_id", 160)
        text = _text(text, "text", 12000)
        session = self._session(session_id)
        installation_id = str(session["installation_id"])
        last_seen_at = int(session.get("last_seen_at") or 0)
        session_status = str(session.get("status", "unknown"))
        stale_live = session_status in {"idle", "running"} and last_seen_at > 0 and now() - last_seen_at > DEFAULT_SESSION_FRESHNESS_SECONDS
        recoverable_offline = False
        if session_status == "offline":
            with self._connect() as connection:
                health = connection.execute(
                    "SELECT last_live_at FROM session_health WHERE session_id = ?", (str(session["session_id"]),)
                ).fetchone()
            recoverable_offline = health is not None and int(health["last_live_at"] or 0) > 0
        if stale_live:
            self._ensure_recovery_ticket(
                session,
                online=False,
                age=max(0, now() - last_seen_at),
                max_age=DEFAULT_SESSION_FRESHNESS_SECONDS,
            )
        claimed = self.registry.claim_command(
            message_id,
            open_id,
            None if private_scope else chat_id,
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
        payload["action"] = action
        _, payload_json = _json_object(payload, "command payload")
        command_id = "cmd_" + uuid.uuid4().hex
        timestamp = now()
        with self._connect() as connection:
            writer = connection.execute(
                "SELECT writer_epoch FROM session_writers WHERE session_id = ?",
                (str(session["session_id"]),),
            ).fetchone()
            writer_epoch = int(writer["writer_epoch"] or 0) if writer is not None else 0
            initial_status = "waiting_recovery" if stale_live or recoverable_offline else "queued"
            recovery_deadline = timestamp + DEFAULT_RECOVERY_DEADLINE_SECONDS if initial_status == "waiting_recovery" else 0
            connection.execute(
                "INSERT INTO agent_commands(command_id, message_id, installation_id, session_id, open_id, chat_id, "
                "task_id, action, payload_json, status, lease_until, attempts, created_at, updated_at, writer_epoch, recovery_deadline_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?, ?, ?)",
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
                    initial_status,
                    timestamp,
                    timestamp,
                    writer_epoch,
                    recovery_deadline,
                ),
            )
        return {
            "queued": initial_status == "queued",
            "waiting_recovery": initial_status == "waiting_recovery",
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
                writer = connection.execute(
                    "SELECT writer_epoch FROM session_writers WHERE session_id = ?", (row["session_id"],)
                ).fetchone()
                writer_epoch = int(writer["writer_epoch"] or 0) if writer is not None else int(row["writer_epoch"] or 0)
                connection.execute(
                    "UPDATE agent_commands SET status = 'inflight', lease_until = ?, attempts = attempts + 1, "
                    "writer_epoch = ?, updated_at = ? WHERE command_id = ?",
                    (timestamp + lease_seconds, writer_epoch, timestamp, row["command_id"]),
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
                        "writer_epoch": writer_epoch,
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
        writer_epoch: int = 0,
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
            modern = str(credential["protocol_version"] or "") == PROTOCOL_VERSION
            if (modern and (attempts < 1 or writer_epoch != int(row["writer_epoch"] or 0))) or (attempts and (
                row["status"] != "inflight"
                or int(row["attempts"] or 0) != attempts
            )):
                raise TransportError("command lease lost")
            connection.execute(
                "UPDATE agent_commands SET status = 'queued', lease_until = 0, updated_at = ?, last_error = ? "
                "WHERE command_id = ?",
                (now(), _text(reason, "reason", 500, required=False), command_id),
            )
            return dict(connection.execute(
                "SELECT * FROM agent_commands WHERE command_id = ?", (command_id,)
            ).fetchone())


    def retry_failed(
        self,
        token: str,
        command_id: str,
        *,
        reason: str = "",
    ) -> dict[str, Any]:
        """Requeue one known pre-turn delivery failure for its owning Agent."""

        credential = self._credential(token)
        command_id = _text(command_id, "command_id", 100)
        allowed_errors = {"runtime-unavailable", "turn-id-unavailable", "turn-id-unavailable-cursor-runtime"}
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM agent_commands WHERE command_id = ? AND installation_id = ?",
                (command_id, credential["installation_id"]),
            ).fetchone()
            if row is None:
                raise TransportError("找不到 command")
            if (
                row["status"] != "failed"
                or int(row["attempts"] or 0) != 1
                or str(row["last_error"] or "") not in allowed_errors
                or str(row["transcript_proof"] or "") != "absent"
            ):
                raise TransportError("command 不符合自动重试条件")
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
        writer_epoch: int = 0,
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
            modern = str(credential["protocol_version"] or "") == PROTOCOL_VERSION
            if row["status"] != "inflight" or (modern and (attempts < 1 or writer_epoch != int(row["writer_epoch"] or 0))) or (attempts and int(row["attempts"] or 0) != attempts):
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

    def authorize_result(
        self, open_id: str, chat_id: str, session_id: str, *, action: str = "", task_id: str = "",
    ) -> None:
        """Recheck current read access at completion and before delivery."""

        if action == "history_search":
            self.registry.authorize_history_search(open_id, chat_id, session_id)
        elif task_id:
            self.registry.authorize_task(open_id, chat_id, task_id, session_id, "read")
        else:
            self.registry.authorize(open_id, chat_id, session_id, "read")

    def complete(
        self,
        token: str,
        command_id: str,
        *,
        attempts: int = 0,
        writer_epoch: int = 0,
        status: str,
        result: dict[str, Any] | None = None,
        error: str = "",
        transcript_proof: str = "",
        turn_id: str = "",
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
            modern = str(credential["protocol_version"] or "") == PROTOCOL_VERSION
            if (modern and (attempts < 1 or writer_epoch != int(row["writer_epoch"] or 0))) or (attempts and (
                row["status"] != "inflight"
                or int(row["attempts"] or 0) != attempts
            )):
                connection.rollback()
                raise TransportError("command lease lost")
            try:
                self.authorize_result(
                    str(row["open_id"]), str(row["chat_id"]), str(row["session_id"]),
                    action=str(row["action"]), task_id=str(row["task_id"] or ""),
                )
            except RegistryError:
                status = "failed"
                error = "history-authorization-revoked" if row["action"] == "history_search" else "result-authorization-revoked"
                result_value = {}
                result_json = "{}"
            connection.execute(
                "UPDATE agent_commands SET status = ?, lease_until = 0, updated_at = ?, result_json = ?, last_error = ?, "
                "transcript_proof = ?, turn_id = ? "
                "WHERE command_id = ?",
                (status, timestamp, result_json, _text(error, "error", 500, required=False),
                 _text(transcript_proof, "transcript_proof", 40, required=False),
                 _text(turn_id, "turn_id", 160, required=False), command_id),
            )
            if status == "failed":
                self._record_repair_on_connection(
                    connection, "command-failure", str(credential["installation_id"]),
                    session_id=str(row["session_id"]), command_id=command_id, status="open",
                    details={"reason": str(error or "")[:500], "transcript_proof": transcript_proof, "turn_id": turn_id},
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
                "INSERT INTO agent_events(command_id, installation_id, session_id, event_type, payload_json, "
                "status, lease_until, attempts, next_attempt_at, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, 'pending', 0, 0, ?, ?, ?) "
                "ON CONFLICT(command_id) DO UPDATE SET "
                "event_type = excluded.event_type, payload_json = excluded.payload_json, "
                "status = 'pending', lease_until = 0, attempts = 0, "
                "next_attempt_at = excluded.next_attempt_at, updated_at = excluded.updated_at, last_error = ''",
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
                event_row = connection.execute("SELECT * FROM agent_events WHERE event_id = ?", (event_id,)).fetchone()
                if event_row is not None:
                    self._record_repair_on_connection(
                        connection, "feishu-outbox", str(event_row["installation_id"]),
                        session_id=str(event_row["session_id"]), command_id=str(event_row["command_id"]), status="resolved",
                        details={"reason": "feishu-outbox-send-failed", "event_id": event_id},
                    )
            else:
                connection.execute(
                    "UPDATE agent_events SET status = 'failed', lease_until = 0, updated_at = ?, "
                    "next_attempt_at = ?, last_error = ? WHERE event_id = ?",
                    (timestamp, timestamp + retry_after, _text(error, "error", 500, required=False), event_id),
                )
                event_row = connection.execute("SELECT * FROM agent_events WHERE event_id = ?", (event_id,)).fetchone()
                if event_row is not None:
                    self._record_repair_on_connection(
                        connection, "feishu-outbox", str(event_row["installation_id"]),
                        session_id=str(event_row["session_id"]), command_id=str(event_row["command_id"]), status="open",
                        details={"reason": "feishu-outbox-send-failed", "event_id": event_id, "error": str(error)[:500]},
                    )
            row = connection.execute(
                "SELECT * FROM agent_events WHERE event_id = ?", (event_id,)
            ).fetchone()
            if row is None:
                raise TransportError("找不到 event")
            return dict(row)

    def publish_completion_notification(
        self,
        token: str,
        *,
        event_key: str,
        session_id: str,
        conversation: str,
        user_message: str,
        answer: str,
    ) -> dict[str, Any]:
        """Persist one local completion for private-workspace delivery.

        The Agent token authenticates the installation; checking the Session
        ownership here prevents one paired machine from notifying another
        user's workspace.
        """

        credential = self._credential(token)
        session = self._session(session_id)
        installation_id = str(credential["installation_id"])
        if str(session.get("installation_id", "")) != installation_id:
            raise TransportError("session 不属于当前 Agent")
        event_key = _text(event_key, "event_key", 1200)
        notification_id = hashlib.sha256(
            f"{installation_id}\0{event_key}".encode("utf-8")
        ).hexdigest()
        timestamp = now()
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO agent_completion_notifications("
                "notification_id,event_key,installation_id,session_id,conversation,user_message,answer,"
                "status,lease_until,attempts,next_attempt_at,created_at,updated_at,last_error) "
                "VALUES (?,?,?,?,?,?,?,'pending',0,0,?,?,?, '') "
                "ON CONFLICT(notification_id) DO UPDATE SET "
                "conversation=CASE WHEN agent_completion_notifications.status='sent' "
                "THEN agent_completion_notifications.conversation ELSE excluded.conversation END, "
                "user_message=CASE WHEN agent_completion_notifications.status='sent' "
                "THEN agent_completion_notifications.user_message ELSE excluded.user_message END, "
                "answer=CASE WHEN agent_completion_notifications.status='sent' "
                "THEN agent_completion_notifications.answer ELSE excluded.answer END, "
                "status=CASE WHEN agent_completion_notifications.status='sent' THEN 'sent' ELSE 'pending' END, "
                "lease_until=0, next_attempt_at=excluded.next_attempt_at, updated_at=excluded.updated_at, last_error=''",
                (
                    notification_id, event_key, installation_id, str(session.get("session_id", "")),
                    _text(conversation, "conversation", 120, required=False),
                    _text(user_message, "user_message", 3000, required=False),
                    _text(answer, "answer", 8000, required=False),
                    timestamp, timestamp, timestamp,
                ),
            )
            row = connection.execute(
                "SELECT * FROM agent_completion_notifications WHERE notification_id = ?", (notification_id,)
            ).fetchone()
        if row is None:
            raise TransportError("completion notification 写入失败")
        return dict(row)

    def next_completion_notification(self) -> dict[str, Any] | None:
        timestamp = now()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM agent_completion_notifications WHERE "
                "((status IN ('pending','failed') AND next_attempt_at <= ?) OR "
                "(status='claimed' AND lease_until < ?)) ORDER BY created_at LIMIT 1",
                (timestamp, timestamp),
            ).fetchone()
        return dict(row) if row is not None else None

    def claim_completion_notification(self, notification_id: str, *, lease_seconds: int = 120) -> dict[str, Any] | None:
        notification_id = _text(notification_id, "notification_id", 80)
        if lease_seconds < 10 or lease_seconds > 3600:
            raise TransportError("lease_seconds 必须在 10 到 3600 之间")
        timestamp = now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM agent_completion_notifications WHERE notification_id = ?", (notification_id,)
            ).fetchone()
            if row is None:
                connection.rollback()
                raise TransportError("找不到 completion notification")
            if row["status"] == "sent" or (row["status"] == "claimed" and int(row["lease_until"] or 0) >= timestamp):
                connection.rollback()
                return None
            connection.execute(
                "UPDATE agent_completion_notifications SET status='claimed', lease_until=?, attempts=attempts+1, updated_at=? "
                "WHERE notification_id=?", (timestamp + lease_seconds, timestamp, notification_id),
            )
            connection.commit()
            updated = connection.execute(
                "SELECT * FROM agent_completion_notifications WHERE notification_id = ?", (notification_id,)
            ).fetchone()
        return dict(updated) if updated is not None else None

    def complete_completion_notification(
        self, notification_id: str, *, status: str = "sent", error: str = "", retry_after: int = 60
    ) -> dict[str, Any]:
        if status not in {"sent", "failed"}:
            raise TransportError("completion notification 状态无效")
        if retry_after < 1 or retry_after > 86400:
            raise TransportError("retry_after 必须在 1 到 86400 秒之间")
        timestamp = now()
        with self._connect() as connection:
            if status == "sent":
                connection.execute(
                    "UPDATE agent_completion_notifications SET status='sent', lease_until=0, updated_at=?, last_error='' "
                    "WHERE notification_id=?", (timestamp, notification_id),
                )
            else:
                connection.execute(
                    "UPDATE agent_completion_notifications SET status='failed', lease_until=0, updated_at=?, "
                    "next_attempt_at=?, last_error=? WHERE notification_id=?",
                    (timestamp, timestamp + retry_after, _text(error, "error", 500, required=False), notification_id),
                )
            row = connection.execute(
                "SELECT * FROM agent_completion_notifications WHERE notification_id = ?", (notification_id,)
            ).fetchone()
        if row is None:
            raise TransportError("找不到 completion notification")
        return dict(row)
