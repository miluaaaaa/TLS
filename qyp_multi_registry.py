#!/usr/bin/env python3
"""Small, transactional control plane for the TLS multi-user branch.

This module deliberately has no Feishu or Codex transport dependency.  It
stores ownership and authorization facts that an ingress adapter can consult:

    Feishu user -> installation -> Codex session
    Feishu group -> members + explicitly shared sessions

The private single-user TLS runtime is not imported or modified here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any, Iterable


DEFAULT_DB = Path.home() / ".local/state/qyp-tls-multi/multi.sqlite3"
SCHEMA_VERSION = 4
SESSION_ID = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$", re.IGNORECASE)
IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:-]{1,160}$")
GROUP_SLOT = re.compile(r"^[a-z][a-z0-9_-]{1,31}$", re.IGNORECASE)
RESERVED_GROUP_SLOTS = {"q1", "q2", "ad"}
ROLE_VALUES = {"owner", "admin", "member"}
USER_STATUS_VALUES = {"pending", "approved", "disabled"}
INSTALLATION_STATUS_VALUES = {"active", "disabled"}
SESSION_STATUS_VALUES = {"unknown", "idle", "running", "offline"}
ACCESS_VALUES = {"read", "write"}
COMMAND_STATUS_VALUES = {"claimed", "completed", "failed"}
TASK_STATUS_VALUES = {"planned", "running", "completed", "failed", "cancelled"}
TASK_RELATION_VALUES = {"primary", "worker", "observer"}
TASK_ACCESS_VALUES = {"read", "write"}
DELIVERY_STATUS_VALUES = {"pending", "claimed", "sent", "failed"}


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    feishu_open_id TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'disabled')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS installations (
    installation_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    hostname TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    installation_id TEXT NOT NULL REFERENCES installations(installation_id) ON DELETE CASCADE,
    label TEXT NOT NULL DEFAULT '',
    workspace TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK (status IN ('unknown', 'idle', 'running', 'offline')),
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER
);

CREATE TABLE IF NOT EXISTS groups_ (
    group_id TEXT PRIMARY KEY,
    feishu_chat_id TEXT UNIQUE,
    name TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id TEXT NOT NULL REFERENCES groups_(group_id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('owner', 'member')),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (group_id, user_id)
);

CREATE TABLE IF NOT EXISTS session_shares (
    group_id TEXT NOT NULL REFERENCES groups_(group_id) ON DELETE CASCADE,
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    access TEXT NOT NULL CHECK (access IN ('read', 'write')),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (group_id, session_id)
);

CREATE TABLE IF NOT EXISTS session_slots (
    group_id TEXT NOT NULL REFERENCES groups_(group_id) ON DELETE CASCADE,
    slot TEXT NOT NULL,
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    assigned_by TEXT NOT NULL REFERENCES users(user_id),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (group_id, slot),
    UNIQUE (group_id, session_id)
);

CREATE TABLE IF NOT EXISTS subscriptions (
    group_id TEXT NOT NULL REFERENCES groups_(group_id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    session_id TEXT REFERENCES sessions(session_id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (group_id, user_id, session_id)
);

CREATE TABLE IF NOT EXISTS pairing_codes (
    code_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    installation_id TEXT REFERENCES installations(installation_id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS commands (
    message_id TEXT PRIMARY KEY,
    open_id TEXT NOT NULL,
    chat_id TEXT NOT NULL DEFAULT '',
    session_id TEXT NOT NULL,
    task_id TEXT REFERENCES tasks(task_id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('claimed', 'completed', 'failed')),
    lease_until INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_open_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT PRIMARY KEY,
    owner_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    contract_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('planned', 'running', 'completed', 'failed', 'cancelled')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS task_sessions (
    task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    relation TEXT NOT NULL CHECK (relation IN ('primary', 'worker', 'observer')),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (task_id, session_id)
);

CREATE TABLE IF NOT EXISTS task_groups (
    task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
    group_id TEXT NOT NULL REFERENCES groups_(group_id) ON DELETE CASCADE,
    access TEXT NOT NULL CHECK (access IN ('read', 'write')),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (task_id, group_id)
);

CREATE TABLE IF NOT EXISTS task_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
    session_id TEXT REFERENCES sessions(session_id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    actor_open_id TEXT NOT NULL DEFAULT '',
    idempotency_key TEXT,
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL,
    UNIQUE (task_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS task_event_deliveries (
    delivery_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL REFERENCES task_events(event_id) ON DELETE CASCADE,
    task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
    group_id TEXT NOT NULL REFERENCES groups_(group_id) ON DELETE CASCADE,
    chat_id TEXT NOT NULL DEFAULT '',
    session_id TEXT REFERENCES sessions(session_id) ON DELETE SET NULL,
    recipient_open_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'claimed', 'sent', 'failed')),
    lease_until INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    sent_at INTEGER,
    last_error TEXT NOT NULL DEFAULT '',
    UNIQUE (event_id, group_id, recipient_open_id)
);

CREATE INDEX IF NOT EXISTS idx_users_open_id ON users(feishu_open_id);
CREATE INDEX IF NOT EXISTS idx_installations_user ON installations(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_installation ON sessions(installation_id);
CREATE INDEX IF NOT EXISTS idx_groups_chat ON groups_(feishu_chat_id);
CREATE INDEX IF NOT EXISTS idx_commands_status ON commands(status, lease_until);
CREATE INDEX IF NOT EXISTS idx_pairings_expiry ON pairing_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_session_slots_session ON session_slots(group_id, session_id);
CREATE INDEX IF NOT EXISTS idx_tasks_owner ON tasks(owner_user_id, updated_at);
CREATE INDEX IF NOT EXISTS idx_task_sessions_session ON task_sessions(session_id, task_id);
CREATE INDEX IF NOT EXISTS idx_task_groups_group ON task_groups(group_id, task_id);
CREATE INDEX IF NOT EXISTS idx_task_events_task ON task_events(task_id, event_id);
CREATE INDEX IF NOT EXISTS idx_task_events_session ON task_events(session_id, event_id);
CREATE INDEX IF NOT EXISTS idx_task_deliveries_ready ON task_event_deliveries(status, next_attempt_at, lease_until);
"""


class RegistryError(ValueError):
    """Expected input or state error exposed to the CLI/adapter."""


class AuthorizationDenied(RegistryError):
    """The user does not have access to the requested session."""


def now() -> int:
    return int(time.time())


def _db_from_env() -> Path:
    return Path(os.environ.get("QYP_TLS_MULTI_DB", str(DEFAULT_DB)))


def _identifier(value: object, field: str) -> str:
    result = str(value or "").strip()
    if not result or not IDENTIFIER.fullmatch(result):
        raise RegistryError(f"{field} 不是有效标识符")
    return result


def _group_slot(value: object) -> str:
    result = str(value or "").strip().casefold()
    if not GROUP_SLOT.fullmatch(result):
        raise RegistryError("群组槽位必须是 2 到 32 位字母数字别名")
    if result in RESERVED_GROUP_SLOTS:
        raise RegistryError("q1、q2 和 ad 是系统保留槽位")
    return result


def _owner_slot_prefix(owner_user_id: str, owner_name: str, group_creator_id: str) -> str:
    """Return a stable, non-secret command prefix for a Session owner."""

    if owner_user_id == group_creator_id:
        return "q"
    source = re.sub(r"[^a-z0-9]+", "-", str(owner_name or "").casefold()).strip("-")
    if not source or source in RESERVED_GROUP_SLOTS:
        source = f"u-{hashlib.sha256(owner_user_id.encode('utf-8')).hexdigest()[:6]}"
    if source[0].isdigit():
        source = f"u-{source}"
    return source[:24]


def _text(value: object, field: str, limit: int = 240, required: bool = True) -> str:
    result = str(value or "").strip()
    if required and not result:
        raise RegistryError(f"{field} 不能为空")
    if len(result) > limit:
        raise RegistryError(f"{field} 过长")
    return result


def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def _rows(rows: Iterable[sqlite3.Row]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]


def _json_object(
    value: object,
    field: str,
    limit: int = 16000,
    *,
    allow_empty: bool = False,
) -> tuple[dict[str, Any], str]:
    if not isinstance(value, dict) or (not allow_empty and not value):
        requirement = "JSON 对象" if allow_empty else "非空 JSON 对象"
        raise RegistryError(f"{field} 必须是{requirement}")
    try:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise RegistryError(f"{field} 不是可序列化的 JSON 对象") from exc
    if len(encoded) > limit:
        raise RegistryError(f"{field} 过长")
    return value, encoded


class Registry:
    """SQLite-backed registry with short, explicit authorization methods."""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path is not None else _db_from_env()

    def _migrate_schema(self, connection: sqlite3.Connection) -> None:
        row = connection.execute(
            "SELECT value FROM meta WHERE key = 'schema_version'"
        ).fetchone()
        current = int(row[0]) if row is not None else 0
        if current > SCHEMA_VERSION:
            raise RegistryError(
                f"数据库 schema_version={current} 高于当前支持版本 {SCHEMA_VERSION}"
            )
        if current < 3:
            command_columns = {
                str(row[1]) for row in connection.execute("PRAGMA table_info(commands)")
            }
            if "task_id" not in command_columns:
                connection.execute("ALTER TABLE commands ADD COLUMN task_id TEXT")
        if current < SCHEMA_VERSION:
            # New tables are created by SCHEMA above.  The explicit version
            # update keeps upgrades from v1 repeatable and observable.
            connection.execute(
                "INSERT INTO meta(key, value) VALUES ('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (str(SCHEMA_VERSION),),
            )
        elif row is None:
            connection.execute(
                "INSERT INTO meta(key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.executescript(SCHEMA)
        self._migrate_schema(connection)
        # Keep each caller at a clean transaction boundary.  Methods that
        # claim messages use BEGIN IMMEDIATE for an atomic dedupe decision.
        connection.commit()
        return connection

    def init(self) -> dict[str, Any]:
        with self._connect() as connection:
            connection.commit()
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        return {"path": str(self.path), "schema_version": SCHEMA_VERSION}

    def _audit(
        self,
        connection: sqlite3.Connection,
        actor_open_id: str,
        action: str,
        target_type: str,
        target_id: str,
        detail: str = "",
    ) -> None:
        connection.execute(
            "INSERT INTO audit_events(actor_open_id, action, target_type, target_id, detail, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (actor_open_id[:160], action[:80], target_type[:80], target_id[:160], detail[:500], now()),
        )

    def _user_row(self, connection: sqlite3.Connection, reference: str) -> sqlite3.Row:
        reference = _text(reference, "user")
        row = connection.execute(
            "SELECT * FROM users WHERE user_id = ? OR feishu_open_id = ?",
            (reference, reference),
        ).fetchone()
        if row is None:
            raise RegistryError(f"找不到用户: {reference}")
        return row

    def _group_row(self, connection: sqlite3.Connection, reference: str) -> sqlite3.Row:
        reference = _text(reference, "group")
        row = connection.execute(
            "SELECT * FROM groups_ WHERE group_id = ? OR feishu_chat_id = ?",
            (reference, reference),
        ).fetchone()
        if row is None:
            raise RegistryError(f"找不到群组: {reference}")
        return row

    def _share_user_sessions_with_group(
        self,
        connection: sqlite3.Connection,
        group_id: str,
        user_id: str,
        timestamp: int,
    ) -> None:
        """Make a member's existing Sessions available in their new group."""

        connection.execute(
            "INSERT OR IGNORE INTO session_shares(group_id, session_id, access, created_at) "
            "SELECT ?, s.session_id, 'write', ? FROM sessions s "
            "JOIN installations i ON i.installation_id = s.installation_id "
            "WHERE i.user_id = ?",
            (group_id, timestamp, user_id),
        )

    def _share_session_with_member_groups(
        self,
        connection: sqlite3.Connection,
        session_id: str,
        owner_user_id: str,
        timestamp: int,
    ) -> None:
        """Make a newly registered Session available in all owner groups."""

        connection.execute(
            "INSERT OR IGNORE INTO session_shares(group_id, session_id, access, created_at) "
            "SELECT gm.group_id, ?, 'write', ? FROM group_members gm "
            "WHERE gm.user_id = ?",
            (session_id, timestamp, owner_user_id),
        )

    def add_user(
        self,
        feishu_open_id: str,
        display_name: str,
        *,
        user_id: str | None = None,
        role: str = "member",
        status: str = "pending",
    ) -> dict[str, Any]:
        open_id = _text(feishu_open_id, "feishu_open_id", 160)
        name = _text(display_name, "display_name", 120)
        role = _text(role, "role")
        status = _text(status, "status")
        if role not in ROLE_VALUES:
            raise RegistryError(f"role 必须是 {sorted(ROLE_VALUES)} 之一")
        if status not in USER_STATUS_VALUES:
            raise RegistryError(f"status 必须是 {sorted(USER_STATUS_VALUES)} 之一")
        uid = _identifier(user_id or f"user-{secrets.token_hex(6)}", "user_id")
        timestamp = now()
        with self._connect() as connection:
            try:
                connection.execute(
                    "INSERT INTO users(user_id, feishu_open_id, display_name, role, status, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (uid, open_id, name, role, status, timestamp, timestamp),
                )
            except sqlite3.IntegrityError as exc:
                raise RegistryError("用户标识或飞书 open_id 已存在") from exc
            return dict(self._user_row(connection, uid))

    def set_user_status(self, reference: str, status: str) -> dict[str, Any]:
        status = _text(status, "status")
        if status not in USER_STATUS_VALUES:
            raise RegistryError(f"status 必须是 {sorted(USER_STATUS_VALUES)} 之一")
        with self._connect() as connection:
            user = self._user_row(connection, reference)
            connection.execute("UPDATE users SET status = ?, updated_at = ? WHERE user_id = ?", (status, now(), user["user_id"]))
            return dict(self._user_row(connection, str(user["user_id"])))

    def list_users(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            return _rows(connection.execute("SELECT * FROM users ORDER BY created_at, user_id"))

    def add_installation(
        self,
        user_reference: str,
        name: str,
        *,
        installation_id: str | None = None,
        hostname: str = "",
    ) -> dict[str, Any]:
        name = _text(name, "installation name", 120)
        host = _text(hostname, "hostname", 240, required=False)
        iid = _identifier(installation_id or f"inst-{secrets.token_hex(6)}", "installation_id")
        timestamp = now()
        with self._connect() as connection:
            user = self._user_row(connection, user_reference)
            if user["status"] != "approved":
                raise RegistryError("用户尚未 approved，不能登记安装实例")
            try:
                connection.execute(
                    "INSERT INTO installations(installation_id, user_id, name, hostname, status, created_at, last_seen_at) "
                    "VALUES (?, ?, ?, ?, 'active', ?, ?)",
                    (iid, user["user_id"], name, host, timestamp, timestamp),
                )
            except sqlite3.IntegrityError as exc:
                raise RegistryError("installation_id 已存在") from exc
            return dict(connection.execute("SELECT * FROM installations WHERE installation_id = ?", (iid,)).fetchone())

    def add_session(
        self,
        installation_id: str,
        session_id: str,
        label: str = "",
        *,
        workspace: str = "",
        status: str = "unknown",
    ) -> dict[str, Any]:
        iid = _identifier(installation_id, "installation_id")
        sid = _text(session_id, "session_id", 80).lower()
        if not SESSION_ID.fullmatch(sid):
            raise RegistryError("session_id 必须是 Codex UUID")
        status = _text(status, "status")
        if status not in SESSION_STATUS_VALUES:
            raise RegistryError(f"status 必须是 {sorted(SESSION_STATUS_VALUES)} 之一")
        label = _text(label, "label", 160, required=False)
        workspace = _text(workspace, "workspace", 500, required=False)
        timestamp = now()
        with self._connect() as connection:
            installation = connection.execute("SELECT * FROM installations WHERE installation_id = ?", (iid,)).fetchone()
            if installation is None:
                raise RegistryError(f"找不到安装实例: {iid}")
            if installation["status"] != "active":
                raise RegistryError("安装实例已停用")
            try:
                connection.execute(
                    "INSERT INTO sessions(session_id, installation_id, label, workspace, status, created_at, last_seen_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (sid, iid, label, workspace, status, timestamp, timestamp),
                )
            except sqlite3.IntegrityError as exc:
                raise RegistryError("session_id 已登记") from exc
            self._share_session_with_member_groups(
                connection,
                sid,
                str(installation["user_id"]),
                timestamp,
            )
            return dict(connection.execute("SELECT * FROM sessions WHERE session_id = ?", (sid,)).fetchone())

    def update_session(self, session_id: str, *, label: str | None = None, status: str | None = None, workspace: str | None = None) -> dict[str, Any]:
        sid = _text(session_id, "session_id", 80).lower()
        updates: list[str] = []
        values: list[object] = []
        if label is not None:
            updates.append("label = ?")
            values.append(_text(label, "label", 160, required=False))
        if workspace is not None:
            updates.append("workspace = ?")
            values.append(_text(workspace, "workspace", 500, required=False))
        if status is not None:
            status = _text(status, "status")
            if status not in SESSION_STATUS_VALUES:
                raise RegistryError(f"status 必须是 {sorted(SESSION_STATUS_VALUES)} 之一")
            updates.append("status = ?")
            values.append(status)
        if not updates:
            raise RegistryError("至少提供一个 session 更新字段")
        updates.extend(["last_seen_at = ?"])
        values.extend([now(), sid])
        with self._connect() as connection:
            connection.execute(f"UPDATE sessions SET {', '.join(updates)} WHERE session_id = ?", values)
            row = connection.execute("SELECT * FROM sessions WHERE session_id = ?", (sid,)).fetchone()
            if row is None:
                raise RegistryError(f"找不到 session: {sid}")
            return dict(row)

    def list_sessions(self, user_reference: str | None = None) -> list[dict[str, Any]]:
        with self._connect() as connection:
            if user_reference:
                user = self._user_row(connection, user_reference)
                rows = connection.execute(
                    "SELECT s.*, i.user_id, i.name AS installation_name FROM sessions s "
                    "JOIN installations i ON i.installation_id = s.installation_id "
                    "WHERE i.user_id = ? ORDER BY s.created_at, s.session_id",
                    (user["user_id"],),
                )
            else:
                rows = connection.execute(
                    "SELECT s.*, i.user_id, i.name AS installation_name FROM sessions s "
                    "JOIN installations i ON i.installation_id = s.installation_id "
                    "ORDER BY s.created_at, s.session_id"
                )
            return _rows(rows)

    def _task_row(self, connection: sqlite3.Connection, task_id: str) -> sqlite3.Row:
        tid = _identifier(task_id, "task_id")
        row = connection.execute("SELECT * FROM tasks WHERE task_id = ?", (tid,)).fetchone()
        if row is None:
            raise RegistryError(f"找不到 task: {tid}")
        return row

    @staticmethod
    def _task_dict(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        try:
            result["contract"] = json.loads(result.pop("contract_json"))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RegistryError("task contract 数据损坏") from exc
        return result

    @staticmethod
    def _task_event_dict(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        try:
            result["payload"] = json.loads(result.pop("payload_json"))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RegistryError("task event payload 数据损坏") from exc
        return result

    def create_task(
        self,
        owner_reference: str,
        name: str,
        contract: dict[str, Any],
        *,
        task_id: str | None = None,
        status: str = "planned",
    ) -> dict[str, Any]:
        tid = _identifier(task_id or f"task-{secrets.token_hex(6)}", "task_id")
        task_name = _text(name, "task name", 160)
        status = _text(status, "status")
        if status not in TASK_STATUS_VALUES:
            raise RegistryError(f"task status 必须是 {sorted(TASK_STATUS_VALUES)} 之一")
        _, contract_json = _json_object(contract, "contract")
        timestamp = now()
        with self._connect() as connection:
            owner = self._user_row(connection, owner_reference)
            if owner["status"] != "approved":
                raise RegistryError("任务所有者尚未 approved")
            try:
                connection.execute(
                    "INSERT INTO tasks(task_id, owner_user_id, name, contract_json, status, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (tid, owner["user_id"], task_name, contract_json, status, timestamp, timestamp),
                )
            except sqlite3.IntegrityError as exc:
                raise RegistryError("task_id 已存在") from exc
            self._audit(connection, owner["feishu_open_id"], "create_task", "task", tid, task_name)
            return self._task_dict(self._task_row(connection, tid))

    def update_task(
        self,
        task_id: str,
        *,
        name: str | None = None,
        contract: dict[str, Any] | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        tid = _identifier(task_id, "task_id")
        updates: list[str] = []
        values: list[object] = []
        if name is not None:
            updates.append("name = ?")
            values.append(_text(name, "task name", 160))
        if contract is not None:
            _, contract_json = _json_object(contract, "contract")
            updates.append("contract_json = ?")
            values.append(contract_json)
        if status is not None:
            status = _text(status, "status")
            if status not in TASK_STATUS_VALUES:
                raise RegistryError(f"task status 必须是 {sorted(TASK_STATUS_VALUES)} 之一")
            updates.append("status = ?")
            values.append(status)
        if not updates:
            raise RegistryError("至少提供一个 task 更新字段")
        with self._connect() as connection:
            task = self._task_row(connection, tid)
            updates.append("updated_at = ?")
            values.extend([now(), tid])
            connection.execute(f"UPDATE tasks SET {', '.join(updates)} WHERE task_id = ?", values)
            owner = connection.execute(
                "SELECT feishu_open_id FROM users WHERE user_id = ?", (task["owner_user_id"],)
            ).fetchone()
            self._audit(connection, str(owner["feishu_open_id"] if owner else ""), "update_task", "task", tid)
            return self._task_dict(self._task_row(connection, tid))

    def get_task(self, task_id: str) -> dict[str, Any]:
        tid = _identifier(task_id, "task_id")
        with self._connect() as connection:
            task = self._task_dict(self._task_row(connection, tid))
            task["sessions"] = _rows(connection.execute(
                "SELECT ts.task_id, ts.session_id, ts.relation, ts.created_at, s.label, s.status, "
                "i.user_id AS owner_user_id FROM task_sessions ts "
                "JOIN sessions s ON s.session_id = ts.session_id "
                "JOIN installations i ON i.installation_id = s.installation_id "
                "WHERE ts.task_id = ? ORDER BY ts.created_at, ts.session_id",
                (tid,),
            ))
            return task

    def list_tasks(
        self,
        owner_reference: str | None = None,
        *,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        if status is not None:
            status = _text(status, "status")
            if status not in TASK_STATUS_VALUES:
                raise RegistryError(f"task status 必须是 {sorted(TASK_STATUS_VALUES)} 之一")
        with self._connect() as connection:
            parameters: list[object] = []
            clauses: list[str] = []
            if owner_reference:
                owner = self._user_row(connection, owner_reference)
                clauses.append("t.owner_user_id = ?")
                parameters.append(owner["user_id"])
            if status is not None:
                clauses.append("t.status = ?")
                parameters.append(status)
            where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
            rows = connection.execute(
                "SELECT t.*, u.display_name AS owner_name, "
                "(SELECT COUNT(*) FROM task_sessions ts WHERE ts.task_id = t.task_id) AS session_count "
                "FROM tasks t JOIN users u ON u.user_id = t.owner_user_id"
                + where
                + " ORDER BY t.updated_at DESC, t.task_id",
                parameters,
            )
            return [self._task_dict(row) for row in rows]

    def attach_task_session(
        self,
        task_id: str,
        session_id: str,
        *,
        relation: str = "worker",
    ) -> dict[str, Any]:
        tid = _identifier(task_id, "task_id")
        sid = _text(session_id, "session_id", 80).lower()
        if not SESSION_ID.fullmatch(sid):
            raise RegistryError("session_id 必须是 Codex UUID")
        relation = _text(relation, "relation")
        if relation not in TASK_RELATION_VALUES:
            raise RegistryError(f"relation 必须是 {sorted(TASK_RELATION_VALUES)} 之一")
        timestamp = now()
        with self._connect() as connection:
            task = self._task_row(connection, tid)
            session = connection.execute("SELECT * FROM sessions WHERE session_id = ?", (sid,)).fetchone()
            if session is None:
                raise RegistryError(f"找不到 session: {sid}")
            connection.execute(
                "INSERT INTO task_sessions(task_id, session_id, relation, created_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(task_id, session_id) DO UPDATE SET relation = excluded.relation",
                (tid, sid, relation, timestamp),
            )
            connection.execute("UPDATE tasks SET updated_at = ? WHERE task_id = ?", (timestamp, tid))
            owner = connection.execute(
                "SELECT feishu_open_id FROM users WHERE user_id = ?", (task["owner_user_id"],)
            ).fetchone()
            self._audit(connection, str(owner["feishu_open_id"] if owner else ""), "attach_task_session", "task", tid, sid)
            return dict(connection.execute(
                "SELECT task_id, session_id, relation, created_at FROM task_sessions WHERE task_id = ? AND session_id = ?",
                (tid, sid),
            ).fetchone())

    def detach_task_session(self, task_id: str, session_id: str) -> dict[str, Any]:
        tid = _identifier(task_id, "task_id")
        sid = _text(session_id, "session_id", 80).lower()
        with self._connect() as connection:
            task = self._task_row(connection, tid)
            row = connection.execute(
                "SELECT task_id, session_id, relation, created_at FROM task_sessions WHERE task_id = ? AND session_id = ?",
                (tid, sid),
            ).fetchone()
            if row is None:
                raise RegistryError("task 与 session 尚未关联")
            connection.execute("DELETE FROM task_sessions WHERE task_id = ? AND session_id = ?", (tid, sid))
            connection.execute("UPDATE tasks SET updated_at = ? WHERE task_id = ?", (now(), tid))
            owner = connection.execute(
                "SELECT feishu_open_id FROM users WHERE user_id = ?", (task["owner_user_id"],)
            ).fetchone()
            self._audit(connection, str(owner["feishu_open_id"] if owner else ""), "detach_task_session", "task", tid, sid)
            result = dict(row)
            result["detached"] = True
            return result

    def share_task(self, group_reference: str, task_id: str, *, access: str = "read") -> dict[str, Any]:
        access = _text(access, "access")
        if access not in TASK_ACCESS_VALUES:
            raise RegistryError("task access 必须是 read 或 write")
        tid = _identifier(task_id, "task_id")
        timestamp = now()
        with self._connect() as connection:
            group = self._group_row(connection, group_reference)
            task = self._task_row(connection, tid)
            owner_member = connection.execute(
                "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?",
                (group["group_id"], task["owner_user_id"]),
            ).fetchone()
            if owner_member is None:
                raise RegistryError("任务所有者必须先加入该群组")
            connection.execute(
                "INSERT INTO task_groups(task_id, group_id, access, created_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(task_id, group_id) DO UPDATE SET access = excluded.access",
                (tid, group["group_id"], access, timestamp),
            )
            return dict(connection.execute(
                "SELECT task_id, group_id, access, created_at FROM task_groups WHERE task_id = ? AND group_id = ?",
                (tid, group["group_id"]),
            ).fetchone())

    def unshare_task(self, group_reference: str, task_id: str) -> dict[str, Any]:
        tid = _identifier(task_id, "task_id")
        with self._connect() as connection:
            group = self._group_row(connection, group_reference)
            row = connection.execute(
                "SELECT task_id, group_id, access, created_at FROM task_groups WHERE task_id = ? AND group_id = ?",
                (tid, group["group_id"]),
            ).fetchone()
            if row is None:
                raise RegistryError("任务尚未共享到该群组")
            connection.execute("DELETE FROM task_groups WHERE task_id = ? AND group_id = ?", (tid, group["group_id"]))
            return {**dict(row), "unshared": True}

    def authorize_task(
        self,
        open_id: str,
        chat_id: str | None,
        task_id: str,
        session_id: str,
        action: str = "read",
    ) -> dict[str, Any]:
        """Authorize a task-scoped event without inferring a task or session."""

        tid = _identifier(task_id, "task_id")
        sid = _text(session_id, "session_id", 80).lower()
        if not SESSION_ID.fullmatch(sid):
            raise AuthorizationDenied("session_id 无效")
        decision = self.authorize(open_id, chat_id, sid, action)
        required = "read" if action in {"read", "notify"} else "write"
        with self._connect() as connection:
            task = self._task_row(connection, tid)
            attached = connection.execute(
                "SELECT relation FROM task_sessions WHERE task_id = ? AND session_id = ?",
                (tid, sid),
            ).fetchone()
            if attached is None:
                raise AuthorizationDenied("该 session 未关联到目标 task")
            if not chat_id:
                owner = connection.execute(
                    "SELECT user_id FROM installations i JOIN sessions s ON s.installation_id = i.installation_id "
                    "WHERE s.session_id = ?", (sid,)
                ).fetchone()
                if owner is None or owner["user_id"] != task["owner_user_id"]:
                    raise AuthorizationDenied("私聊只能访问任务所有者的 session")
            else:
                share = connection.execute(
                    "SELECT access FROM task_groups WHERE task_id = ? AND group_id = ?",
                    (tid, decision["group_id"]),
                ).fetchone()
                if share is None:
                    raise AuthorizationDenied("该 task 尚未共享到当前群组")
                if required == "write" and share["access"] != "write":
                    raise AuthorizationDenied("该 task 只读")
            return {
                **decision,
                "task_id": tid,
                "task_status": task["status"],
                "task_name": task["name"],
                "task_relation": attached["relation"],
            }

    def _enqueue_task_event_deliveries(
        self,
        connection: sqlite3.Connection,
        event_id: int,
        task_id: str,
        session_id: str | None,
        timestamp: int,
    ) -> int:
        groups = connection.execute(
            "SELECT tg.group_id, g.feishu_chat_id FROM task_groups tg "
            "JOIN groups_ g ON g.group_id = tg.group_id WHERE tg.task_id = ?",
            (task_id,),
        ).fetchall()
        inserted = 0
        for group in groups:
            if session_id is not None:
                shared = connection.execute(
                    "SELECT 1 FROM session_shares WHERE group_id = ? AND session_id = ?",
                    (group["group_id"], session_id),
                ).fetchone()
                if shared is None:
                    continue
                subscription_clause = "sub.session_id = ? OR sub.session_id IS NULL"
                subscription_args: tuple[object, ...] = (session_id,)
            else:
                subscription_clause = "sub.session_id IS NULL"
                subscription_args = ()
            recipients = connection.execute(
                "SELECT DISTINCT u.feishu_open_id FROM subscriptions sub "
                "JOIN users u ON u.user_id = sub.user_id "
                "JOIN group_members gm ON gm.group_id = sub.group_id AND gm.user_id = sub.user_id "
                "WHERE sub.group_id = ? AND u.status = 'approved' AND (" + subscription_clause + ")",
                (group["group_id"], *subscription_args),
            ).fetchall()
            for recipient in recipients:
                cursor = connection.execute(
                    "INSERT OR IGNORE INTO task_event_deliveries("
                    "event_id, task_id, group_id, chat_id, session_id, recipient_open_id, status, "
                    "lease_until, attempts, next_attempt_at, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, 'pending', 0, 0, ?, ?, ?)",
                    (
                        event_id,
                        task_id,
                        group["group_id"],
                        str(group["feishu_chat_id"] or ""),
                        session_id,
                        recipient["feishu_open_id"],
                        timestamp,
                        timestamp,
                        timestamp,
                    ),
                )
                inserted += int(cursor.rowcount > 0)
        return inserted

    def _append_task_event_in_connection(
        self,
        connection: sqlite3.Connection,
        task_id: str,
        event_type: str,
        payload: dict[str, Any],
        *,
        session_id: str | None,
        actor_open_id: str,
        idempotency_key: str | None,
        timestamp: int,
    ) -> sqlite3.Row:
        tid = _identifier(task_id, "task_id")
        event_name = _text(event_type, "event_type", 80)
        _, payload_json = _json_object(payload, "payload", allow_empty=True)
        actor = _text(actor_open_id, "actor_open_id", 160, required=False)
        sid = None
        if session_id is not None:
            sid = _text(session_id, "session_id", 80).lower()
            if not SESSION_ID.fullmatch(sid):
                raise RegistryError("session_id 必须是 Codex UUID")
            attached = connection.execute(
                "SELECT 1 FROM task_sessions WHERE task_id = ? AND session_id = ?", (tid, sid)
            ).fetchone()
            if attached is None:
                raise RegistryError("事件的 session 必须先关联到该 task")
        task = self._task_row(connection, tid)
        if idempotency_key is not None:
            existing = connection.execute(
                "SELECT * FROM task_events WHERE task_id = ? AND idempotency_key = ?",
                (tid, idempotency_key),
            ).fetchone()
            if existing is not None:
                return existing
        cursor = connection.execute(
            "INSERT INTO task_events(task_id, session_id, event_type, actor_open_id, idempotency_key, payload_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (tid, sid, event_name, actor, idempotency_key, payload_json, timestamp),
        )
        event_id = int(cursor.lastrowid)
        connection.execute("UPDATE tasks SET updated_at = ? WHERE task_id = ?", (timestamp, tid))
        owner = connection.execute(
            "SELECT feishu_open_id FROM users WHERE user_id = ?", (task["owner_user_id"],)
        ).fetchone()
        self._audit(
            connection,
            actor or str(owner["feishu_open_id"] if owner else ""),
            "append_task_event",
            "task_event",
            str(event_id),
            f"{tid}:{event_name}",
        )
        self._enqueue_task_event_deliveries(connection, event_id, tid, sid, timestamp)
        return connection.execute("SELECT * FROM task_events WHERE event_id = ?", (event_id,)).fetchone()

    def append_task_event(
        self,
        task_id: str,
        event_type: str,
        payload: dict[str, Any],
        *,
        session_id: str | None = None,
        actor_open_id: str = "",
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        tid = _identifier(task_id, "task_id")
        idem = None if idempotency_key is None else _text(idempotency_key, "idempotency_key", 160)
        timestamp = now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._append_task_event_in_connection(
                connection,
                tid,
                event_type,
                payload,
                session_id=session_id,
                actor_open_id=actor_open_id,
                idempotency_key=idem,
                timestamp=timestamp,
            )
            connection.commit()
            return self._task_event_dict(row)

    def list_task_events(
        self,
        task_id: str,
        *,
        session_id: str | None = None,
        event_type: str | None = None,
        after_event_id: int | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        tid = _identifier(task_id, "task_id")
        if limit < 1 or limit > 500:
            raise RegistryError("limit 必须在 1 到 500 之间")
        with self._connect() as connection:
            self._task_row(connection, tid)
            clauses = ["task_id = ?"]
            parameters: list[object] = [tid]
            if session_id is not None:
                sid = _text(session_id, "session_id", 80).lower()
                clauses.append("session_id = ?")
                parameters.append(sid)
            if event_type is not None:
                clauses.append("event_type = ?")
                parameters.append(_text(event_type, "event_type", 80))
            if after_event_id is not None:
                if after_event_id < 0:
                    raise RegistryError("after_event_id 不能为负数")
                clauses.append("event_id > ?")
                parameters.append(after_event_id)
            parameters.append(limit)
            rows = connection.execute(
                "SELECT * FROM task_events WHERE " + " AND ".join(clauses) +
                " ORDER BY event_id LIMIT ?", parameters
            )
            return [self._task_event_dict(row) for row in rows]

    @staticmethod
    def _delivery_dict(row: sqlite3.Row) -> dict[str, Any]:
        return dict(row)

    def next_task_event_delivery(self) -> dict[str, Any] | None:
        timestamp = now()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM task_event_deliveries WHERE "
                "((status IN ('pending', 'failed') AND next_attempt_at <= ?) "
                "OR (status = 'claimed' AND lease_until < ?)) "
                "ORDER BY delivery_id LIMIT 1",
                (timestamp, timestamp),
            ).fetchone()
            return self._delivery_dict(row) if row is not None else None

    def task_event_delivery(self, delivery_id: int) -> dict[str, Any]:
        if delivery_id < 1:
            raise RegistryError("delivery_id 无效")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT d.*, e.event_type, e.actor_open_id, e.idempotency_key, e.payload_json, "
                "t.name AS task_name, s.label AS session_label "
                "FROM task_event_deliveries d JOIN task_events e ON e.event_id = d.event_id "
                "JOIN tasks t ON t.task_id = d.task_id "
                "LEFT JOIN sessions s ON s.session_id = d.session_id "
                "WHERE d.delivery_id = ?",
                (delivery_id,),
            ).fetchone()
            if row is None:
                raise RegistryError("找不到 delivery")
            result = dict(row)
            try:
                result["payload"] = json.loads(result.pop("payload_json"))
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise RegistryError("delivery event payload 数据损坏") from exc
            return result

    def claim_task_event_delivery(
        self,
        delivery_id: int,
        *,
        lease_seconds: int = 120,
    ) -> dict[str, Any] | None:
        if delivery_id < 1:
            raise RegistryError("delivery_id 无效")
        if lease_seconds < 1 or lease_seconds > 3600:
            raise RegistryError("delivery lease 必须在 1 到 3600 秒之间")
        timestamp = now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM task_event_deliveries WHERE delivery_id = ?", (delivery_id,)
            ).fetchone()
            if row is None:
                connection.rollback()
                raise RegistryError("找不到 delivery")
            member = connection.execute(
                "SELECT 1 FROM group_members gm JOIN users u ON u.user_id = gm.user_id "
                "WHERE gm.group_id = ? AND u.feishu_open_id = ? AND u.status = 'approved'",
                (row["group_id"], row["recipient_open_id"]),
            ).fetchone()
            task_share = connection.execute(
                "SELECT 1 FROM task_groups WHERE task_id = ? AND group_id = ?",
                (row["task_id"], row["group_id"]),
            ).fetchone()
            if row["session_id"]:
                session_share = connection.execute(
                    "SELECT 1 FROM session_shares WHERE group_id = ? AND session_id = ?",
                    (row["group_id"], row["session_id"]),
                ).fetchone()
                subscription = connection.execute(
                    "SELECT 1 FROM subscriptions sub JOIN users u ON u.user_id = sub.user_id "
                    "WHERE sub.group_id = ? AND u.feishu_open_id = ? "
                    "AND (sub.session_id = ? OR sub.session_id IS NULL)",
                    (row["group_id"], row["recipient_open_id"], row["session_id"]),
                ).fetchone()
            else:
                session_share = True
                subscription = connection.execute(
                    "SELECT 1 FROM subscriptions sub JOIN users u ON u.user_id = sub.user_id "
                    "WHERE sub.group_id = ? AND u.feishu_open_id = ? AND sub.session_id IS NULL",
                    (row["group_id"], row["recipient_open_id"]),
                ).fetchone()
            if member is None or task_share is None or session_share is None or subscription is None:
                connection.execute("DELETE FROM task_event_deliveries WHERE delivery_id = ?", (delivery_id,))
                connection.commit()
                return None
            if row["status"] == "sent" or (
                row["status"] == "claimed" and int(row["lease_until"] or 0) >= timestamp
            ):
                connection.rollback()
                return None
            connection.execute(
                "UPDATE task_event_deliveries SET status = 'claimed', lease_until = ?, "
                "attempts = attempts + 1, updated_at = ? WHERE delivery_id = ?",
                (timestamp + lease_seconds, timestamp, delivery_id),
            )
            connection.commit()
            return self._delivery_dict(connection.execute(
                "SELECT * FROM task_event_deliveries WHERE delivery_id = ?", (delivery_id,)
            ).fetchone())

    def complete_task_event_delivery(
        self,
        delivery_id: int,
        *,
        status: str = "sent",
        error: str = "",
        retry_after: int = 60,
    ) -> dict[str, Any]:
        status = _text(status, "status")
        if status not in {"sent", "failed"}:
            raise RegistryError("delivery 完成状态必须是 sent 或 failed")
        if retry_after < 1 or retry_after > 86400:
            raise RegistryError("retry_after 必须在 1 到 86400 秒之间")
        timestamp = now()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM task_event_deliveries WHERE delivery_id = ?", (delivery_id,)
            ).fetchone()
            if row is None:
                raise RegistryError("找不到 delivery")
            if status == "sent":
                connection.execute(
                    "UPDATE task_event_deliveries SET status = 'sent', lease_until = 0, "
                    "updated_at = ?, sent_at = ?, last_error = '' WHERE delivery_id = ?",
                    (timestamp, timestamp, delivery_id),
                )
            else:
                connection.execute(
                    "UPDATE task_event_deliveries SET status = 'failed', lease_until = 0, "
                    "updated_at = ?, next_attempt_at = ?, last_error = ? WHERE delivery_id = ?",
                    (timestamp, timestamp + retry_after, _text(error, "error", 500, required=False), delivery_id),
                )
            return self._delivery_dict(connection.execute(
                "SELECT * FROM task_event_deliveries WHERE delivery_id = ?", (delivery_id,)
            ).fetchone())

    def list_task_event_deliveries(
        self,
        *,
        task_id: str | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if limit < 1 or limit > 500:
            raise RegistryError("limit 必须在 1 到 500 之间")
        if status is not None:
            status = _text(status, "status")
            if status not in DELIVERY_STATUS_VALUES:
                raise RegistryError(f"delivery status 必须是 {sorted(DELIVERY_STATUS_VALUES)} 之一")
        with self._connect() as connection:
            clauses: list[str] = []
            parameters: list[object] = []
            if task_id:
                clauses.append("task_id = ?")
                parameters.append(_identifier(task_id, "task_id"))
            if status:
                clauses.append("status = ?")
                parameters.append(status)
            where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
            parameters.append(limit)
            rows = connection.execute(
                "SELECT * FROM task_event_deliveries" + where + " ORDER BY delivery_id LIMIT ?", parameters
            )
            return [self._delivery_dict(row) for row in rows]

    def create_group(self, name: str, creator_reference: str, *, group_id: str | None = None, feishu_chat_id: str = "") -> dict[str, Any]:
        name = _text(name, "group name", 160)
        gid = _identifier(group_id or f"group-{secrets.token_hex(6)}", "group_id")
        chat_id = _text(feishu_chat_id, "feishu_chat_id", 160, required=False)
        timestamp = now()
        with self._connect() as connection:
            creator = self._user_row(connection, creator_reference)
            if creator["status"] != "approved":
                raise RegistryError("群组创建者尚未 approved")
            try:
                connection.execute(
                    "INSERT INTO groups_(group_id, feishu_chat_id, name, created_by, created_at) VALUES (?, ?, ?, ?, ?)",
                    (gid, chat_id or None, name, creator["user_id"], timestamp),
                )
                connection.execute(
                    "INSERT INTO group_members(group_id, user_id, role, created_at) VALUES (?, ?, 'owner', ?)",
                    (gid, creator["user_id"], timestamp),
                )
            except sqlite3.IntegrityError as exc:
                raise RegistryError("group_id 或 feishu_chat_id 已存在") from exc
            return dict(connection.execute("SELECT * FROM groups_ WHERE group_id = ?", (gid,)).fetchone())

    def add_group_member(self, group_reference: str, user_reference: str, *, role: str = "member") -> dict[str, Any]:
        role = _text(role, "group role")
        if role not in {"owner", "member"}:
            raise RegistryError("群组 role 必须是 owner 或 member")
        timestamp = now()
        with self._connect() as connection:
            group = self._group_row(connection, group_reference)
            user = self._user_row(connection, user_reference)
            if user["status"] != "approved":
                raise RegistryError("用户尚未 approved")
            connection.execute(
                "INSERT INTO group_members(group_id, user_id, role, created_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(group_id, user_id) DO UPDATE SET role = excluded.role",
                (group["group_id"], user["user_id"], role, timestamp),
            )
            self._share_user_sessions_with_group(
                connection,
                str(group["group_id"]),
                str(user["user_id"]),
                timestamp,
            )
            return dict(connection.execute(
                "SELECT gm.group_id, gm.user_id, gm.role, u.feishu_open_id, u.display_name "
                "FROM group_members gm JOIN users u ON u.user_id = gm.user_id "
                "WHERE gm.group_id = ? AND gm.user_id = ?",
                (group["group_id"], user["user_id"]),
            ).fetchone())

    def ensure_group_member(
        self,
        group_reference: str,
        feishu_open_id: str,
        *,
        display_name: str = "",
    ) -> dict[str, Any]:
        """Enroll a sender from an already-registered Feishu group.

        Feishu has already established group membership when it delivers a
        group event.  Keep the registry as the source of shared-session
        authorization while avoiding a second, manually maintained member
        allowlist for that registered group.  Explicitly disabled users stay
        denied.
        """

        open_id = _text(feishu_open_id, "feishu_open_id", 160)
        name = _text(display_name, "display_name", 120, required=False)
        if not name:
            name = f"Feishu 成员 {open_id[-8:]}"
        timestamp = now()
        with self._connect() as connection:
            group = self._group_row(connection, group_reference)
            user_id = f"user-feishu-{hashlib.sha256(open_id.encode('utf-8')).hexdigest()[:24]}"
            connection.execute(
                "INSERT OR IGNORE INTO users(user_id, feishu_open_id, display_name, role, status, created_at, updated_at) "
                "VALUES (?, ?, ?, 'member', 'approved', ?, ?)",
                (user_id, open_id, name, timestamp, timestamp),
            )
            user = self._user_row(connection, open_id)
            if user["status"] == "disabled":
                raise AuthorizationDenied("用户已被禁用")
            if user["status"] != "approved":
                connection.execute(
                    "UPDATE users SET status = 'approved', updated_at = ? WHERE user_id = ?",
                    (timestamp, user["user_id"]),
                )
            connection.execute(
                "INSERT INTO group_members(group_id, user_id, role, created_at) VALUES (?, ?, 'member', ?) "
                "ON CONFLICT(group_id, user_id) DO NOTHING",
                (group["group_id"], user["user_id"], timestamp),
            )
            self._share_user_sessions_with_group(
                connection,
                str(group["group_id"]),
                str(user["user_id"]),
                timestamp,
            )
            return dict(connection.execute(
                "SELECT gm.group_id, gm.user_id, gm.role, u.feishu_open_id, u.display_name "
                "FROM group_members gm JOIN users u ON u.user_id = gm.user_id "
                "WHERE gm.group_id = ? AND gm.user_id = ?",
                (group["group_id"], user["user_id"]),
            ).fetchone())

    def share_session(self, group_reference: str, session_id: str, *, access: str = "write") -> dict[str, Any]:
        access = _text(access, "access")
        if access not in ACCESS_VALUES:
            raise RegistryError("access 必须是 read 或 write")
        sid = _text(session_id, "session_id", 80).lower()
        timestamp = now()
        with self._connect() as connection:
            group = self._group_row(connection, group_reference)
            session = connection.execute(
                "SELECT s.*, i.user_id AS owner_user_id FROM sessions s "
                "JOIN installations i ON i.installation_id = s.installation_id WHERE s.session_id = ?",
                (sid,),
            ).fetchone()
            if session is None:
                raise RegistryError(f"找不到 session: {sid}")
            owner_member = connection.execute(
                "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?",
                (group["group_id"], session["owner_user_id"]),
            ).fetchone()
            if owner_member is None:
                raise RegistryError("先把 session 所有者加入群组，再共享 session")
            connection.execute(
                "INSERT INTO session_shares(group_id, session_id, access, created_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(group_id, session_id) DO UPDATE SET access = excluded.access",
                (group["group_id"], sid, access, timestamp),
            )
            return dict(connection.execute(
                "SELECT ss.group_id, ss.session_id, ss.access, s.label, i.user_id AS owner_user_id "
                "FROM session_shares ss JOIN sessions s ON s.session_id = ss.session_id "
                "JOIN installations i ON i.installation_id = s.installation_id "
                "WHERE ss.group_id = ? AND ss.session_id = ?",
                (group["group_id"], sid),
            ).fetchone())

    def add_session_to_group(
        self,
        group_reference: str,
        actor_reference: str,
        session_id: str,
        *,
        access: str = "write",
        slot_alias: str | None = None,
    ) -> dict[str, Any]:
        """Import an owned Session and assign an owner-scoped command alias."""

        access = _text(access, "access")
        if access not in ACCESS_VALUES:
            raise RegistryError("access 必须是 read 或 write")
        sid = _text(session_id, "session_id", 80).lower()
        if not SESSION_ID.fullmatch(sid):
            raise RegistryError("session_id 必须是 Codex UUID")
        requested_slot = _group_slot(slot_alias) if slot_alias else ""
        timestamp = now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            group = self._group_row(connection, group_reference)
            actor = self._user_row(connection, actor_reference)
            if actor["status"] != "approved":
                raise AuthorizationDenied("用户未获批准")
            membership = connection.execute(
                "SELECT role FROM group_members WHERE group_id = ? AND user_id = ?",
                (group["group_id"], actor["user_id"]),
            ).fetchone()
            if membership is None:
                raise AuthorizationDenied("用户不是该群组成员")
            session = connection.execute(
                "SELECT s.*, i.user_id AS owner_user_id, u.display_name AS owner_name "
                "FROM sessions s JOIN installations i ON i.installation_id = s.installation_id "
                "JOIN users u ON u.user_id = i.user_id WHERE s.session_id = ?",
                (sid,),
            ).fetchone()
            if session is None:
                raise RegistryError(f"找不到 session: {sid}")
            owner_member = connection.execute(
                "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?",
                (group["group_id"], session["owner_user_id"]),
            ).fetchone()
            if owner_member is None:
                raise RegistryError("session 所有者不是该群组成员")
            can_import_other = (
                str(membership["role"]) == "owner"
                or str(actor["role"]) in {"owner", "admin"}
            )
            if str(session["owner_user_id"]) != str(actor["user_id"]) and not can_import_other:
                raise AuthorizationDenied("只能导入自己拥有的 Session")
            if (
                requested_slot
                and requested_slot.startswith("q")
                and requested_slot[1:].isdigit()
                and str(session["owner_user_id"]) != str(group["created_by"])
            ):
                raise RegistryError("其他用户的 Session 不能使用 qN 编号，请使用姓名或自定义字母别名")

            existing = connection.execute(
                "SELECT ss.access, sl.slot FROM session_shares ss "
                "LEFT JOIN session_slots sl ON sl.group_id = ss.group_id AND sl.session_id = ss.session_id "
                "WHERE ss.group_id = ? AND ss.session_id = ?",
                (group["group_id"], sid),
            ).fetchone()
            slot = str(existing["slot"] or "").casefold() if existing is not None else ""
            if not slot:
                used_slots = {
                    str(row[0]).casefold()
                    for row in connection.execute(
                        "SELECT slot FROM session_slots WHERE group_id = ?",
                        (group["group_id"],),
                    )
                }
                if requested_slot:
                    if requested_slot in used_slots:
                        raise RegistryError(f"槽位 /{requested_slot} 已被其他 Session 占用")
                    slot = requested_slot
                else:
                    prefix = _owner_slot_prefix(
                        str(session["owner_user_id"]),
                        str(session["owner_name"]),
                        str(group["created_by"]),
                    )
                    if prefix == "q":
                        number = 3
                        while f"q{number}" in used_slots:
                            number += 1
                        slot = _group_slot(f"q{number}")
                    else:
                        slot = prefix
                        suffix = 2
                        while slot in used_slots:
                            slot = _group_slot(f"{prefix}{suffix}")
                            suffix += 1
                connection.execute(
                    "INSERT INTO session_slots(group_id, slot, session_id, assigned_by, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (group["group_id"], slot, sid, actor["user_id"], timestamp),
                )
            connection.execute(
                "INSERT INTO session_shares(group_id, session_id, access, created_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(group_id, session_id) DO UPDATE SET access = excluded.access",
                (group["group_id"], sid, access, timestamp),
            )
            self._audit(
                connection,
                str(actor["feishu_open_id"]),
                "add_session_to_group",
                "session",
                sid,
                f"group={group['group_id']};slot={slot};access={access}",
            )
            return {
                "group_id": group["group_id"],
                "session_id": sid,
                "slot": slot,
                "access": access,
                "label": session["label"],
                "status": session["status"],
                "owner_user_id": session["owner_user_id"],
                "owner_name": session["owner_name"],
                "existing": existing is not None,
            }

    def unshare_session(self, group_reference: str, session_id: str) -> dict[str, Any]:
        """Remove a session from a group whitelist and its notifications.

        Subscriptions are intentionally removed together with the share.  A
        later re-share must be an explicit user action instead of silently
        restoring an old notification route.
        """

        sid = _text(session_id, "session_id", 80).lower()
        with self._connect() as connection:
            group = self._group_row(connection, group_reference)
            shared = connection.execute(
                "SELECT access FROM session_shares WHERE group_id = ? AND session_id = ?",
                (group["group_id"], sid),
            ).fetchone()
            if shared is None:
                raise RegistryError("session 尚未共享到该群组")
            removed_subscriptions = connection.execute(
                "DELETE FROM subscriptions WHERE group_id = ? AND session_id = ?",
                (group["group_id"], sid),
            ).rowcount
            connection.execute(
                "DELETE FROM session_slots WHERE group_id = ? AND session_id = ?",
                (group["group_id"], sid),
            )
            connection.execute(
                "DELETE FROM session_shares WHERE group_id = ? AND session_id = ?",
                (group["group_id"], sid),
            )
            return {
                "group_id": group["group_id"],
                "session_id": sid,
                "previous_access": shared["access"],
                "removed_subscriptions": max(0, int(removed_subscriptions)),
                "unshared": True,
            }

    def subscribe(self, group_reference: str, user_reference: str, session_id: str | None = None) -> dict[str, Any]:
        sid = _text(session_id, "session_id", 80).lower() if session_id else None
        timestamp = now()
        with self._connect() as connection:
            group = self._group_row(connection, group_reference)
            user = self._user_row(connection, user_reference)
            member = connection.execute(
                "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?",
                (group["group_id"], user["user_id"]),
            ).fetchone()
            if member is None:
                raise AuthorizationDenied("用户不是该群组成员")
            if sid:
                shared = connection.execute(
                    "SELECT 1 FROM session_shares WHERE group_id = ? AND session_id = ?",
                    (group["group_id"], sid),
                ).fetchone()
                if shared is None:
                    raise RegistryError("只能订阅本群已共享的 session")
            connection.execute(
                "INSERT OR IGNORE INTO subscriptions(group_id, user_id, session_id, created_at) VALUES (?, ?, ?, ?)",
                (group["group_id"], user["user_id"], sid, timestamp),
            )
            return {
                "group_id": group["group_id"],
                "user_id": user["user_id"],
                "session_id": sid,
            }

    def authorize(self, open_id: str, chat_id: str | None, session_id: str, action: str = "write") -> dict[str, Any]:
        """Authorize one ingress event without inferring ownership.

        Private chat: only the session owner can read/write their own session.
        Group chat: the user must be a member and the session must be explicitly
        shared with sufficient access.  A group member never gains access to an
        unshared session merely because its owner is in the group.
        """

        action = _text(action, "action")
        required = "read" if action in {"read", "notify"} else "write"
        sid = _text(session_id, "session_id", 80).lower()
        chat = str(chat_id or "").strip()
        with self._connect() as connection:
            user = self._user_row(connection, open_id)
            if user["status"] != "approved":
                raise AuthorizationDenied("用户未获批准")
            session = connection.execute(
                "SELECT s.session_id, s.label, s.status, i.user_id AS owner_user_id "
                "FROM sessions s JOIN installations i ON i.installation_id = s.installation_id "
                "WHERE s.session_id = ?",
                (sid,),
            ).fetchone()
            if session is None:
                raise AuthorizationDenied("session 不存在")
            if not chat:
                if session["owner_user_id"] != user["user_id"]:
                    raise AuthorizationDenied("私聊只能访问自己的 session")
                return {"allowed": True, "scope": "private", "session_id": sid, "label": session["label"]}
            group = self._group_row(connection, chat)
            member = connection.execute(
                "SELECT role FROM group_members WHERE group_id = ? AND user_id = ?",
                (group["group_id"], user["user_id"]),
            ).fetchone()
            share = connection.execute(
                "SELECT access FROM session_shares WHERE group_id = ? AND session_id = ?",
                (group["group_id"], sid),
            ).fetchone()
            if member is None or share is None:
                raise AuthorizationDenied("群组成员或 session 共享关系不存在")
            if required == "write" and share["access"] != "write":
                raise AuthorizationDenied("该 session 只读")
            return {
                "allowed": True,
                "scope": "group",
                "group_id": group["group_id"],
                "session_id": sid,
                "label": session["label"],
                "access": share["access"],
            }

    def notification_recipients(self, group_reference: str, session_id: str) -> list[str]:
        sid = _text(session_id, "session_id", 80).lower()
        with self._connect() as connection:
            group = self._group_row(connection, group_reference)
            shared = connection.execute(
                "SELECT 1 FROM session_shares WHERE group_id = ? AND session_id = ?",
                (group["group_id"], sid),
            ).fetchone()
            if shared is None:
                return []
            rows = connection.execute(
                "SELECT DISTINCT u.feishu_open_id FROM subscriptions sub "
                "JOIN users u ON u.user_id = sub.user_id "
                "WHERE sub.group_id = ? AND (sub.session_id = ? OR sub.session_id IS NULL) "
                "AND u.status = 'approved' ORDER BY u.feishu_open_id",
                (group["group_id"], sid),
            )
            return [str(row[0]) for row in rows]

    def claim_command(
        self,
        message_id: str,
        open_id: str,
        chat_id: str | None,
        session_id: str,
        *,
        action: str = "write",
        lease_seconds: int = 120,
        task_id: str | None = None,
    ) -> bool:
        message_id = _text(message_id, "message_id", 160)
        if task_id:
            decision = self.authorize_task(open_id, chat_id, task_id, session_id, action)
            task_reference = str(decision["task_id"])
        else:
            decision = self.authorize(open_id, chat_id, session_id, action)
            task_reference = None
        timestamp = now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute("SELECT status, lease_until FROM commands WHERE message_id = ?", (message_id,)).fetchone()
            if existing is not None:
                if existing["status"] in {"completed", "failed"} or int(existing["lease_until"] or 0) >= timestamp:
                    connection.rollback()
                    return False
                connection.execute("DELETE FROM commands WHERE message_id = ?", (message_id,))
            connection.execute(
                "INSERT INTO commands(message_id, open_id, chat_id, session_id, task_id, action, status, lease_until, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, 'claimed', ?, ?, ?)",
                (
                    message_id,
                    _text(open_id, "open_id", 160),
                    str(chat_id or "")[:160],
                    decision["session_id"],
                    task_reference,
                    action,
                    timestamp + max(1, lease_seconds),
                    timestamp,
                    timestamp,
                ),
            )
            self._audit(connection, open_id, "claim_command", "message", message_id, session_id)
            if task_reference:
                self._append_task_event_in_connection(
                    connection,
                    task_reference,
                    "command.claimed",
                    {"message_id": message_id, "chat_id": str(chat_id or ""), "action": action},
                    session_id=str(decision["session_id"]),
                    actor_open_id=open_id,
                    idempotency_key=f"command:{message_id}:claimed",
                    timestamp=timestamp,
                )
            connection.commit()
            return True

    def complete_command(self, message_id: str, status: str = "completed") -> dict[str, Any]:
        status = _text(status, "status")
        if status not in COMMAND_STATUS_VALUES:
            raise RegistryError(f"command status 必须是 {sorted(COMMAND_STATUS_VALUES)} 之一")
        with self._connect() as connection:
            timestamp = now()
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("UPDATE commands SET status = ?, lease_until = 0, updated_at = ? WHERE message_id = ?", (status, timestamp, message_id))
            row = connection.execute("SELECT * FROM commands WHERE message_id = ?", (message_id,)).fetchone()
            if row is None:
                connection.rollback()
                raise RegistryError("找不到 message_id")
            if row["task_id"]:
                event_type = "command.completed" if status == "completed" else "command.failed"
                self._append_task_event_in_connection(
                    connection,
                    str(row["task_id"]),
                    event_type,
                    {"message_id": message_id, "status": status},
                    session_id=str(row["session_id"]),
                    actor_open_id=str(row["open_id"]),
                    idempotency_key=f"command:{message_id}:{status}",
                    timestamp=timestamp,
                )
            connection.commit()
            return dict(row)

    def create_pairing(self, user_reference: str, installation_id: str | None = None, ttl: int = 600) -> str:
        if ttl < 30 or ttl > 86400:
            raise RegistryError("pairing TTL 必须在 30 到 86400 秒之间")
        code = secrets.token_urlsafe(9).replace("-", "A").replace("_", "B")[:12].upper()
        timestamp = now()
        with self._connect() as connection:
            user = self._user_row(connection, user_reference)
            if user["status"] != "approved":
                raise RegistryError("用户尚未 approved")
            if installation_id:
                iid = _identifier(installation_id, "installation_id")
                owned = connection.execute(
                    "SELECT 1 FROM installations WHERE installation_id = ? AND user_id = ?",
                    (iid, user["user_id"]),
                ).fetchone()
                if owned is None:
                    raise RegistryError("安装实例不属于该用户")
            else:
                iid = None
            connection.execute("DELETE FROM pairing_codes WHERE expires_at < ? OR consumed_at IS NOT NULL", (timestamp,))
            connection.execute(
                "INSERT INTO pairing_codes(code_hash, user_id, installation_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
                (hashlib.sha256(code.encode("ascii")).hexdigest(), user["user_id"], iid, timestamp + ttl, timestamp),
            )
        return code

    def consume_pairing(self, code: str) -> dict[str, Any]:
        normalized = _text(code, "pairing code", 64).upper()
        timestamp = now()
        digest = hashlib.sha256(normalized.encode("ascii", errors="ignore")).hexdigest()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM pairing_codes WHERE code_hash = ? AND consumed_at IS NULL AND expires_at >= ?",
                (digest, timestamp),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise RegistryError("配对码不正确、已使用或已过期")
            connection.execute("UPDATE pairing_codes SET consumed_at = ? WHERE code_hash = ?", (timestamp, digest))
            connection.commit()
            return {
                "user_id": row["user_id"],
                "installation_id": row["installation_id"],
                "expires_at": row["expires_at"],
            }

    def group_dashboard(self, group_reference: str, user_reference: str | None = None) -> dict[str, Any]:
        with self._connect() as connection:
            group = self._group_row(connection, group_reference)
            if user_reference:
                user = self._user_row(connection, user_reference)
                if user["status"] != "approved":
                    raise AuthorizationDenied("用户未获批准")
                member = connection.execute(
                    "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?",
                    (group["group_id"], user["user_id"]),
                ).fetchone()
                if member is None:
                    raise AuthorizationDenied("用户不是该群组成员")
            members = _rows(connection.execute(
                "SELECT u.user_id, u.feishu_open_id, u.display_name, gm.role FROM group_members gm "
                "JOIN users u ON u.user_id = gm.user_id WHERE gm.group_id = ? ORDER BY gm.created_at, u.user_id",
                (group["group_id"],),
            ))
            sessions = _rows(connection.execute(
                "SELECT ss.session_id, ss.access, sl.slot, s.label, s.workspace, s.status, "
                "i.installation_id, i.name AS installation_name, i.hostname, "
                "i.user_id AS owner_user_id, "
                "u.display_name AS owner_name FROM session_shares ss "
                "JOIN sessions s ON s.session_id = ss.session_id "
                "JOIN installations i ON i.installation_id = s.installation_id "
                "JOIN users u ON u.user_id = i.user_id "
                "LEFT JOIN session_slots sl ON sl.group_id = ss.group_id AND sl.session_id = ss.session_id "
                "WHERE ss.group_id = ? "
                "ORDER BY s.created_at, s.session_id",
                (group["group_id"],),
            ))
            return {
                "group": dict(group),
                "members": members,
                "sessions": sessions,
            }

    def group_tasks(self, group_reference: str, user_reference: str | None = None) -> dict[str, Any]:
        with self._connect() as connection:
            group = self._group_row(connection, group_reference)
            if user_reference:
                user = self._user_row(connection, user_reference)
                if user["status"] != "approved":
                    raise AuthorizationDenied("用户未获批准")
                member = connection.execute(
                    "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?",
                    (group["group_id"], user["user_id"]),
                ).fetchone()
                if member is None:
                    raise AuthorizationDenied("用户不是该群组成员")
            tasks = _rows(connection.execute(
                "SELECT t.task_id, t.name, t.status, t.updated_at, tg.access, "
                "(SELECT COUNT(*) FROM task_sessions ts WHERE ts.task_id = t.task_id) AS session_count "
                "FROM task_groups tg JOIN tasks t ON t.task_id = tg.task_id "
                "WHERE tg.group_id = ? ORDER BY t.updated_at DESC, t.task_id",
                (group["group_id"],),
            ))
            for task in tasks:
                task["sessions"] = _rows(connection.execute(
                    "SELECT ts.session_id, ts.relation, s.label, s.workspace, s.status, ss.access, "
                    "i.installation_id, i.name AS installation_name, i.hostname "
                    "FROM task_sessions ts JOIN sessions s ON s.session_id = ts.session_id "
                    "JOIN installations i ON i.installation_id = s.installation_id "
                    "JOIN session_shares ss ON ss.session_id = ts.session_id AND ss.group_id = ? "
                    "WHERE ts.task_id = ? ORDER BY ts.created_at, ts.session_id",
                    (group["group_id"], task["task_id"]),
                ))
            return {"group": dict(group), "tasks": tasks}

    def dump(self) -> dict[str, Any]:
        with self._connect() as connection:
            result: dict[str, Any] = {}
            for table in (
                "users",
                "installations",
                "sessions",
                "groups_",
                "group_members",
                "session_shares",
                "session_slots",
                "subscriptions",
                "tasks",
                "task_sessions",
                "task_groups",
                "task_events",
                "task_event_deliveries",
            ):
                result[table.rstrip("_")] = _rows(connection.execute(f"SELECT * FROM {table} ORDER BY rowid"))
            return result


def _print(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def _json_arg(value: str, field: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise RegistryError(f"{field} 不是有效 JSON") from exc
    if not isinstance(parsed, dict):
        raise RegistryError(f"{field} 必须是 JSON 对象")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="TLS qyp 多人模式控制面")
    parser.add_argument("--db", type=Path, default=None, help="SQLite 注册表路径")
    parser.add_argument("--json", action="store_true", help="保留兼容参数，输出 JSON")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init")
    p = sub.add_parser("add-user")
    p.add_argument("--open-id", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--user-id")
    p.add_argument("--role", default="member")
    p.add_argument("--status", default="pending")
    p = sub.add_parser("approve")
    p.add_argument("user")
    p = sub.add_parser("add-installation")
    p.add_argument("--user", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--id")
    p.add_argument("--hostname", default="")
    p = sub.add_parser("add-session")
    p.add_argument("--installation", required=True)
    p.add_argument("--session-id", required=True)
    p.add_argument("--label", default="")
    p.add_argument("--workspace", default="")
    p.add_argument("--status", default="unknown")
    p = sub.add_parser("create-group")
    p.add_argument("--name", required=True)
    p.add_argument("--creator", required=True)
    p.add_argument("--id")
    p.add_argument("--chat-id", default="")
    p = sub.add_parser("add-member")
    p.add_argument("--group", required=True)
    p.add_argument("--user", required=True)
    p.add_argument("--role", default="member")
    p = sub.add_parser("share-session")
    p.add_argument("--group", required=True)
    p.add_argument("--session", required=True)
    p.add_argument("--access", default="write")
    p = sub.add_parser("unshare-session")
    p.add_argument("--group", required=True)
    p.add_argument("--session", required=True)
    p = sub.add_parser("subscribe")
    p.add_argument("--group", required=True)
    p.add_argument("--user", required=True)
    p.add_argument("--session")
    p = sub.add_parser("authorize")
    p.add_argument("--open-id", required=True)
    p.add_argument("--chat-id", default="")
    p.add_argument("--session", required=True)
    p.add_argument("--action", default="write")
    p = sub.add_parser("dashboard")
    p.add_argument("--group", required=True)
    p.add_argument("--user")
    p = sub.add_parser("pair")
    p.add_argument("--user", required=True)
    p.add_argument("--installation")
    p.add_argument("--ttl", type=int, default=600)
    p = sub.add_parser("consume-pair")
    p.add_argument("code")
    p = sub.add_parser("claim")
    p.add_argument("--message-id", required=True)
    p.add_argument("--open-id", required=True)
    p.add_argument("--chat-id", default="")
    p.add_argument("--session", required=True)
    p.add_argument("--action", default="write")
    p.add_argument("--task")
    p = sub.add_parser("complete")
    p.add_argument("message_id")
    p.add_argument("--status", default="completed")
    p = sub.add_parser("create-task")
    p.add_argument("--owner", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--contract", required=True, help="JSON 对象")
    p.add_argument("--id")
    p.add_argument("--status", default="planned")
    p = sub.add_parser("update-task")
    p.add_argument("task")
    p.add_argument("--name")
    p.add_argument("--contract", help="JSON 对象")
    p.add_argument("--status")
    p = sub.add_parser("attach-task-session")
    p.add_argument("--task", required=True)
    p.add_argument("--session", required=True)
    p.add_argument("--relation", default="worker")
    p = sub.add_parser("detach-task-session")
    p.add_argument("--task", required=True)
    p.add_argument("--session", required=True)
    p = sub.add_parser("emit-event")
    p.add_argument("--task", required=True)
    p.add_argument("--type", required=True)
    p.add_argument("--payload", required=True, help="JSON 对象")
    p.add_argument("--session")
    p.add_argument("--actor-open-id", default="")
    p.add_argument("--idempotency-key")
    p = sub.add_parser("list-tasks")
    p.add_argument("--owner")
    p.add_argument("--status")
    p = sub.add_parser("list-task-events")
    p.add_argument("--task", required=True)
    p.add_argument("--session")
    p.add_argument("--type")
    p.add_argument("--after-event-id", type=int)
    p.add_argument("--limit", type=int, default=100)
    p = sub.add_parser("share-task")
    p.add_argument("--group", required=True)
    p.add_argument("--task", required=True)
    p.add_argument("--access", default="read")
    p = sub.add_parser("unshare-task")
    p.add_argument("--group", required=True)
    p.add_argument("--task", required=True)
    p = sub.add_parser("list-deliveries")
    p.add_argument("--task")
    p.add_argument("--status")
    p.add_argument("--limit", type=int, default=100)
    p = sub.add_parser("claim-delivery")
    p.add_argument("delivery_id", type=int)
    p.add_argument("--lease", type=int, default=120)
    p = sub.add_parser("complete-delivery")
    p.add_argument("delivery_id", type=int)
    p.add_argument("--status", default="sent")
    p.add_argument("--error", default="")
    p.add_argument("--retry-after", type=int, default=60)
    p = sub.add_parser("list-users")
    sub.add_parser("list-sessions").add_argument("--user")
    sub.add_parser("dump")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    registry = Registry(args.db)
    try:
        command = args.command
        if command == "init":
            result = registry.init()
        elif command == "add-user":
            result = registry.add_user(args.open_id, args.name, user_id=args.user_id, role=args.role, status=args.status)
        elif command == "approve":
            result = registry.set_user_status(args.user, "approved")
        elif command == "add-installation":
            result = registry.add_installation(args.user, args.name, installation_id=args.id, hostname=args.hostname)
        elif command == "add-session":
            result = registry.add_session(args.installation, args.session_id, args.label, workspace=args.workspace, status=args.status)
        elif command == "create-group":
            result = registry.create_group(args.name, args.creator, group_id=args.id, feishu_chat_id=args.chat_id)
        elif command == "add-member":
            result = registry.add_group_member(args.group, args.user, role=args.role)
        elif command == "share-session":
            result = registry.share_session(args.group, args.session, access=args.access)
        elif command == "unshare-session":
            result = registry.unshare_session(args.group, args.session)
        elif command == "subscribe":
            result = registry.subscribe(args.group, args.user, args.session)
        elif command == "authorize":
            result = registry.authorize(args.open_id, args.chat_id, args.session, args.action)
        elif command == "dashboard":
            result = registry.group_dashboard(args.group, args.user)
        elif command == "pair":
            result = {"code": registry.create_pairing(args.user, args.installation, args.ttl)}
        elif command == "consume-pair":
            result = registry.consume_pairing(args.code)
        elif command == "claim":
            result = {
                "claimed": registry.claim_command(
                    args.message_id,
                    args.open_id,
                    args.chat_id,
                    args.session,
                    action=args.action,
                    task_id=args.task,
                )
            }
        elif command == "complete":
            result = registry.complete_command(args.message_id, args.status)
        elif command == "create-task":
            result = registry.create_task(
                args.owner,
                args.name,
                _json_arg(args.contract, "contract"),
                task_id=args.id,
                status=args.status,
            )
        elif command == "update-task":
            result = registry.update_task(
                args.task,
                name=args.name,
                contract=_json_arg(args.contract, "contract") if args.contract else None,
                status=args.status,
            )
        elif command == "attach-task-session":
            result = registry.attach_task_session(args.task, args.session, relation=args.relation)
        elif command == "detach-task-session":
            result = registry.detach_task_session(args.task, args.session)
        elif command == "emit-event":
            result = registry.append_task_event(
                args.task,
                args.type,
                _json_arg(args.payload, "payload"),
                session_id=args.session,
                actor_open_id=args.actor_open_id,
                idempotency_key=args.idempotency_key,
            )
        elif command == "list-tasks":
            result = registry.list_tasks(args.owner, status=args.status)
        elif command == "list-task-events":
            result = registry.list_task_events(
                args.task,
                session_id=args.session,
                event_type=args.type,
                after_event_id=args.after_event_id,
                limit=args.limit,
            )
        elif command == "share-task":
            result = registry.share_task(args.group, args.task, access=args.access)
        elif command == "unshare-task":
            result = registry.unshare_task(args.group, args.task)
        elif command == "list-deliveries":
            result = registry.list_task_event_deliveries(task_id=args.task, status=args.status, limit=args.limit)
        elif command == "claim-delivery":
            result = registry.claim_task_event_delivery(args.delivery_id, lease_seconds=args.lease)
        elif command == "complete-delivery":
            result = registry.complete_task_event_delivery(
                args.delivery_id,
                status=args.status,
                error=args.error,
                retry_after=args.retry_after,
            )
        elif command == "list-users":
            result = registry.list_users()
        elif command == "list-sessions":
            result = registry.list_sessions(args.user)
        elif command == "dump":
            result = registry.dump()
        else:
            raise RegistryError(f"未知命令: {command}")
        _print(result)
        return 0
    except (RegistryError, sqlite3.Error) as error:
        print(f"qyp-tls-multi: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
