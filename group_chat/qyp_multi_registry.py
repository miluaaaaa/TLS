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


DEFAULT_DB = Path.home() / ".local/state/tls-group-chat/multi.sqlite3"
SCHEMA_VERSION = 8
SESSION_ID = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$", re.IGNORECASE)
IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:-]{1,160}$")
GROUP_SLOT = re.compile(r"^[a-z]{1,2}$", re.IGNORECASE)
RESERVED_GROUP_SLOTS = {"ad"}
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
ROLE_SCOPE_VALUES = {"global", "group", "task"}
ASSIGNMENT_STATUS_VALUES = {
    "proposed",
    "assigned",
    "accepted",
    "active",
    "completed",
    "declined",
    "cancelled",
}
AGENT_RUN_STATUS_VALUES = {
    "created",
    "queued",
    "running",
    "waiting",
    "completed",
    "failed",
    "cancelled",
    "stale",
}
EVIDENCE_STATUS_VALUES = {"unverified", "verified", "rejected"}
TASK_PROGRESS_EVENT_WEIGHTS = {
    "task.started": 20,
    "command.claimed": 20,
    "command.completed": 75,
    "task.completed": 75,
    "file.changed": 50,
    "artifact.recorded": 50,
    "test.finished": 75,
    "evidence.attached": 75,
    "evidence.verified": 90,
}
HANDOFF_STATUS_VALUES = {"draft", "ready", "accepted", "superseded"}
AGENT_CHANNEL_STATUS_VALUES = {"requested", "active", "revoked", "expired"}
AGENT_CHANNEL_MESSAGE_STATUS_VALUES = {"queued", "claimed", "acknowledged", "rejected"}
CHANNEL_CAPABILITY_VALUES = {"agent.message", "task.read", "evidence.read", "handoff.write"}
CHANNEL_SECRET_MARKERS = (
    "-----begin",
    "private_key",
    "ssh -i",
    "ssh://",
    "known_hosts",
    "identityfile",
    "authorization: bearer",
    "password=",
    "token=",
    "secret=",
    "api_key=",
)
DEFAULT_ROLE_DEFINITIONS = (
    (
        "owner",
        "Owner",
        "Task owner and contract authority",
        {
            "task.create": True,
            "task.assign": True,
            "agent.channel.create": True,
            "agent.channel.approve": True,
            "agent.channel.read": True,
            "agent.channel.message": True,
        },
    ),
    (
        "admin",
        "Admin",
        "Control-plane administrator",
        {
            "task.assign": True,
            "task.intervene": True,
            "agent.channel.create": True,
            "agent.channel.approve": True,
            "agent.channel.read": True,
            "agent.channel.message": True,
        },
    ),
    ("member", "Member", "Approved platform member", {"task.read": True, "agent.channel.read": True}),
    (
        "implementer",
        "Implementer",
        "Owns an assigned execution slice",
        {"task.write": True, "agent.channel.request": True, "agent.channel.message": True, "agent.channel.read": True},
    ),
    (
        "tester",
        "Tester",
        "Produces verification evidence",
        {"evidence.write": True, "agent.channel.request": True, "agent.channel.message": True, "agent.channel.read": True},
    ),
    (
        "reviewer",
        "Reviewer",
        "Reviews evidence and handoffs",
        {"evidence.verify": True, "agent.channel.approve": True, "agent.channel.read": True},
    ),
    ("observer", "Observer", "Read-only task participant", {"task.read": True, "agent.channel.read": True}),
)


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
    private_only INTEGER NOT NULL DEFAULT 0 CHECK (private_only IN (0, 1)),
    model TEXT NOT NULL DEFAULT 'unknown',
    effort TEXT NOT NULL DEFAULT 'unknown',
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

CREATE TABLE IF NOT EXISTS roles (
    role_id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    capabilities_json TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    role_id TEXT NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    scope_type TEXT NOT NULL CHECK (scope_type IN ('global', 'group', 'task')),
    scope_id TEXT NOT NULL DEFAULT '',
    granted_by TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, role_id, scope_type, scope_id)
);

CREATE TABLE IF NOT EXISTS task_assignments (
    assignment_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    role_id TEXT NOT NULL REFERENCES roles(role_id),
    session_id TEXT REFERENCES sessions(session_id) ON DELETE SET NULL,
    status TEXT NOT NULL CHECK (
        status IN ('proposed', 'assigned', 'accepted', 'active', 'completed', 'declined', 'cancelled')
    ),
    assigned_by TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    accepted_at INTEGER,
    completed_at INTEGER,
    UNIQUE (task_id, user_id, role_id, session_id)
);

CREATE TABLE IF NOT EXISTS task_queue_claims (
    claim_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
    group_id TEXT NOT NULL REFERENCES groups_(group_id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('active', 'submitted', 'released', 'credited')),
    evidence_id TEXT REFERENCES evidence(evidence_id) ON DELETE SET NULL,
    claimed_at INTEGER NOT NULL,
    submitted_at INTEGER,
    closed_at INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_task_one_open_claim
    ON task_queue_claims(task_id) WHERE status IN ('active', 'submitted');

CREATE TABLE IF NOT EXISTS task_credits (
    task_id TEXT PRIMARY KEY REFERENCES tasks(task_id) ON DELETE CASCADE,
    claim_id TEXT NOT NULL UNIQUE REFERENCES task_queue_claims(claim_id),
    user_id TEXT NOT NULL REFERENCES users(user_id),
    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
    approved_by TEXT NOT NULL REFERENCES users(user_id),
    awarded_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS session_history_shares (
    group_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    enabled_by TEXT NOT NULL REFERENCES users(user_id),
    enabled_at INTEGER NOT NULL,
    PRIMARY KEY (group_id, session_id),
    FOREIGN KEY (group_id, session_id) REFERENCES session_shares(group_id, session_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS agent_runs (
    run_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
    assignment_id TEXT REFERENCES task_assignments(assignment_id) ON DELETE SET NULL,
    session_id TEXT REFERENCES sessions(session_id) ON DELETE SET NULL,
    status TEXT NOT NULL CHECK (
        status IN ('created', 'queued', 'running', 'waiting', 'completed', 'failed', 'cancelled', 'stale')
    ),
    summary TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    started_at INTEGER,
    finished_at INTEGER
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
    assignment_id TEXT REFERENCES task_assignments(assignment_id) ON DELETE SET NULL,
    run_id TEXT REFERENCES agent_runs(run_id) ON DELETE SET NULL,
    session_id TEXT REFERENCES sessions(session_id) ON DELETE SET NULL,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    uri TEXT NOT NULL DEFAULT '',
    content_hash TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    verification_status TEXT NOT NULL CHECK (verification_status IN ('unverified', 'verified', 'rejected')),
    verifier_open_id TEXT NOT NULL DEFAULT '',
    verified_at INTEGER,
    created_by TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS handoffs (
    handoff_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
    from_assignment_id TEXT REFERENCES task_assignments(assignment_id) ON DELETE SET NULL,
    to_assignment_id TEXT REFERENCES task_assignments(assignment_id) ON DELETE SET NULL,
    from_run_id TEXT REFERENCES agent_runs(run_id) ON DELETE SET NULL,
    status TEXT NOT NULL CHECK (status IN ('draft', 'ready', 'accepted', 'superseded')),
    capsule_json TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    accepted_by TEXT NOT NULL DEFAULT '',
    accepted_at INTEGER
);

CREATE TABLE IF NOT EXISTS agent_channels (
    channel_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
    from_run_id TEXT NOT NULL REFERENCES agent_runs(run_id) ON DELETE CASCADE,
    to_run_id TEXT NOT NULL REFERENCES agent_runs(run_id) ON DELETE CASCADE,
    capabilities_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('requested', 'active', 'revoked', 'expired')),
    created_by TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    accepted_by TEXT NOT NULL DEFAULT '',
    accepted_at INTEGER,
    revoked_by TEXT NOT NULL DEFAULT '',
    revoked_at INTEGER
);

CREATE TABLE IF NOT EXISTS agent_channel_messages (
    message_id TEXT PRIMARY KEY,
    channel_id TEXT NOT NULL REFERENCES agent_channels(channel_id) ON DELETE CASCADE,
    sender_run_id TEXT NOT NULL REFERENCES agent_runs(run_id) ON DELETE CASCADE,
    recipient_run_id TEXT NOT NULL REFERENCES agent_runs(run_id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('queued', 'claimed', 'acknowledged', 'rejected')),
    lease_until INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    claimed_at INTEGER,
    acknowledged_at INTEGER,
    UNIQUE (channel_id, sequence)
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
CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id, scope_type, scope_id);
CREATE INDEX IF NOT EXISTS idx_assignments_task ON task_assignments(task_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_assignments_user ON task_assignments(user_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_agent_runs_task ON agent_runs(task_id, created_at);
CREATE INDEX IF NOT EXISTS idx_agent_runs_session ON agent_runs(session_id, created_at);
CREATE INDEX IF NOT EXISTS idx_evidence_task ON evidence(task_id, created_at);
CREATE INDEX IF NOT EXISTS idx_handoffs_task ON handoffs(task_id, created_at);
CREATE INDEX IF NOT EXISTS idx_agent_channels_task ON agent_channels(task_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_agent_channels_runs ON agent_channels(from_run_id, to_run_id, status);
CREATE INDEX IF NOT EXISTS idx_agent_channel_messages_ready
    ON agent_channel_messages(channel_id, recipient_run_id, status, lease_until, sequence);
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
        raise RegistryError("群组槽位必须是 1 到 2 位字母别名")
    if result in RESERVED_GROUP_SLOTS:
        raise RegistryError("ad 是系统保留槽位")
    return result


def _owner_slot_prefix(owner_user_id: str, owner_name: str) -> str:
    """Return a stable one- or two-letter alias derived from the owner name."""

    source = re.sub(r"[^a-z]+", "", str(owner_name or "").casefold())
    if source:
        prefix = source[:2]
    else:
        digest = hashlib.sha256(
            f"{owner_user_id}:{owner_name}".encode("utf-8")
        ).digest()
        prefix = "".join(chr(ord("a") + value % 26) for value in digest[:2])
    if prefix in RESERVED_GROUP_SLOTS:
        prefix = "u" + prefix[:1]
    return prefix[:2] or "u"


def _auto_group_slot(
    owner_user_id: str,
    owner_name: str,
    used_slots: set[str],
) -> str:
    """Choose the first free deterministic one- or two-letter alias."""

    alphabet = "abcdefghijklmnopqrstuvwxyz"
    prefix = _owner_slot_prefix(owner_user_id, owner_name)
    candidates: list[str] = [prefix]
    if len(prefix) == 1:
        candidates.extend(f"{prefix}{letter}" for letter in alphabet)
    else:
        candidates.extend(f"{prefix[0]}{letter}" for letter in alphabet)
    candidates.extend(letter for letter in alphabet)
    candidates.extend(
        f"{first}{second}" for first in alphabet for second in alphabet
    )
    seen: set[str] = set()
    for candidate in candidates:
        if candidate in seen or candidate in RESERVED_GROUP_SLOTS:
            continue
        seen.add(candidate)
        if candidate not in used_slots:
            return candidate
    raise RegistryError("群组可用槽位已耗尽")


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


def _channel_capabilities(value: object) -> tuple[list[str], str]:
    if not isinstance(value, list) or not value:
        raise RegistryError("channel capabilities 必须是非空字符串列表")
    normalized: list[str] = []
    for item in value:
        capability = _text(item, "channel capability", 80)
        if capability not in CHANNEL_CAPABILITY_VALUES:
            raise RegistryError(
                f"channel capability 必须是 {sorted(CHANNEL_CAPABILITY_VALUES)} 之一"
            )
        if capability in normalized:
            raise RegistryError("channel capabilities 不能重复")
        normalized.append(capability)
    return normalized, json.dumps(normalized, ensure_ascii=False, separators=(",", ":"))


def _channel_payload(value: object) -> tuple[dict[str, Any], str]:
    payload, encoded = _json_object(value, "channel payload", limit=16000)
    lowered = encoded.casefold()
    if any(marker in lowered for marker in CHANNEL_SECRET_MARKERS):
        raise RegistryError("channel payload 不得包含凭据、私钥或 SSH 认证材料")

    def scan_keys(item: object) -> bool:
        if isinstance(item, dict):
            for raw_key, child in item.items():
                key = str(raw_key).casefold().replace("-", "_")
                if key in {
                    "token",
                    "password",
                    "secret",
                    "private_key",
                    "ssh_key",
                    "identity_file",
                    "ssh_host",
                    "ssh_address",
                    "hostname",
                    "workspace",
                    "api_key",
                    "authorization",
                }:
                    return True
                if scan_keys(child):
                    return True
        elif isinstance(item, list):
            return any(scan_keys(child) for child in item)
        return False

    if scan_keys(payload):
        raise RegistryError("channel payload 不得包含凭据字段")
    return payload, encoded


class Registry:
    """SQLite-backed registry with short, explicit authorization methods."""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path is not None else _db_from_env()

    def _seed_default_roles(self, connection: sqlite3.Connection) -> None:
        timestamp = now()
        role_ids = {item[0] for item in DEFAULT_ROLE_DEFINITIONS}
        for role_id, name, description, capabilities in DEFAULT_ROLE_DEFINITIONS:
            capabilities_json = json.dumps(capabilities, ensure_ascii=False, separators=(",", ":"))
            connection.execute(
                "INSERT OR IGNORE INTO roles(role_id, name, description, capabilities_json, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    role_id,
                    name,
                    description,
                    capabilities_json,
                    timestamp,
                ),
            )
            existing = connection.execute(
                "SELECT capabilities_json FROM roles WHERE role_id = ?", (role_id,)
            ).fetchone()
            if existing is not None:
                try:
                    current_capabilities = json.loads(existing[0])
                except (TypeError, ValueError, json.JSONDecodeError):
                    current_capabilities = {}
                if isinstance(current_capabilities, dict):
                    merged = dict(capabilities)
                    merged.update(current_capabilities)
                    if merged != current_capabilities:
                        connection.execute(
                            "UPDATE roles SET capabilities_json = ? WHERE role_id = ?",
                            (json.dumps(merged, ensure_ascii=False, separators=(",", ":")), role_id),
                        )
        for row in connection.execute("SELECT user_id, role FROM users"):
            role_id = str(row["role"])
            if role_id not in role_ids:
                continue
            connection.execute(
                "INSERT OR IGNORE INTO user_roles(user_id, role_id, scope_type, scope_id, granted_by, created_at) "
                "VALUES (?, ?, 'global', '', 'migration', ?)",
                (str(row["user_id"]), role_id, timestamp),
            )

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
        if current < 6:
            session_columns = {
                str(row[1]) for row in connection.execute("PRAGMA table_info(sessions)")
            }
            if "private_only" not in session_columns:
                connection.execute(
                    "ALTER TABLE sessions ADD COLUMN private_only INTEGER NOT NULL DEFAULT 0"
                )
        if current < 7:
            session_columns = {
                str(row[1]) for row in connection.execute("PRAGMA table_info(sessions)")
            }
            if "model" not in session_columns:
                connection.execute("ALTER TABLE sessions ADD COLUMN model TEXT NOT NULL DEFAULT 'unknown'")
            if "effort" not in session_columns:
                connection.execute("ALTER TABLE sessions ADD COLUMN effort TEXT NOT NULL DEFAULT 'unknown'")
        if current < SCHEMA_VERSION:
            # New tables are created by SCHEMA above.  The explicit version
            # update keeps upgrades from v1 repeatable and observable.
            if current < 5:
                self._seed_default_roles(connection)
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
        os.chmod(self.path, 0o600)
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
            "WHERE i.user_id = ? AND s.private_only = 0",
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

    def ensure_private_user(
        self,
        feishu_open_id: str,
        *,
        display_name: str = "",
    ) -> dict[str, Any]:
        """Register a private-chat sender without granting group access."""

        open_id = _text(feishu_open_id, "feishu_open_id", 160)
        name = _text(display_name, "display_name", 120, required=False)
        if not name:
            name = f"Feishu 成员 {open_id[-8:]}"
        timestamp = now()
        user_id = f"user-feishu-{hashlib.sha256(open_id.encode('utf-8')).hexdigest()[:24]}"
        with self._connect() as connection:
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
            return dict(self._user_row(connection, open_id))

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
        share_with_groups: bool = True,
        model: str = "unknown",
        effort: str = "unknown",
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
        model = _text(model, "model", 160, required=False) or "unknown"
        effort = _text(effort, "effort", 80, required=False) or "unknown"
        timestamp = now()
        with self._connect() as connection:
            installation = connection.execute("SELECT * FROM installations WHERE installation_id = ?", (iid,)).fetchone()
            if installation is None:
                raise RegistryError(f"找不到安装实例: {iid}")
            if installation["status"] != "active":
                raise RegistryError("安装实例已停用")
            try:
                connection.execute(
                    "INSERT INTO sessions(session_id, installation_id, label, workspace, status, private_only, model, effort, created_at, last_seen_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (sid, iid, label, workspace, status, 0 if share_with_groups else 1, model, effort, timestamp, timestamp),
                )
            except sqlite3.IntegrityError as exc:
                raise RegistryError("session_id 已登记") from exc
            if share_with_groups:
                self._share_session_with_member_groups(
                    connection,
                    sid,
                    str(installation["user_id"]),
                    timestamp,
                )
            return dict(connection.execute("SELECT * FROM sessions WHERE session_id = ?", (sid,)).fetchone())

    def update_session(self, session_id: str, *, label: str | None = None, status: str | None = None, workspace: str | None = None, model: str | None = None, effort: str | None = None) -> dict[str, Any]:
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
        if model is not None:
            updates.append("model = ?")
            values.append(_text(model, "model", 160, required=False) or "unknown")
        if effort is not None:
            updates.append("effort = ?")
            values.append(_text(effort, "effort", 80, required=False) or "unknown")
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

    @staticmethod
    def _role_dict(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        try:
            result["capabilities"] = json.loads(result.pop("capabilities_json"))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RegistryError("role capabilities 数据损坏") from exc
        return result

    @staticmethod
    def _handoff_dict(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        try:
            result["capsule"] = json.loads(result.pop("capsule_json"))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RegistryError("handoff capsule 数据损坏") from exc
        return result

    def _role_row(self, connection: sqlite3.Connection, reference: str) -> sqlite3.Row:
        value = _text(reference, "role")
        row = connection.execute(
            "SELECT * FROM roles WHERE role_id = ? OR name = ?",
            (value, value),
        ).fetchone()
        if row is None:
            raise RegistryError(f"找不到 role: {value}")
        return row

    def _assignment_row(self, connection: sqlite3.Connection, assignment_id: str) -> sqlite3.Row:
        aid = _identifier(assignment_id, "assignment_id")
        row = connection.execute(
            "SELECT * FROM task_assignments WHERE assignment_id = ?",
            (aid,),
        ).fetchone()
        if row is None:
            raise RegistryError(f"找不到 task assignment: {aid}")
        return row

    def _agent_run_row(self, connection: sqlite3.Connection, run_id: str) -> sqlite3.Row:
        rid = _identifier(run_id, "run_id")
        row = connection.execute(
            "SELECT * FROM agent_runs WHERE run_id = ?",
            (rid,),
        ).fetchone()
        if row is None:
            raise RegistryError(f"找不到 agent run: {rid}")
        return row

    def _channel_row(self, connection: sqlite3.Connection, channel_id: str) -> sqlite3.Row:
        cid = _identifier(channel_id, "channel_id")
        row = connection.execute(
            "SELECT * FROM agent_channels WHERE channel_id = ?", (cid,)
        ).fetchone()
        if row is None:
            raise RegistryError(f"找不到 agent channel: {cid}")
        return row

    @staticmethod
    def _channel_dict(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        try:
            result["capabilities"] = json.loads(result.pop("capabilities_json"))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RegistryError("agent channel capabilities 数据损坏") from exc
        return result

    @staticmethod
    def _channel_message_dict(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        try:
            result["payload"] = json.loads(result.pop("payload_json"))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RegistryError("agent channel message payload 数据损坏") from exc
        return result

    def _evidence_row(self, connection: sqlite3.Connection, evidence_id: str) -> sqlite3.Row:
        eid = _identifier(evidence_id, "evidence_id")
        row = connection.execute(
            "SELECT * FROM evidence WHERE evidence_id = ?",
            (eid,),
        ).fetchone()
        if row is None:
            raise RegistryError(f"找不到 evidence: {eid}")
        return row

    def _handoff_row(self, connection: sqlite3.Connection, handoff_id: str) -> sqlite3.Row:
        hid = _identifier(handoff_id, "handoff_id")
        row = connection.execute(
            "SELECT * FROM handoffs WHERE handoff_id = ?",
            (hid,),
        ).fetchone()
        if row is None:
            raise RegistryError(f"找不到 handoff: {hid}")
        return row

    def list_roles(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM roles ORDER BY role_id")
            return [self._role_dict(row) for row in rows]

    def create_role(
        self,
        role_id: str,
        name: str,
        *,
        description: str = "",
        capabilities: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        rid = _identifier(role_id, "role_id")
        role_name = _text(name, "role name", 120)
        _, capabilities_json = _json_object(
            capabilities or {},
            "capabilities",
            allow_empty=True,
        )
        timestamp = now()
        with self._connect() as connection:
            try:
                connection.execute(
                    "INSERT INTO roles(role_id, name, description, capabilities_json, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (rid, role_name, _text(description, "description", 500, required=False), capabilities_json, timestamp),
                )
            except sqlite3.IntegrityError as exc:
                raise RegistryError("role_id 或 role name 已存在") from exc
            return self._role_dict(self._role_row(connection, rid))

    def grant_role(
        self,
        user_reference: str,
        role_reference: str,
        *,
        scope_type: str = "global",
        scope_id: str = "",
        granted_by: str = "",
    ) -> dict[str, Any]:
        scope = _text(scope_type, "scope_type")
        if scope not in ROLE_SCOPE_VALUES:
            raise RegistryError(f"scope_type 必须是 {sorted(ROLE_SCOPE_VALUES)} 之一")
        normalized_scope_id = _text(scope_id, "scope_id", 160, required=False)
        if scope == "global" and normalized_scope_id:
            raise RegistryError("global role 不应包含 scope_id")
        if scope != "global":
            normalized_scope_id = _identifier(normalized_scope_id, "scope_id")
        timestamp = now()
        with self._connect() as connection:
            user = self._user_row(connection, user_reference)
            role = self._role_row(connection, role_reference)
            if scope == "group":
                self._group_row(connection, normalized_scope_id)
            elif scope == "task":
                self._task_row(connection, normalized_scope_id)
            actor = _text(granted_by, "granted_by", 160, required=False)
            connection.execute(
                "INSERT OR IGNORE INTO user_roles("
                "user_id, role_id, scope_type, scope_id, granted_by, created_at"
                ") VALUES (?, ?, ?, ?, ?, ?)",
                (
                    str(user["user_id"]),
                    str(role["role_id"]),
                    scope,
                    normalized_scope_id,
                    actor,
                    timestamp,
                ),
            )
            self._audit(
                connection,
                actor or str(user["feishu_open_id"]),
                "grant_role",
                "role",
                str(role["role_id"]),
                f"{user['user_id']}:{scope}:{normalized_scope_id}",
            )
            row = connection.execute(
                "SELECT ur.*, r.name, r.description, r.capabilities_json "
                "FROM user_roles ur JOIN roles r ON r.role_id = ur.role_id "
                "WHERE ur.user_id = ? AND ur.role_id = ? AND ur.scope_type = ? AND ur.scope_id = ?",
                (user["user_id"], role["role_id"], scope, normalized_scope_id),
            ).fetchone()
            return self._role_dict(row)

    def list_user_roles(self, user_reference: str, *, scope_type: str | None = None) -> list[dict[str, Any]]:
        with self._connect() as connection:
            user = self._user_row(connection, user_reference)
            parameters: list[object] = [user["user_id"]]
            where = "ur.user_id = ?"
            if scope_type is not None:
                scope = _text(scope_type, "scope_type")
                if scope not in ROLE_SCOPE_VALUES:
                    raise RegistryError(f"scope_type 必须是 {sorted(ROLE_SCOPE_VALUES)} 之一")
                where += " AND ur.scope_type = ?"
                parameters.append(scope)
            rows = connection.execute(
                "SELECT ur.*, r.name, r.description, r.capabilities_json "
                "FROM user_roles ur JOIN roles r ON r.role_id = ur.role_id "
                f"WHERE {where} ORDER BY ur.scope_type, ur.scope_id, ur.role_id",
                parameters,
            )
            return [self._role_dict(row) for row in rows]

    def create_task_assignment(
        self,
        task_id: str,
        user_reference: str,
        role_reference: str,
        *,
        session_id: str | None = None,
        assignment_id: str | None = None,
        status: str = "assigned",
        assigned_by: str = "",
    ) -> dict[str, Any]:
        tid = _identifier(task_id, "task_id")
        aid = _identifier(assignment_id or f"assignment-{secrets.token_hex(6)}", "assignment_id")
        assignment_status = _text(status, "assignment status")
        if assignment_status not in ASSIGNMENT_STATUS_VALUES:
            raise RegistryError(f"assignment status 必须是 {sorted(ASSIGNMENT_STATUS_VALUES)} 之一")
        timestamp = now()
        sid = _text(session_id, "session_id", 80) if session_id else None
        if sid is not None and not SESSION_ID.fullmatch(sid):
            raise RegistryError("session_id 必须是 Codex UUID")
        accepted_at = timestamp if assignment_status in {"accepted", "active", "completed"} else None
        completed_at = timestamp if assignment_status == "completed" else None
        with self._connect() as connection:
            task = self._task_row(connection, tid)
            user = self._user_row(connection, user_reference)
            role = self._role_row(connection, role_reference)
            if sid is not None:
                session = connection.execute(
                    "SELECT session_id FROM sessions WHERE session_id = ?",
                    (sid,),
                ).fetchone()
                if session is None:
                    raise RegistryError(f"找不到 session: {sid}")
                attached = connection.execute(
                    "SELECT 1 FROM task_sessions WHERE task_id = ? AND session_id = ?",
                    (tid, sid),
                ).fetchone()
                if attached is None:
                    raise RegistryError("assignment 的 session 必须先关联到该 task")
            try:
                connection.execute(
                    "INSERT INTO task_assignments("
                    "assignment_id, task_id, user_id, role_id, session_id, status, assigned_by, "
                    "created_at, accepted_at, completed_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        aid,
                        tid,
                        user["user_id"],
                        role["role_id"],
                        sid,
                        assignment_status,
                        _text(assigned_by, "assigned_by", 160, required=False),
                        timestamp,
                        accepted_at,
                        completed_at,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise RegistryError("assignment_id 或 task assignment 已存在") from exc
            connection.execute("UPDATE tasks SET updated_at = ? WHERE task_id = ?", (timestamp, tid))
            self._audit(
                connection,
                str(assigned_by or user["feishu_open_id"]),
                "create_task_assignment",
                "task_assignment",
                aid,
                str(task["name"]),
            )
            return self._task_assignment_dict(
                connection.execute(
                    "SELECT ta.*, u.feishu_open_id, u.display_name, r.name AS role_name, "
                    "r.capabilities_json, s.label AS session_label "
                    "FROM task_assignments ta JOIN users u ON u.user_id = ta.user_id "
                    "JOIN roles r ON r.role_id = ta.role_id "
                    "LEFT JOIN sessions s ON s.session_id = ta.session_id "
                    "WHERE ta.assignment_id = ?",
                    (aid,),
                ).fetchone()
            )

    @staticmethod
    def _task_assignment_dict(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        if "capabilities_json" in result:
            try:
                result["role_capabilities"] = json.loads(result.pop("capabilities_json"))
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise RegistryError("assignment role capabilities 数据损坏") from exc
        return result

    def list_task_assignments(self, task_id: str) -> list[dict[str, Any]]:
        tid = _identifier(task_id, "task_id")
        with self._connect() as connection:
            self._task_row(connection, tid)
            rows = connection.execute(
                "SELECT ta.*, u.feishu_open_id, u.display_name, r.name AS role_name, "
                "r.capabilities_json, s.label AS session_label "
                "FROM task_assignments ta JOIN users u ON u.user_id = ta.user_id "
                "JOIN roles r ON r.role_id = ta.role_id "
                "LEFT JOIN sessions s ON s.session_id = ta.session_id "
                "WHERE ta.task_id = ? ORDER BY ta.created_at, ta.assignment_id",
                (tid,),
            )
            return [self._task_assignment_dict(row) for row in rows]

    def start_agent_run(
        self,
        task_id: str,
        session_id: str,
        *,
        assignment_id: str | None = None,
        run_id: str | None = None,
        status: str = "running",
    ) -> dict[str, Any]:
        tid = _identifier(task_id, "task_id")
        rid = _identifier(run_id or f"run-{secrets.token_hex(6)}", "run_id")
        run_status = _text(status, "agent run status")
        if run_status not in AGENT_RUN_STATUS_VALUES:
            raise RegistryError(f"agent run status 必须是 {sorted(AGENT_RUN_STATUS_VALUES)} 之一")
        sid = _text(session_id, "session_id", 80).lower()
        if not SESSION_ID.fullmatch(sid):
            raise RegistryError("session_id 必须是 Codex UUID")
        timestamp = now()
        started_at = timestamp if run_status in {"running", "waiting"} else None
        with self._connect() as connection:
            self._task_row(connection, tid)
            session = connection.execute("SELECT session_id FROM sessions WHERE session_id = ?", (sid,)).fetchone()
            if session is None:
                raise RegistryError(f"找不到 session: {sid}")
            attached = connection.execute(
                "SELECT 1 FROM task_sessions WHERE task_id = ? AND session_id = ?",
                (tid, sid),
            ).fetchone()
            if attached is None:
                raise RegistryError("agent run 的 session 必须先关联到该 task")
            assignment = None
            if assignment_id:
                assignment = self._assignment_row(connection, assignment_id)
                if str(assignment["task_id"]) != tid:
                    raise RegistryError("assignment 不属于该 task")
                if assignment["session_id"] and str(assignment["session_id"]) != sid:
                    raise RegistryError("agent run 的 session 与 assignment 不一致")
            try:
                connection.execute(
                    "INSERT INTO agent_runs("
                    "run_id, task_id, assignment_id, session_id, status, created_at, started_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (rid, tid, assignment_id, sid, run_status, timestamp, started_at),
                )
            except sqlite3.IntegrityError as exc:
                raise RegistryError("run_id 已存在") from exc
            return dict(connection.execute("SELECT * FROM agent_runs WHERE run_id = ?", (rid,)).fetchone())

    def finish_agent_run(
        self,
        run_id: str,
        *,
        status: str = "completed",
        summary: str = "",
        error: str = "",
    ) -> dict[str, Any]:
        run_status = _text(status, "agent run status")
        if run_status not in AGENT_RUN_STATUS_VALUES:
            raise RegistryError(f"agent run status 必须是 {sorted(AGENT_RUN_STATUS_VALUES)} 之一")
        terminal = run_status in {"completed", "failed", "cancelled", "stale"}
        with self._connect() as connection:
            run = self._agent_run_row(connection, run_id)
            finished_at = now() if terminal else None
            connection.execute(
                "UPDATE agent_runs SET status = ?, summary = ?, error = ?, finished_at = ? WHERE run_id = ?",
                (
                    run_status,
                    _text(summary, "summary", 4000, required=False),
                    _text(error, "error", 2000, required=False),
                    finished_at,
                    run["run_id"],
                ),
            )
            return dict(self._agent_run_row(connection, run_id))

    def list_agent_runs(self, task_id: str) -> list[dict[str, Any]]:
        tid = _identifier(task_id, "task_id")
        with self._connect() as connection:
            self._task_row(connection, tid)
            return _rows(connection.execute(
                "SELECT * FROM agent_runs WHERE task_id = ? ORDER BY created_at, run_id",
                (tid,),
            ))

    def _channel_principal(self, connection: sqlite3.Connection, run_id: str) -> sqlite3.Row:
        rid = _identifier(run_id, "run_id")
        row = connection.execute(
            "SELECT u.user_id, u.feishu_open_id, u.status, u.role "
            "FROM agent_runs ar "
            "LEFT JOIN task_assignments ta ON ta.assignment_id = ar.assignment_id "
            "JOIN sessions s ON s.session_id = ar.session_id "
            "JOIN installations i ON i.installation_id = s.installation_id "
            "JOIN users u ON u.user_id = COALESCE(ta.user_id, i.user_id) "
            "WHERE ar.run_id = ?",
            (rid,),
        ).fetchone()
        if row is None:
            raise RegistryError(f"找不到 agent run principal: {rid}")
        return row

    def _channel_capabilities(
        self,
        connection: sqlite3.Connection,
        user: sqlite3.Row,
        task_id: str,
    ) -> set[str]:
        defaults = {item[0]: item[3] for item in DEFAULT_ROLE_DEFINITIONS}
        capabilities: set[str] = {
            name for name, enabled in defaults.get(str(user["role"]), {}).items() if enabled
        }
        task = self._task_row(connection, task_id)
        if str(user["user_id"]) == str(task["owner_user_id"]):
            capabilities.update(
                name for name, enabled in defaults["owner"].items() if enabled
            )
        rows = connection.execute(
            "SELECT r.capabilities_json FROM user_roles ur "
            "JOIN roles r ON r.role_id = ur.role_id "
            "WHERE ur.user_id = ? AND (ur.scope_type = 'global' OR "
            "(ur.scope_type = 'task' AND ur.scope_id = ?))",
            (user["user_id"], task_id),
        )
        for row in rows:
            try:
                values = json.loads(row["capabilities_json"])
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise RegistryError("role capabilities 数据损坏") from exc
            if isinstance(values, dict):
                capabilities.update(name for name, enabled in values.items() if enabled)
        return capabilities

    def _channel_actor(
        self,
        connection: sqlite3.Connection,
        task_id: str,
        actor_reference: str,
    ) -> tuple[sqlite3.Row, set[str]]:
        actor = self._user_row(connection, actor_reference)
        if str(actor["status"]) != "approved":
            raise AuthorizationDenied("用户尚未 approved")
        return actor, self._channel_capabilities(connection, actor, task_id)

    def _channel_expire_if_needed(
        self,
        connection: sqlite3.Connection,
        channel: sqlite3.Row,
        timestamp: int | None = None,
    ) -> sqlite3.Row:
        timestamp = now() if timestamp is None else timestamp
        if channel["status"] in {"requested", "active"} and int(channel["expires_at"]) <= timestamp:
            connection.execute(
                "UPDATE agent_channels SET status = 'expired' WHERE channel_id = ?",
                (channel["channel_id"],),
            )
            channel = self._channel_row(connection, str(channel["channel_id"]))
        return channel

    def _channel_endpoint_allowed(
        self,
        connection: sqlite3.Connection,
        task_id: str,
        actor: sqlite3.Row,
        capabilities: set[str],
        run_id: str,
        *,
        capability: str,
        approver_capability: str = "agent.channel.approve",
    ) -> bool:
        principal = self._channel_principal(connection, run_id)
        if str(principal["user_id"]) == str(actor["user_id"]):
            return capability in capabilities
        return approver_capability in capabilities

    def request_agent_channel(
        self,
        task_id: str,
        from_run_id: str,
        to_run_id: str,
        capabilities: list[str],
        *,
        requested_by: str,
        channel_id: str | None = None,
        ttl_seconds: int = 3600,
    ) -> dict[str, Any]:
        tid = _identifier(task_id, "task_id")
        from_rid = _identifier(from_run_id, "from_run_id")
        to_rid = _identifier(to_run_id, "to_run_id")
        if from_rid == to_rid:
            raise RegistryError("agent channel 不能连接同一个 run")
        normalized_capabilities, capabilities_json = _channel_capabilities(capabilities)
        try:
            ttl = int(ttl_seconds)
        except (TypeError, ValueError) as exc:
            raise RegistryError("ttl_seconds 无效") from exc
        if ttl < 60 or ttl > 86400:
            raise RegistryError("ttl_seconds 必须在 60 到 86400 之间")
        cid = _identifier(channel_id or f"channel-{secrets.token_hex(16)}", "channel_id")
        timestamp = now()
        with self._connect() as connection:
            task = self._task_row(connection, tid)
            if str(task["status"]) in {"completed", "failed", "cancelled"}:
                raise RegistryError("任务已经结束，不能创建 agent channel")
            from_run = self._agent_run_row(connection, from_rid)
            to_run = self._agent_run_row(connection, to_rid)
            if str(from_run["task_id"]) != tid or str(to_run["task_id"]) != tid:
                raise RegistryError("channel 两端 run 必须属于同一个 task")
            if str(from_run["status"]) in {"completed", "failed", "cancelled", "stale"}:
                raise RegistryError("channel 发起端 run 已结束")
            if str(to_run["status"]) in {"completed", "failed", "cancelled", "stale"}:
                raise RegistryError("channel 接收端 run 已结束")
            actor, actor_capabilities = self._channel_actor(connection, tid, requested_by)
            from_principal = self._channel_principal(connection, from_rid)
            can_create = "agent.channel.create" in actor_capabilities
            if (
                str(from_principal["user_id"]) != str(actor["user_id"])
                and not can_create
            ):
                raise AuthorizationDenied("只有发起端 Agent 或任务控制者可以请求 channel")
            if not ({"agent.channel.request", "agent.channel.create"} & actor_capabilities):
                raise AuthorizationDenied("当前用户没有创建 agent channel 的权限")
            try:
                connection.execute(
                    "INSERT INTO agent_channels("
                    "channel_id, task_id, from_run_id, to_run_id, capabilities_json, status, "
                    "created_by, created_at, expires_at"
                    ") VALUES (?, ?, ?, ?, ?, 'requested', ?, ?, ?)",
                    (cid, tid, from_rid, to_rid, capabilities_json, actor["feishu_open_id"], timestamp, timestamp + ttl),
                )
            except sqlite3.IntegrityError as exc:
                raise RegistryError("channel_id 已存在") from exc
            self._audit(
                connection,
                str(actor["feishu_open_id"]),
                "request_agent_channel",
                "agent_channel",
                cid,
                f"{tid}:{from_rid}->{to_rid}:{','.join(normalized_capabilities)}",
            )
            return self._channel_dict(self._channel_row(connection, cid))

    def accept_agent_channel(
        self,
        channel_id: str,
        accepting_run_id: str,
        *,
        accepted_by: str,
    ) -> dict[str, Any]:
        cid = _identifier(channel_id, "channel_id")
        rid = _identifier(accepting_run_id, "accepting_run_id")
        with self._connect() as connection:
            channel = self._channel_expire_if_needed(connection, self._channel_row(connection, cid))
            if channel["status"] != "requested":
                raise RegistryError("agent channel 当前不能接收")
            if str(channel["to_run_id"]) != rid:
                raise AuthorizationDenied("只有 channel 接收端可以接受请求")
            actor, capabilities = self._channel_actor(connection, str(channel["task_id"]), accepted_by)
            if not self._channel_endpoint_allowed(
                connection,
                str(channel["task_id"]),
                actor,
                capabilities,
                rid,
                capability="agent.channel.read",
            ):
                raise AuthorizationDenied("当前用户不是接收端 Agent 或 channel 审批者")
            timestamp = now()
            connection.execute(
                "UPDATE agent_channels SET status = 'active', accepted_by = ?, accepted_at = ? "
                "WHERE channel_id = ? AND status = 'requested'",
                (actor["feishu_open_id"], timestamp, cid),
            )
            self._audit(
                connection,
                str(actor["feishu_open_id"]),
                "accept_agent_channel",
                "agent_channel",
                cid,
                rid,
            )
            return self._channel_dict(self._channel_row(connection, cid))

    def revoke_agent_channel(self, channel_id: str, *, revoked_by: str) -> dict[str, Any]:
        cid = _identifier(channel_id, "channel_id")
        with self._connect() as connection:
            channel = self._channel_expire_if_needed(connection, self._channel_row(connection, cid))
            if channel["status"] in {"revoked", "expired"}:
                return self._channel_dict(channel)
            actor, capabilities = self._channel_actor(connection, str(channel["task_id"]), revoked_by)
            allowed = any(
                self._channel_endpoint_allowed(
                    connection,
                    str(channel["task_id"]),
                    actor,
                    capabilities,
                    str(run_id),
                    capability="agent.channel.read",
                )
                for run_id in (str(channel["from_run_id"]), str(channel["to_run_id"]))
            ) or "agent.channel.approve" in capabilities
            if not allowed:
                raise AuthorizationDenied("当前用户不能撤销该 channel")
            timestamp = now()
            connection.execute(
                "UPDATE agent_channels SET status = 'revoked', revoked_by = ?, revoked_at = ? "
                "WHERE channel_id = ?",
                (actor["feishu_open_id"], timestamp, cid),
            )
            self._audit(
                connection,
                str(actor["feishu_open_id"]),
                "revoke_agent_channel",
                "agent_channel",
                cid,
            )
            return self._channel_dict(self._channel_row(connection, cid))

    def list_agent_channels(
        self,
        task_id: str,
        *,
        user_reference: str | None = None,
    ) -> list[dict[str, Any]]:
        tid = _identifier(task_id, "task_id")
        with self._connect() as connection:
            self._task_row(connection, tid)
            if user_reference:
                actor, capabilities = self._channel_actor(connection, tid, user_reference)
                participant = connection.execute(
                    "SELECT 1 FROM agent_runs ar "
                    "LEFT JOIN task_assignments ta ON ta.assignment_id = ar.assignment_id "
                    "JOIN sessions s ON s.session_id = ar.session_id "
                    "JOIN installations i ON i.installation_id = s.installation_id "
                    "WHERE ar.task_id = ? AND COALESCE(ta.user_id, i.user_id) = ? LIMIT 1",
                    (tid, actor["user_id"]),
                ).fetchone()
                if participant is None and not (
                    {"agent.channel.read", "agent.channel.approve", "agent.channel.create"} & capabilities
                ):
                    raise AuthorizationDenied("当前用户不能查看该 task 的 agent channel")
            timestamp = now()
            channels = connection.execute(
                "SELECT * FROM agent_channels WHERE task_id = ? ORDER BY created_at, channel_id",
                (tid,),
            ).fetchall()
            return [
                self._channel_dict(self._channel_expire_if_needed(connection, channel, timestamp))
                for channel in channels
            ]

    def send_agent_channel_message(
        self,
        channel_id: str,
        sender_run_id: str,
        message_id: str,
        payload: dict[str, Any],
        *,
        sent_by: str,
    ) -> dict[str, Any]:
        cid = _identifier(channel_id, "channel_id")
        sender = _identifier(sender_run_id, "sender_run_id")
        mid = _identifier(message_id, "message_id")
        normalized_payload, payload_json = _channel_payload(payload)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            channel = self._channel_expire_if_needed(connection, self._channel_row(connection, cid))
            if channel["status"] != "active":
                connection.rollback()
                raise RegistryError("agent channel 当前未激活")
            if sender not in {str(channel["from_run_id"]), str(channel["to_run_id"])}:
                connection.rollback()
                raise AuthorizationDenied("sender run 不属于该 channel")
            if "agent.message" not in json.loads(channel["capabilities_json"]):
                connection.rollback()
                raise AuthorizationDenied("该 channel 没有 agent.message capability")
            actor, capabilities = self._channel_actor(connection, str(channel["task_id"]), sent_by)
            if not self._channel_endpoint_allowed(
                connection,
                str(channel["task_id"]),
                actor,
                capabilities,
                sender,
                capability="agent.channel.message",
            ):
                connection.rollback()
                raise AuthorizationDenied("当前用户不能代表 sender run 发送消息")
            recipient = (
                str(channel["to_run_id"])
                if sender == str(channel["from_run_id"])
                else str(channel["from_run_id"])
            )
            existing = connection.execute(
                "SELECT * FROM agent_channel_messages WHERE message_id = ?", (mid,)
            ).fetchone()
            if existing is not None:
                if (
                    str(existing["channel_id"]) != cid
                    or str(existing["sender_run_id"]) != sender
                    or str(existing["recipient_run_id"]) != recipient
                    or json.loads(existing["payload_json"]) != normalized_payload
                ):
                    connection.rollback()
                    raise RegistryError("message_id 已用于另一条 channel 消息")
                connection.commit()
                return self._channel_message_dict(existing)
            sequence_row = connection.execute(
                "SELECT COALESCE(MAX(sequence), 0) + 1 FROM agent_channel_messages WHERE channel_id = ?",
                (cid,),
            ).fetchone()
            sequence = int(sequence_row[0])
            timestamp = now()
            try:
                connection.execute(
                    "INSERT INTO agent_channel_messages("
                    "message_id, channel_id, sender_run_id, recipient_run_id, sequence, payload_json, "
                    "status, lease_until, attempts, created_at, updated_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, 'queued', 0, 0, ?, ?)",
                    (mid, cid, sender, recipient, sequence, payload_json, timestamp, timestamp),
                )
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise RegistryError("channel message_id 或 sequence 已存在") from exc
            self._audit(
                connection,
                str(actor["feishu_open_id"]),
                "send_agent_channel_message",
                "agent_channel",
                cid,
                f"{mid}:{sender}->{recipient}:seq={sequence}",
            )
            connection.commit()
            return self._channel_message_dict(
                connection.execute(
                    "SELECT * FROM agent_channel_messages WHERE message_id = ?", (mid,)
                ).fetchone()
            )

    def poll_agent_channel_messages(
        self,
        channel_id: str,
        recipient_run_id: str,
        *,
        requested_by: str,
        limit: int = 20,
        lease_seconds: int = 120,
    ) -> list[dict[str, Any]]:
        cid = _identifier(channel_id, "channel_id")
        recipient = _identifier(recipient_run_id, "recipient_run_id")
        if limit < 1 or limit > 50:
            raise RegistryError("limit 必须在 1 到 50 之间")
        if lease_seconds < 10 or lease_seconds > 3600:
            raise RegistryError("lease_seconds 必须在 10 到 3600 之间")
        timestamp = now()
        with self._connect() as connection:
            channel = self._channel_expire_if_needed(connection, self._channel_row(connection, cid), timestamp)
            if channel["status"] != "active":
                raise RegistryError("agent channel 当前未激活")
            if recipient not in {str(channel["from_run_id"]), str(channel["to_run_id"])}:
                raise AuthorizationDenied("recipient run 不属于该 channel")
            actor, capabilities = self._channel_actor(connection, str(channel["task_id"]), requested_by)
            if not self._channel_endpoint_allowed(
                connection,
                str(channel["task_id"]),
                actor,
                capabilities,
                recipient,
                capability="agent.channel.read",
            ):
                raise AuthorizationDenied("当前用户不能读取 recipient run 的 channel 消息")
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT * FROM agent_channel_messages WHERE channel_id = ? AND recipient_run_id = ? "
                "AND ((status = 'queued') OR (status = 'claimed' AND lease_until < ?)) "
                "ORDER BY sequence LIMIT ?",
                (cid, recipient, timestamp, limit),
            ).fetchall()
            result: list[dict[str, Any]] = []
            for row in rows:
                connection.execute(
                    "UPDATE agent_channel_messages SET status = 'claimed', lease_until = ?, "
                    "attempts = attempts + 1, claimed_at = ?, updated_at = ? WHERE message_id = ?",
                    (timestamp + lease_seconds, timestamp, timestamp, row["message_id"]),
                )
                updated = connection.execute(
                    "SELECT * FROM agent_channel_messages WHERE message_id = ?",
                    (row["message_id"],),
                ).fetchone()
                if updated is not None:
                    result.append(self._channel_message_dict(updated))
            connection.commit()
            return result

    def ack_agent_channel_message(
        self,
        message_id: str,
        recipient_run_id: str,
        *,
        status: str = "acknowledged",
        acknowledged_by: str,
    ) -> dict[str, Any]:
        mid = _identifier(message_id, "message_id")
        recipient = _identifier(recipient_run_id, "recipient_run_id")
        message_status = _text(status, "message status")
        if message_status not in {"acknowledged", "rejected"}:
            raise RegistryError("message status 必须是 acknowledged 或 rejected")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM agent_channel_messages WHERE message_id = ?", (mid,)
            ).fetchone()
            if row is None:
                raise RegistryError(f"找不到 channel message: {mid}")
            channel = self._channel_row(connection, str(row["channel_id"]))
            if str(row["recipient_run_id"]) != recipient:
                raise AuthorizationDenied("只有消息接收端可以确认消息")
            actor, capabilities = self._channel_actor(connection, str(channel["task_id"]), acknowledged_by)
            if not self._channel_endpoint_allowed(
                connection,
                str(channel["task_id"]),
                actor,
                capabilities,
                recipient,
                capability="agent.channel.read",
            ):
                raise AuthorizationDenied("当前用户不能确认该 channel 消息")
            if row["status"] in {"acknowledged", "rejected"}:
                if str(row["status"]) != message_status:
                    raise RegistryError("channel message 已经以另一状态确认")
                return self._channel_message_dict(row)
            if row["status"] != "claimed":
                raise RegistryError("channel message 尚未被 poll claim")
            timestamp = now()
            connection.execute(
                "UPDATE agent_channel_messages SET status = ?, lease_until = 0, acknowledged_at = ?, updated_at = ? "
                "WHERE message_id = ?",
                (message_status, timestamp, timestamp, mid),
            )
            self._audit(
                connection,
                str(actor["feishu_open_id"]),
                "ack_agent_channel_message",
                "agent_channel_message",
                mid,
                message_status,
            )
            return self._channel_message_dict(
                connection.execute(
                    "SELECT * FROM agent_channel_messages WHERE message_id = ?", (mid,)
                ).fetchone()
            )

    def record_evidence(
        self,
        task_id: str,
        kind: str,
        title: str,
        *,
        uri: str = "",
        content_hash: str = "",
        summary: str = "",
        assignment_id: str | None = None,
        run_id: str | None = None,
        session_id: str | None = None,
        evidence_id: str | None = None,
        created_by: str = "",
        verification_status: str = "unverified",
    ) -> dict[str, Any]:
        tid = _identifier(task_id, "task_id")
        eid = _identifier(evidence_id or f"evidence-{secrets.token_hex(6)}", "evidence_id")
        verification = _text(verification_status, "verification_status")
        if verification not in EVIDENCE_STATUS_VALUES:
            raise RegistryError(f"verification_status 必须是 {sorted(EVIDENCE_STATUS_VALUES)} 之一")
        timestamp = now()
        with self._connect() as connection:
            self._task_row(connection, tid)
            if assignment_id:
                assignment = self._assignment_row(connection, assignment_id)
                if str(assignment["task_id"]) != tid:
                    raise RegistryError("evidence assignment 不属于该 task")
            if run_id:
                run = self._agent_run_row(connection, run_id)
                if str(run["task_id"]) != tid:
                    raise RegistryError("evidence run 不属于该 task")
                if session_id is None:
                    session_id = str(run["session_id"] or "") or None
            sid = _text(session_id, "session_id", 80).lower() if session_id else None
            if sid is not None:
                if not SESSION_ID.fullmatch(sid):
                    raise RegistryError("session_id 必须是 Codex UUID")
                if connection.execute("SELECT 1 FROM sessions WHERE session_id = ?", (sid,)).fetchone() is None:
                    raise RegistryError(f"找不到 session: {sid}")
            actor = _text(created_by, "created_by", 160, required=False)
            actor_user = self._user_row(connection, actor) if actor else None
            try:
                connection.execute(
                    "INSERT INTO evidence("
                    "evidence_id, task_id, assignment_id, run_id, session_id, kind, title, uri, "
                    "content_hash, summary, verification_status, created_by, created_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        eid,
                        tid,
                        assignment_id,
                        run_id,
                        sid,
                        _text(kind, "evidence kind", 80),
                        _text(title, "evidence title", 240),
                        _text(uri, "evidence uri", 1000, required=False),
                        _text(content_hash, "content_hash", 200, required=False),
                        _text(summary, "evidence summary", 4000, required=False),
                        verification,
                        actor,
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise RegistryError("evidence_id 已存在") from exc
            self._append_task_event_in_connection(
                connection,
                tid,
                "evidence.attached",
                {"evidence_id": eid, "kind": kind, "verification_status": verification},
                session_id=sid,
                actor_open_id=str(actor_user["feishu_open_id"] if actor_user else ""),
                idempotency_key=f"evidence:{eid}:attached",
                timestamp=timestamp,
            )
            return self._evidence_row_dict(self._evidence_row(connection, eid))

    @staticmethod
    def _evidence_row_dict(row: sqlite3.Row) -> dict[str, Any]:
        return dict(row)

    def verify_evidence(
        self,
        evidence_id: str,
        verifier_reference: str,
        *,
        status: str = "verified",
    ) -> dict[str, Any]:
        verification = _text(status, "verification_status")
        if verification not in EVIDENCE_STATUS_VALUES:
            raise RegistryError(f"verification_status 必须是 {sorted(EVIDENCE_STATUS_VALUES)} 之一")
        with self._connect() as connection:
            evidence = self._evidence_row(connection, evidence_id)
            verifier = self._user_row(connection, verifier_reference)
            verified_at = now() if verification in {"verified", "rejected"} else None
            connection.execute(
                "UPDATE evidence SET verification_status = ?, verifier_open_id = ?, verified_at = ? "
                "WHERE evidence_id = ?",
                (verification, verifier["feishu_open_id"], verified_at, evidence_id),
            )
            self._append_task_event_in_connection(
                connection,
                str(evidence["task_id"]),
                "evidence.verified" if verification == "verified" else "evidence.rejected",
                {"evidence_id": str(evidence["evidence_id"]), "verification_status": verification},
                session_id=str(evidence["session_id"] or "") or None,
                actor_open_id=str(verifier["feishu_open_id"]),
                idempotency_key=f"evidence:{evidence_id}:{verification}",
                timestamp=verified_at or now(),
            )
            return self._evidence_row_dict(self._evidence_row(connection, evidence_id))

    def verify_evidence_as_task_owner(
        self,
        task_id: str,
        evidence_id: str,
        owner_reference: str,
    ) -> dict[str, Any]:
        """Verify one evidence item only when the caller owns its task."""

        tid = _identifier(task_id, "task_id")
        with self._connect() as connection:
            task = self._task_row(connection, tid)
            owner = self._user_row(connection, owner_reference)
            evidence = self._evidence_row(connection, evidence_id)
            if str(task["owner_user_id"]) != str(owner["user_id"]):
                raise AuthorizationDenied("只有任务负责人可以验证证据")
            if str(evidence["task_id"]) != tid:
                raise RegistryError("evidence 不属于该 task")
        return self.verify_evidence(evidence_id, owner_reference, status="verified")

    def approve_task(
        self,
        task_id: str,
        owner_reference: str,
        *,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        """Complete a task only after its owner accepts verified evidence."""

        tid = _identifier(task_id, "task_id")
        sid = _text(session_id, "session_id", 80).lower() if session_id else None
        timestamp = now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            task = self._task_row(connection, tid)
            owner = self._user_row(connection, owner_reference)
            if str(task["owner_user_id"]) != str(owner["user_id"]):
                raise AuthorizationDenied("只有任务负责人可以确认验收")
            previous_credit = connection.execute(
                "SELECT * FROM task_credits WHERE task_id=?", (tid,),
            ).fetchone()
            if task["status"] == "completed" and previous_credit is not None:
                return {**self._task_dict(task), "credit": dict(previous_credit)}
            claim = connection.execute(
                "SELECT * FROM task_queue_claims WHERE task_id=? AND status IN ('active','submitted')",
                (tid,),
            ).fetchone()
            if self._task_dict(task)["contract"].get("team_queue") and claim is None:
                raise RegistryError("队列任务必须由领取者提交后才能验收")
            if claim is not None and claim["status"] != "submitted":
                raise RegistryError("领取者尚未提交任务")
            if sid:
                attached = connection.execute(
                    "SELECT 1 FROM task_sessions WHERE task_id = ? AND session_id = ?", (tid, sid)
                ).fetchone()
                if attached is None:
                    raise RegistryError("验收的 session 未关联到该 task")
            if claim is not None:
                evidence = connection.execute(
                    "SELECT evidence_id FROM evidence WHERE evidence_id=? AND task_id=? "
                    "AND verification_status='verified' AND (? IS NULL OR session_id=? OR session_id IS NULL)",
                    (claim["evidence_id"], tid, sid, sid),
                ).fetchone()
            elif sid:
                evidence = connection.execute(
                    "SELECT evidence_id FROM evidence WHERE task_id = ? AND verification_status = 'verified' "
                    "AND (session_id = ? OR session_id IS NULL) ORDER BY created_at DESC LIMIT 1",
                    (tid, sid),
                ).fetchone()
            else:
                evidence = connection.execute(
                    "SELECT evidence_id FROM evidence WHERE task_id = ? AND verification_status = 'verified' "
                    "ORDER BY created_at DESC LIMIT 1",
                    (tid,),
                ).fetchone()
            if evidence is None:
                raise RegistryError("任务还没有已验证证据，不能确认完成")
            event = self._append_task_event_in_connection(
                connection,
                tid,
                "task.approved",
                {"evidence_id": str(evidence["evidence_id"])},
                session_id=sid,
                actor_open_id=str(owner["feishu_open_id"]),
                idempotency_key=f"task:{tid}:approved:{sid or 'all'}",
                timestamp=timestamp,
            )
            connection.execute(
                "UPDATE tasks SET status = 'completed', updated_at = ? WHERE task_id = ?",
                (timestamp, tid),
            )
            if claim is not None:
                connection.execute(
                    "INSERT INTO task_credits(task_id,claim_id,user_id,evidence_id,approved_by,awarded_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (tid, claim["claim_id"], claim["user_id"], evidence["evidence_id"], owner["user_id"], timestamp),
                )
                connection.execute(
                    "UPDATE task_queue_claims SET status='credited', closed_at=? WHERE claim_id=?",
                    (timestamp, claim["claim_id"]),
                )
            connection.commit()
            result = self._task_dict(self._task_row(connection, tid))
            result["approval_event"] = self._task_event_dict(event)
            credit = connection.execute("SELECT * FROM task_credits WHERE task_id=?", (tid,)).fetchone()
            if credit is not None:
                result["credit"] = dict(credit)
            return result

    def list_evidence(self, task_id: str, *, verification_status: str | None = None) -> list[dict[str, Any]]:
        tid = _identifier(task_id, "task_id")
        with self._connect() as connection:
            self._task_row(connection, tid)
            parameters: list[object] = [tid]
            where = "task_id = ?"
            if verification_status is not None:
                verification = _text(verification_status, "verification_status")
                if verification not in EVIDENCE_STATUS_VALUES:
                    raise RegistryError(f"verification_status 必须是 {sorted(EVIDENCE_STATUS_VALUES)} 之一")
                where += " AND verification_status = ?"
                parameters.append(verification)
            return _rows(connection.execute(
                f"SELECT * FROM evidence WHERE {where} ORDER BY created_at, evidence_id",
                parameters,
            ))

    def task_progress(self, task_id: str, *, session_id: str | None = None) -> dict[str, Any]:
        """Derive a conservative, evidence-backed task progress snapshot.

        A terminal response is not completion evidence.  One verified evidence
        item caps a task at 90%; the task owner must append ``task.approved``
        before the card can show 100%.
        """

        tid = _identifier(task_id, "task_id")
        sid = _text(session_id, "session_id", 80).lower() if session_id else None
        with self._connect() as connection:
            task = self._task_dict(self._task_row(connection, tid))
            owner = connection.execute(
                "SELECT feishu_open_id FROM users WHERE user_id = ?", (task["owner_user_id"],)
            ).fetchone()
            clauses = ["task_id = ?"]
            parameters: list[object] = [tid]
            if sid:
                if connection.execute(
                    "SELECT 1 FROM task_sessions WHERE task_id = ? AND session_id = ?", (tid, sid)
                ).fetchone() is None:
                    raise RegistryError("进度查询的 session 必须关联到该 task")
                clauses.append("(session_id = ? OR session_id IS NULL)")
                parameters.append(sid)
            events = _rows(connection.execute(
                "SELECT event_type, actor_open_id FROM task_events WHERE " + " AND ".join(clauses),
                parameters,
            ))
            evidence_clauses = ["task_id = ?"]
            evidence_parameters: list[object] = [tid]
            if sid:
                evidence_clauses.append("(session_id = ? OR session_id IS NULL)")
                evidence_parameters.append(sid)
            evidence = _rows(connection.execute(
                "SELECT verification_status FROM evidence WHERE " + " AND ".join(evidence_clauses),
                evidence_parameters,
            ))

        event_types = {str(event["event_type"]).casefold() for event in events}
        evidence_count = len(evidence)
        verified_count = sum(item["verification_status"] == "verified" for item in evidence)
        percent = 10
        for event_type, weight in TASK_PROGRESS_EVENT_WEIGHTS.items():
            if event_type in event_types:
                percent = max(percent, weight)
        if evidence_count:
            percent = max(percent, 75)
        if verified_count:
            percent = max(percent, 90)

        owner_open_id = str(owner["feishu_open_id"] if owner else "")
        approved = any(
            str(event["event_type"]).casefold() == "task.approved"
            and str(event["actor_open_id"]) == owner_open_id
            for event in events
        )
        completed_claim = bool({"command.completed", "task.completed"} & event_types)
        if task["status"] in {"failed", "cancelled"}:
            state, color = "任务异常", "red"
            percent = 0
        elif approved and verified_count:
            percent = 100
            state, color = "已验收", "green"
        elif verified_count:
            state, color = "等待确认", "blue"
        elif evidence_count:
            state, color = "证据待验证", "yellow"
        elif completed_claim:
            state, color = "证据缺失", "yellow"
        elif task["status"] == "planned":
            state, color = "待执行", "grey"
        else:
            state, color = "执行中", "blue"

        return {
            "task_id": tid,
            "session_id": sid or "",
            "percent": percent,
            "state": state,
            "color": color,
            "evidence_count": evidence_count,
            "verified_evidence_count": verified_count,
            "approved": approved,
        }

    def create_handoff(
        self,
        task_id: str,
        capsule: dict[str, Any],
        *,
        from_assignment_id: str | None = None,
        to_assignment_id: str | None = None,
        from_run_id: str | None = None,
        handoff_id: str | None = None,
        status: str = "ready",
        created_by: str,
    ) -> dict[str, Any]:
        tid = _identifier(task_id, "task_id")
        hid = _identifier(handoff_id or f"handoff-{secrets.token_hex(6)}", "handoff_id")
        handoff_status = _text(status, "handoff status")
        if handoff_status not in HANDOFF_STATUS_VALUES:
            raise RegistryError(f"handoff status 必须是 {sorted(HANDOFF_STATUS_VALUES)} 之一")
        _, capsule_json = _json_object(capsule, "handoff capsule")
        timestamp = now()
        with self._connect() as connection:
            self._task_row(connection, tid)
            for assignment_id in (from_assignment_id, to_assignment_id):
                if assignment_id:
                    assignment = self._assignment_row(connection, assignment_id)
                    if str(assignment["task_id"]) != tid:
                        raise RegistryError("handoff assignment 不属于该 task")
            if from_run_id:
                run = self._agent_run_row(connection, from_run_id)
                if str(run["task_id"]) != tid:
                    raise RegistryError("handoff run 不属于该 task")
            creator = self._user_row(connection, created_by)
            try:
                connection.execute(
                    "INSERT INTO handoffs("
                    "handoff_id, task_id, from_assignment_id, to_assignment_id, from_run_id, status, "
                    "capsule_json, created_by, created_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        hid,
                        tid,
                        from_assignment_id,
                        to_assignment_id,
                        from_run_id,
                        handoff_status,
                        capsule_json,
                        creator["feishu_open_id"],
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise RegistryError("handoff_id 已存在") from exc
            return self._handoff_dict(self._handoff_row(connection, hid))

    def accept_handoff(self, handoff_id: str, user_reference: str) -> dict[str, Any]:
        with self._connect() as connection:
            handoff = self._handoff_row(connection, handoff_id)
            user = self._user_row(connection, user_reference)
            if handoff["status"] not in {"draft", "ready"}:
                raise RegistryError("handoff 当前不能接收")
            connection.execute(
                "UPDATE handoffs SET status = 'accepted', accepted_by = ?, accepted_at = ? "
                "WHERE handoff_id = ?",
                (user["feishu_open_id"], now(), handoff["handoff_id"]),
            )
            return self._handoff_dict(self._handoff_row(connection, handoff_id))

    def list_handoffs(self, task_id: str) -> list[dict[str, Any]]:
        tid = _identifier(task_id, "task_id")
        with self._connect() as connection:
            self._task_row(connection, tid)
            return [
                self._handoff_dict(row)
                for row in connection.execute(
                    "SELECT * FROM handoffs WHERE task_id = ? ORDER BY created_at, handoff_id",
                    (tid,),
                )
            ]

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

    def create_group_task(
        self,
        group_reference: str,
        owner_reference: str,
        session_id: str,
        name: str,
        contract: dict[str, Any],
        *,
        task_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Atomically create, bind, and share a runnable group task."""

        tid = _identifier(task_id or f"task-{secrets.token_hex(6)}", "task_id")
        sid = _text(session_id, "session_id", 80).lower()
        if not SESSION_ID.fullmatch(sid):
            raise RegistryError("session_id 必须是 Codex UUID")
        task_name = _text(name, "task name", 160)
        contract = dict(contract)
        if idempotency_key is not None:
            contract["source_message_id"] = _text(idempotency_key, "message_id", 160)
        _, contract_json = _json_object(contract, "contract")
        timestamp = now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            group = self._group_row(connection, group_reference)
            owner = self._user_row(connection, owner_reference)
            membership = connection.execute(
                "SELECT role FROM group_members WHERE group_id = ? AND user_id = ?",
                (group["group_id"], owner["user_id"]),
            ).fetchone()
            if owner["status"] != "approved" or membership is None:
                raise AuthorizationDenied("任务负责人不是已批准的群成员")
            shared = connection.execute(
                "SELECT access FROM session_shares WHERE group_id = ? AND session_id = ?",
                (group["group_id"], sid),
            ).fetchone()
            if shared is None or str(shared["access"]) != "write":
                raise AuthorizationDenied("目标 Session 未以可指导权限共享到当前群组")
            existing = connection.execute(
                "SELECT t.owner_user_id, t.contract_json FROM tasks t "
                "JOIN task_groups tg ON tg.task_id=t.task_id AND tg.group_id=? "
                "JOIN task_sessions ts ON ts.task_id=t.task_id AND ts.session_id=? "
                "WHERE t.task_id=?", (group["group_id"], sid, tid),
            ).fetchone()
            if existing is not None and idempotency_key is not None \
                    and existing["owner_user_id"] == owner["user_id"] \
                    and existing["contract_json"] == contract_json:
                return self.get_task(tid)
            try:
                connection.execute(
                    "INSERT INTO tasks(task_id, owner_user_id, name, contract_json, status, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, 'planned', ?, ?)",
                    (tid, owner["user_id"], task_name, contract_json, timestamp, timestamp),
                )
            except sqlite3.IntegrityError as exc:
                raise RegistryError("task_id 已存在") from exc
            connection.execute(
                "INSERT INTO task_sessions(task_id, session_id, relation, created_at) VALUES (?, ?, 'primary', ?)",
                (tid, sid, timestamp),
            )
            connection.execute(
                "INSERT INTO task_groups(task_id, group_id, access, created_at) VALUES (?, ?, 'write', ?)",
                (tid, group["group_id"], timestamp),
            )
            self._append_task_event_in_connection(
                connection,
                tid,
                "task.created",
                {"objective": contract.get("objective", "")},
                session_id=None,
                actor_open_id=str(owner["feishu_open_id"]),
                idempotency_key=f"task:{tid}:created",
                timestamp=timestamp,
            )
            self._audit(connection, owner["feishu_open_id"], "create_group_task", "task", tid, sid)
            connection.commit()
            return self.get_task(tid)

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

    def bind_group_task_session(
        self,
        group_reference: str,
        owner_reference: str,
        task_id: str,
        session_id: str,
    ) -> dict[str, Any]:
        """Bind an owner task to a writable Session already shared to a group."""

        tid = _identifier(task_id, "task_id")
        sid = _text(session_id, "session_id", 80).lower()
        if not SESSION_ID.fullmatch(sid):
            raise RegistryError("session_id 必须是 Codex UUID")
        with self._connect() as connection:
            group = self._group_row(connection, group_reference)
            owner = self._user_row(connection, owner_reference)
            task = self._task_row(connection, tid)
            if str(task["owner_user_id"]) != str(owner["user_id"]):
                raise AuthorizationDenied("只有任务负责人可以绑定 Session")
            member = connection.execute(
                "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?",
                (group["group_id"], owner["user_id"]),
            ).fetchone()
            share = connection.execute(
                "SELECT access FROM session_shares WHERE group_id = ? AND session_id = ?",
                (group["group_id"], sid),
            ).fetchone()
            if member is None or share is None or str(share["access"]) != "write":
                raise AuthorizationDenied("目标 Session 未以可指导权限共享到当前群组")
        return self.attach_task_session(tid, sid, relation="primary")

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

    def _shared_task_context(
        self, connection: sqlite3.Connection, chat_id: str, open_id: str, task_id: str,
        *, write: bool = True,
    ) -> tuple[sqlite3.Row, sqlite3.Row, sqlite3.Row]:
        group = self._group_row(connection, chat_id)
        user = self._user_row(connection, open_id)
        task = self._task_row(connection, task_id)
        member = connection.execute(
            "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?",
            (group["group_id"], user["user_id"]),
        ).fetchone()
        share = connection.execute(
            "SELECT access FROM task_groups WHERE task_id = ? AND group_id = ?",
            (task["task_id"], group["group_id"]),
        ).fetchone()
        if user["status"] != "approved" or member is None or share is None:
            raise AuthorizationDenied("用户无权查看该群任务")
        if write and share["access"] != "write":
            raise AuthorizationDenied("该群任务只读")
        return group, user, task

    def task_queue(self, chat_id: str, open_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            group = self._group_row(connection, chat_id)
            user = self._user_row(connection, open_id)
            if user["status"] != "approved" or connection.execute(
                "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?",
                (group["group_id"], user["user_id"]),
            ).fetchone() is None:
                raise AuthorizationDenied("用户不是已批准的群成员")
            rows = connection.execute(
                "SELECT t.*, tg.access, c.claim_id, c.status AS claim_status, "
                "u.display_name AS claimant, cr.user_id AS credited_user_id "
                "FROM task_groups tg JOIN tasks t ON t.task_id = tg.task_id "
                "LEFT JOIN task_queue_claims c ON c.task_id = t.task_id AND c.status IN ('active','submitted') "
                "LEFT JOIN users u ON u.user_id = c.user_id "
                "LEFT JOIN task_credits cr ON cr.task_id = t.task_id "
                "WHERE tg.group_id = ? ORDER BY t.updated_at DESC, t.task_id",
                (group["group_id"],),
            )
            return [self._task_dict(row) for row in rows]

    def claim_shared_task(self, chat_id: str, open_id: str, task_id: str) -> dict[str, Any]:
        tid = _identifier(task_id, "task_id")
        timestamp = now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            group, user, task = self._shared_task_context(connection, chat_id, open_id, tid)
            if task["status"] not in {"planned", "running"}:
                raise RegistryError("任务已经结束")
            contract = self._task_dict(task)["contract"]
            if not isinstance(contract.get("acceptance"), list) or not contract["acceptance"]:
                raise RegistryError("任务需要明确的验收标准才能领取")
            current = connection.execute(
                "SELECT * FROM task_queue_claims WHERE task_id = ? AND status IN ('active','submitted')",
                (tid,),
            ).fetchone()
            if current is not None:
                if current["user_id"] == user["user_id"]:
                    return dict(current)
                raise RegistryError("任务已由其他成员领取")
            claim_id = f"claim-{secrets.token_hex(8)}"
            connection.execute(
                "INSERT INTO task_queue_claims(claim_id,task_id,group_id,user_id,status,claimed_at) "
                "VALUES(?,?,?,?, 'active', ?)",
                (claim_id, tid, group["group_id"], user["user_id"], timestamp),
            )
            connection.execute("UPDATE tasks SET status = 'running', updated_at = ? WHERE task_id = ?", (timestamp, tid))
            self._audit(connection, open_id, "claim_shared_task", "task", tid, claim_id)
            connection.commit()
            return dict(connection.execute("SELECT * FROM task_queue_claims WHERE claim_id = ?", (claim_id,)).fetchone())

    def release_shared_task(self, chat_id: str, open_id: str, task_id: str) -> dict[str, Any]:
        tid = _identifier(task_id, "task_id")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            _, user, task = self._shared_task_context(connection, chat_id, open_id, tid)
            current = connection.execute(
                "SELECT * FROM task_queue_claims WHERE task_id = ? AND status IN ('active','submitted')",
                (tid,),
            ).fetchone()
            if current is None:
                raise RegistryError("任务当前无人领取")
            if user["user_id"] not in {current["user_id"], task["owner_user_id"]}:
                raise AuthorizationDenied("只有领取者或负责人可以释放任务")
            timestamp = now()
            connection.execute(
                "UPDATE task_queue_claims SET status='released', closed_at=? WHERE claim_id=?",
                (timestamp, current["claim_id"]),
            )
            connection.execute("UPDATE tasks SET status='planned', updated_at=? WHERE task_id=?", (timestamp, tid))
            self._audit(connection, open_id, "release_shared_task", "task", tid, str(current["claim_id"]))
            connection.commit()
            return dict(connection.execute("SELECT * FROM task_queue_claims WHERE claim_id=?", (current["claim_id"],)).fetchone())

    def submit_shared_task(self, chat_id: str, open_id: str, task_id: str, evidence_id: str) -> dict[str, Any]:
        tid = _identifier(task_id, "task_id")
        eid = _identifier(evidence_id, "evidence_id")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            _, user, _ = self._shared_task_context(connection, chat_id, open_id, tid)
            claim = connection.execute(
                "SELECT * FROM task_queue_claims WHERE task_id=? AND status IN ('active','submitted')",
                (tid,),
            ).fetchone()
            if claim is None or claim["user_id"] != user["user_id"]:
                raise AuthorizationDenied("只有当前领取者可以提交")
            if claim["status"] == "submitted":
                if claim["evidence_id"] == eid:
                    return dict(claim)
                raise RegistryError("任务已提交，先释放或等待验收")
            evidence = self._evidence_row(connection, eid)
            creator = self._user_row(connection, str(evidence["created_by"]))
            if evidence["task_id"] != tid or creator["user_id"] != user["user_id"] or evidence["created_at"] < claim["claimed_at"]:
                raise AuthorizationDenied("证据不属于当前领取者的本次任务")
            timestamp = now()
            connection.execute(
                "UPDATE task_queue_claims SET status='submitted', evidence_id=?, submitted_at=? WHERE claim_id=?",
                (eid, timestamp, claim["claim_id"]),
            )
            self._audit(connection, open_id, "submit_shared_task", "task", tid, eid)
            connection.commit()
            return dict(connection.execute("SELECT * FROM task_queue_claims WHERE claim_id=?", (claim["claim_id"],)).fetchone())

    def current_shared_task_claim(
        self, chat_id: str, open_id: str, task_id: str, *, evidence_id: str | None = None,
    ) -> dict[str, Any]:
        tid = _identifier(task_id, "task_id")
        with self._connect() as connection:
            _, user, _ = self._shared_task_context(connection, chat_id, open_id, tid)
            claim = connection.execute(
                "SELECT * FROM task_queue_claims WHERE task_id=? AND status IN ('active','submitted') AND user_id=?",
                (tid, user["user_id"]),
            ).fetchone()
            if claim is None or (claim["status"] == "submitted" and claim["evidence_id"] != evidence_id):
                raise AuthorizationDenied("只有当前领取者可以提交")
            return dict(claim)

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
        required = "read" if action in {"read", "notify", "history_search"} else "write"
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
        """Import an owned Session and assign an owner-scoped short alias."""

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
                    slot = _auto_group_slot(
                        str(session["owner_user_id"]),
                        str(session["owner_name"]),
                        used_slots,
                    )
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

    def set_history_search(self, chat_id: str, owner_reference: str, session_id: str, *, enabled: bool) -> dict[str, Any]:
        sid = _text(session_id, "session_id", 80).lower()
        if not SESSION_ID.fullmatch(sid):
            raise RegistryError("session_id 必须是 Codex UUID")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            group = self._group_row(connection, chat_id)
            owner = self._user_row(connection, owner_reference)
            session = connection.execute(
                "SELECT i.user_id FROM sessions s JOIN installations i ON i.installation_id=s.installation_id "
                "WHERE s.session_id=?", (sid,),
            ).fetchone()
            member = connection.execute(
                "SELECT 1 FROM group_members WHERE group_id=? AND user_id=?",
                (group["group_id"], owner["user_id"]),
            ).fetchone()
            share = connection.execute(
                "SELECT 1 FROM session_shares WHERE group_id=? AND session_id=?",
                (group["group_id"], sid),
            ).fetchone()
            if owner["status"] != "approved" or session is None or session["user_id"] != owner["user_id"] or member is None or share is None:
                raise AuthorizationDenied("只有已共享 Session 的所有者可以设置历史检索")
            if enabled:
                connection.execute(
                    "INSERT INTO session_history_shares(group_id,session_id,enabled_by,enabled_at) VALUES(?,?,?,?) "
                    "ON CONFLICT(group_id,session_id) DO UPDATE SET enabled_by=excluded.enabled_by, enabled_at=excluded.enabled_at",
                    (group["group_id"], sid, owner["user_id"], now()),
                )
            else:
                connection.execute(
                    "DELETE FROM session_history_shares WHERE group_id=? AND session_id=?",
                    (group["group_id"], sid),
                )
            self._audit(connection, str(owner["feishu_open_id"]), "set_history_search", "session", sid, str(enabled))
            connection.commit()
            return {"group_id": str(group["group_id"]), "session_id": sid, "enabled": enabled}

    def authorize_history_search(self, open_id: str, chat_id: str, session_id: str) -> dict[str, Any]:
        if not str(chat_id or "").strip():
            raise AuthorizationDenied("历史检索只能在群组中使用")
        decision = self.authorize(open_id, chat_id, session_id, "read")
        with self._connect() as connection:
            enabled = connection.execute(
                "SELECT 1 FROM session_history_shares WHERE group_id=? AND session_id=?",
                (decision["group_id"], decision["session_id"]),
            ).fetchone()
            if enabled is None:
                raise AuthorizationDenied("Session 所有者尚未开放历史检索")
        return decision

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
        required = "read" if action in {"read", "notify", "history_search"} else "write"
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
        if action == "history_search" and not task_id:
            decision = self.authorize_history_search(open_id, str(chat_id or ""), session_id)
            task_reference = None
        elif task_id:
            decision = self.authorize_task(open_id, chat_id, task_id, session_id, action)
            task_reference = str(decision["task_id"])
        else:
            decision = self.authorize(open_id, chat_id, session_id, action)
            task_reference = None
        timestamp = now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if action == "history_search":
                allowed = connection.execute(
                    "SELECT 1 FROM session_history_shares hs JOIN session_shares ss "
                    "ON ss.group_id=hs.group_id AND ss.session_id=hs.session_id "
                    "WHERE hs.group_id=? AND hs.session_id=?",
                    (decision["group_id"], decision["session_id"]),
                ).fetchone()
                if allowed is None:
                    raise AuthorizationDenied("历史检索授权已撤销")
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
                connection.execute(
                    "UPDATE tasks SET status = CASE WHEN status = 'planned' THEN 'running' ELSE status END, "
                    "updated_at = ? WHERE task_id = ?",
                    (timestamp, task_reference),
                )
                self._append_task_event_in_connection(
                    connection,
                    task_reference,
                    "task.started",
                    {"message_id": message_id, "action": action},
                    session_id=str(decision["session_id"]),
                    actor_open_id=open_id,
                    idempotency_key=f"command:{message_id}:started",
                    timestamp=timestamp,
                )
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
                if status == "failed":
                    connection.execute(
                        "UPDATE tasks SET status = 'failed', updated_at = ? WHERE task_id = ?",
                        (timestamp, str(row["task_id"])),
                    )
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
