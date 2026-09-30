#!/usr/bin/env python3
"""Feishu-facing bridge for the TLS multi-user registry.

This module deliberately has no Lark SDK dependency.  The running TLS
ingress can use it to authorize a group event, while the registry remains
transport-neutral and the private single-user path stays unchanged.
"""

from __future__ import annotations

import os
import hashlib
from pathlib import Path
from typing import Any

from qyp_multi_adapter import Route, claim_event, route_event
from qyp_multi_registry import AuthorizationDenied, Registry, RegistryError


DEFAULT_DB = Path.home() / ".local/state/tls-group-chat/multi.sqlite3"


def registry(path: str | Path | None = None) -> Registry:
    """Create a registry using the service override or the default DB."""

    selected = Path(path) if path is not None else Path(os.environ.get("QYP_TLS_MULTI_DB", DEFAULT_DB))
    return Registry(selected)


def registered_group(chat_id: str, *, path: str | Path | None = None) -> dict[str, Any] | None:
    """Return a group record when ``chat_id`` is explicitly registered."""

    chat = str(chat_id or "").strip()
    if not chat:
        return None
    try:
        return registry(path).group_dashboard(chat)
    except RegistryError:
        return None


def member_dashboard(
    chat_id: str,
    open_id: str,
    *,
    path: str | Path | None = None,
) -> dict[str, Any]:
    """Enroll the Feishu sender, then return the shared group dashboard."""

    selected = registry(path)
    selected.ensure_group_member(str(chat_id), str(open_id))
    return selected.group_dashboard(str(chat_id), str(open_id))


def ensure_group_member(
    chat_id: str,
    open_id: str,
    *,
    display_name: str = "",
    path: str | Path | None = None,
) -> dict[str, Any]:
    """Enroll a sender as a member of an already-registered Feishu group."""

    return registry(path).ensure_group_member(str(chat_id), str(open_id), display_name=display_name)


def ensure_private_user(
    open_id: str,
    *,
    display_name: str = "",
    path: str | Path | None = None,
) -> dict[str, Any]:
    """Register a private-chat sender without granting group membership."""

    return registry(path).ensure_private_user(str(open_id), display_name=display_name)


def task_dashboard(
    chat_id: str,
    open_id: str,
    *,
    path: str | Path | None = None,
) -> dict[str, Any]:
    """Return tasks explicitly shared to a member-visible group."""

    return registry(path).group_tasks(str(chat_id), str(open_id))


def task_progress(
    chat_id: str,
    open_id: str,
    task_id: str,
    *,
    session_id: str | None = None,
    path: str | Path | None = None,
) -> dict[str, Any]:
    """Return progress only for a task visible in the requesting group."""

    shared_task(chat_id, open_id, task_id, path=path)
    return registry(path).task_progress(task_id, session_id=session_id)


def task_evidence(
    chat_id: str,
    open_id: str,
    task_id: str,
    *,
    session_id: str | None = None,
    path: str | Path | None = None,
) -> dict[str, Any]:
    """Return the read-only evidence graph for a task visible in the group."""

    task = shared_task(chat_id, open_id, task_id, path=path)
    selected = registry(path)
    return {
        "task": task,
        "progress": selected.task_progress(task_id, session_id=session_id),
        "evidence": selected.list_evidence(str(task_id)),
    }


def create_group_task(
    chat_id: str,
    open_id: str,
    task_id: str,
    session_id: str,
    objective: str,
    *,
    path: str | Path | None = None,
) -> dict[str, Any]:
    """Create a minimal task contract and bind it to one writable Session."""

    selected = registry(path)
    selected.ensure_group_member(str(chat_id), str(open_id))
    return selected.create_group_task(
        str(chat_id),
        str(open_id),
        str(session_id),
        str(task_id),
        {"objective": str(objective), "acceptance": ["提交并验证至少一条证据"]},
        task_id=str(task_id),
    )


def submit_task_evidence(
    chat_id: str,
    open_id: str,
    task_id: str,
    session_id: str,
    source: str,
    *,
    path: str | Path | None = None,
) -> dict[str, Any]:
    """Attach user-provided evidence after task/session write authorization."""

    selected = registry(path)
    shared_task(chat_id, open_id, task_id, path=path)
    selected.authorize_task(open_id, chat_id, task_id, session_id, "write")
    value = str(source).strip()
    uri = value if "://" in value or value.startswith(("git@", "commit:", "sha256:")) else ""
    summary = "" if uri else value
    return selected.record_evidence(
        task_id,
        "user-submitted",
        value[:120],
        uri=uri,
        summary=summary,
        session_id=session_id,
        created_by=open_id,
    )


def submit_agent_evidence(
    task_id: str,
    session_id: str,
    answer: str,
    message_id: str,
    *,
    created_by: str = "",
    path: str | Path | None = None,
) -> dict[str, Any]:
    """Persist one deterministic Agent result as unverified evidence."""

    value = str(answer or "").strip() or "Agent completed without a readable answer."
    message = str(message_id or "").strip()
    evidence_id = f"agent-result-{message}"[:160]
    selected = registry(path)
    try:
        return selected.record_evidence(
            str(task_id),
            "agent-result",
            "Agent 完成结果",
            content_hash="sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest(),
            summary=value[:4000],
            session_id=str(session_id),
            evidence_id=evidence_id,
            created_by=str(created_by or ""),
        )
    except RegistryError as error:
        if "evidence_id 已存在" not in str(error):
            raise
        matches = [item for item in selected.list_evidence(str(task_id)) if item.get("evidence_id") == evidence_id]
        if not matches:
            raise
        return matches[0]


def bind_group_task_session(
    chat_id: str,
    open_id: str,
    task_id: str,
    session_id: str,
    *,
    path: str | Path | None = None,
) -> dict[str, Any]:
    """Bind an existing owner task to a writable Session in its group."""

    selected = registry(path)
    shared_task(chat_id, open_id, task_id, path=path)
    return selected.bind_group_task_session(str(chat_id), str(open_id), str(task_id), str(session_id))


def verify_task_evidence(
    chat_id: str,
    open_id: str,
    task_id: str,
    evidence_id: str,
    *,
    path: str | Path | None = None,
) -> dict[str, Any]:
    shared_task(chat_id, open_id, task_id, path=path)
    return registry(path).verify_evidence_as_task_owner(task_id, evidence_id, open_id)


def approve_task(
    chat_id: str,
    open_id: str,
    task_id: str,
    *,
    session_id: str | None = None,
    path: str | Path | None = None,
) -> dict[str, Any]:
    shared_task(chat_id, open_id, task_id, path=path)
    return registry(path).approve_task(task_id, open_id, session_id=session_id)


def shared_task(
    chat_id: str,
    open_id: str,
    task_id: str,
    *,
    path: str | Path | None = None,
) -> dict[str, Any]:
    requested = str(task_id or "").strip()
    if not requested:
        raise RegistryError("task_id 不能为空")
    tasks = list(task_dashboard(chat_id, open_id, path=path).get("tasks", []))
    matches = [item for item in tasks if str(item.get("task_id", "")) == requested]
    if len(matches) != 1:
        raise AuthorizationDenied("该 task 未共享到当前群组")
    return matches[0]


def shared_session(
    chat_id: str,
    open_id: str,
    session_id: str | None = None,
    *,
    path: str | Path | None = None,
) -> dict[str, Any]:
    """Resolve one explicitly shared Session for a group event.

    A caller may omit the Session only while exactly one Session is shared;
    this keeps the first group test simple without guessing when the group
    later contains multiple Sessions.
    """

    dashboard = member_dashboard(chat_id, open_id, path=path)
    sessions = list(dashboard.get("sessions", []))
    requested = str(session_id or "").strip().lower()
    if requested:
        matches = [item for item in sessions if str(item.get("session_id", "")).lower() == requested]
    else:
        matches = sessions if len(sessions) == 1 else []
    if len(matches) != 1:
        if not sessions:
            raise AuthorizationDenied("群组尚未共享可用的 Session")
        raise RegistryError("群组包含多个 Session，请明确选择目标")
    return matches[0]


def add_member_session(
    chat_id: str,
    open_id: str,
    session_id: str,
    *,
    access: str = "write",
    slot_alias: str | None = None,
    path: str | Path | None = None,
) -> dict[str, Any]:
    """Import the sender's Session and assign a persistent owner-scoped slot."""

    selected = registry(path)
    selected.ensure_group_member(str(chat_id), str(open_id))
    return selected.add_session_to_group(
        str(chat_id),
        str(open_id),
        str(session_id),
        access=access,
        slot_alias=slot_alias,
    )


def authorize_group_event(
    event: dict[str, Any],
    session_id: str,
    *,
    action: str = "write",
    task_id: str | None = None,
    path: str | Path | None = None,
) -> Route:
    """Authorize one Feishu group event through the shared-session policy."""

    if str(event.get("chat_type", "")).strip().lower() != "group":
        raise AuthorizationDenied("多人路由只能处理群聊事件")
    chat_id = str(event.get("chat_id", "")).strip()
    if registered_group(chat_id, path=path) is None:
        raise AuthorizationDenied("该群组尚未启用多人模式")
    return route_event(registry(path), event, session_id, action=action, task_id=task_id)


def claim_group_event(
    event: dict[str, Any],
    session_id: str,
    *,
    action: str = "write",
    lease_seconds: int = 120,
    task_id: str | None = None,
    path: str | Path | None = None,
) -> tuple[Route, bool]:
    """Authorize and atomically deduplicate one group event."""

    if str(event.get("chat_type", "")).strip().lower() != "group":
        raise AuthorizationDenied("多人路由只能处理群聊事件")
    chat_id = str(event.get("chat_id", "")).strip()
    if registered_group(chat_id, path=path) is None:
        raise AuthorizationDenied("该群组尚未启用多人模式")
    return claim_event(
        registry(path),
        event,
        session_id,
        action=action,
        lease_seconds=lease_seconds,
        task_id=task_id,
    )


def complete_group_event(
    message_id: str,
    *,
    status: str = "completed",
    path: str | Path | None = None,
) -> dict[str, Any]:
    """Close a previously claimed group event after delivery."""

    return registry(path).complete_command(str(message_id), status)


def next_task_event_delivery(*, path: str | Path | None = None) -> dict[str, Any] | None:
    return registry(path).next_task_event_delivery()


def claim_task_event_delivery(
    delivery_id: int,
    *,
    lease_seconds: int = 120,
    path: str | Path | None = None,
) -> dict[str, Any] | None:
    return registry(path).claim_task_event_delivery(delivery_id, lease_seconds=lease_seconds)


def task_event_delivery(delivery_id: int, *, path: str | Path | None = None) -> dict[str, Any]:
    return registry(path).task_event_delivery(delivery_id)


def complete_task_event_delivery(
    delivery_id: int,
    *,
    status: str = "sent",
    error: str = "",
    retry_after: int = 60,
    path: str | Path | None = None,
) -> dict[str, Any]:
    return registry(path).complete_task_event_delivery(
        delivery_id,
        status=status,
        error=error,
        retry_after=retry_after,
    )


def group_is_member(chat_id: str, open_id: str, *, path: str | Path | None = None) -> bool:
    """Accept any live sender from a registered Feishu group.

    The Feishu event itself proves that the sender is in the group.  We mirror
    that fact into the registry before the normal dashboard/authorization
    checks, while preserving disabled-user rejection.
    """

    try:
        member_dashboard(chat_id, open_id, path=path)
    except (AuthorizationDenied, RegistryError):
        return False
    return True
