#!/usr/bin/env python3
"""Feishu-facing bridge for the qyp TLS multi-user registry.

This module deliberately has no Lark SDK dependency.  The running TLS
ingress can use it to authorize a group event, while the registry remains
transport-neutral and the private single-user path stays unchanged.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from qyp_multi_adapter import Route, claim_event, route_event
from qyp_multi_registry import AuthorizationDenied, Registry, RegistryError


DEFAULT_DB = Path.home() / ".local/state/qyp-tls-multi/multi.sqlite3"


def registry(path: str | Path | None = None) -> Registry:
    """Create a registry using the service override or the qyp default DB."""

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


def task_dashboard(
    chat_id: str,
    open_id: str,
    *,
    path: str | Path | None = None,
) -> dict[str, Any]:
    """Return tasks explicitly shared to a member-visible group."""

    return registry(path).group_tasks(str(chat_id), str(open_id))


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
