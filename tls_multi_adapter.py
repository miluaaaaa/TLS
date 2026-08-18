"""Transport-neutral adapter for wiring the TLS registry into Feishu ingress."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tls_multi_registry import AuthorizationDenied, Registry, RegistryError


@dataclass(frozen=True)
class Route:
    """A validated destination for one incoming Feishu message."""

    open_id: str
    chat_id: str
    session_id: str
    scope: str
    access: str
    label: str
    task_id: str = ""


def route_event(
    registry: Registry,
    event: dict[str, Any],
    session_id: str,
    *,
    action: str = "write",
    task_id: str | None = None,
) -> Route:
    """Authorize an event and return a route safe for the transport layer.

    A missing group chat id means private scope.  Group events never fall back
    to the user's active private session; the caller must provide the session
    selected by the group dashboard/card.
    """

    open_id = str(event.get("open_id", "")).strip()
    chat_type = str(event.get("chat_type", "p2p")).strip().lower()
    chat_id = str(event.get("chat_id", "")).strip() if chat_type == "group" else ""
    decision = (
        registry.authorize_task(open_id, chat_id, task_id, session_id, action)
        if task_id
        else registry.authorize(open_id, chat_id, session_id, action)
    )
    return Route(
        open_id=open_id,
        chat_id=chat_id,
        session_id=str(decision["session_id"]),
        scope=str(decision["scope"]),
        access=str(decision.get("access", "write")),
        label=str(decision.get("label", "")),
        task_id=str(decision.get("task_id", task_id or "")),
    )


def claim_event(
    registry: Registry,
    event: dict[str, Any],
    session_id: str,
    *,
    action: str = "write",
    lease_seconds: int = 120,
    task_id: str | None = None,
) -> tuple[Route, bool]:
    """Authorize and atomically claim an event by its Feishu message id."""

    route = route_event(registry, event, session_id, action=action, task_id=task_id)
    message_id = str(event.get("message_id", "")).strip()
    if not message_id:
        raise RegistryError("Feishu event 缺少 message_id")
    claimed = registry.claim_command(
        message_id,
        route.open_id,
        route.chat_id,
        route.session_id,
        action=action,
        lease_seconds=lease_seconds,
        task_id=route.task_id or None,
    )
    return route, claimed


def group_dashboard(registry: Registry, event: dict[str, Any]) -> dict[str, Any]:
    """Return a dashboard only when the caller is a member of that group."""

    if str(event.get("chat_type", "")).strip().lower() != "group":
        raise AuthorizationDenied("多人控制台只能在群聊上下文打开")
    open_id = str(event.get("open_id", "")).strip()
    chat_id = str(event.get("chat_id", "")).strip()
    return registry.group_dashboard(chat_id, open_id)
