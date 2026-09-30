#!/usr/bin/env python3
"""Feishu long-connection consumer for the published group-chat protocol."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from qyp_multi_feishu import authorize_group_event, ensure_group_member, registered_group, registry, shared_session
from qyp_multi_registry import AuthorizationDenied, RegistryError
from qyp_multi_transport import TransportStore


LOG = logging.getLogger("tls.feishu_group_ingress")
SESSION_ID = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$", re.I)
EXPLICIT_SESSION = re.compile(r"^/session\s+(\S+)\s+(.+)$", re.I | re.S)
TASK_CREATE = re.compile(r"^/task\s+([A-Za-z0-9_.:-]{1,160})\s+(\S+)\s+(.+?)\s+\|\s+(.+)$", re.I | re.S)
TASK_ACTION = re.compile(r"^/(claim|release|approve)\s+([A-Za-z0-9_.:-]{1,160})$", re.I)
TASK_SUBMIT = re.compile(r"^/submit\s+([A-Za-z0-9_.:-]{1,160})\s+(.+)$", re.I | re.S)
TASK_VERIFY = re.compile(r"^/verify\s+([A-Za-z0-9_.:-]{1,160})\s+([A-Za-z0-9_.:-]{1,160})$", re.I)
HISTORY_TOGGLE = re.compile(r"^/history-(on|off)\s+(\S+)$", re.I)
HISTORY_SEARCH = re.compile(r"^/history\s+(\S+)\s+(.+)$", re.I | re.S)
MAX_REPLY = 4000


class RouteStore:
    """Durable inbox and bot-message routes, keyed by Feishu message IDs."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        created_parent = not self.path.parent.exists()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if created_parent:
            os.chmod(self.path.parent, 0o700)
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS inbox (
                    message_id TEXT PRIMARY KEY, event_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending', received_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS replies (
                    source_message_id TEXT PRIMARY KEY, reply_message_id TEXT UNIQUE NOT NULL,
                    chat_id TEXT NOT NULL, session_id TEXT NOT NULL, created_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS inbox_pending ON inbox(status, received_at);
            """)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        os.chmod(self.path, 0o600)
        return db

    def receive(self, event: dict[str, str]) -> None:
        with self._connect() as db:
            db.execute(
                "INSERT OR IGNORE INTO inbox(message_id,event_json,received_at) VALUES(?,?,?)",
                (event["message_id"], json.dumps(event, ensure_ascii=False), int(time.time())),
            )

    def next_message(self) -> dict[str, str] | None:
        with self._connect() as db:
            row = db.execute("SELECT event_json FROM inbox WHERE status='pending' ORDER BY received_at, message_id LIMIT 1").fetchone()
        return json.loads(row[0]) if row else None

    def finish(self, message_id: str) -> None:
        with self._connect() as db:
            db.execute("UPDATE inbox SET status='done' WHERE message_id=?", (message_id,))

    def route(self, reply_message_id: str, chat_id: str) -> str:
        with self._connect() as db:
            row = db.execute(
                "SELECT session_id FROM replies WHERE reply_message_id=? AND chat_id=?",
                (reply_message_id, chat_id),
            ).fetchone()
        return str(row[0]) if row else ""

    def bind(self, source_id: str, reply_id: str, chat_id: str, session_id: str) -> None:
        with self._connect() as db:
            db.execute(
                "INSERT INTO replies(source_message_id,reply_message_id,chat_id,session_id,created_at) "
                "VALUES(?,?,?,?,?) ON CONFLICT(source_message_id) DO UPDATE SET "
                "reply_message_id=excluded.reply_message_id",
                (source_id, reply_id, chat_id, session_id, int(time.time())),
            )


def parse_message(data: Any) -> dict[str, str] | None:
    event = getattr(data, "event", None)
    sender = getattr(event, "sender", None)
    message = getattr(event, "message", None)
    sender_id = getattr(sender, "sender_id", None)
    if getattr(sender, "sender_type", "") != "user" or getattr(message, "chat_type", "") != "group":
        return None
    if getattr(message, "message_type", "") != "text":
        return None
    try:
        content = json.loads(str(getattr(message, "content", "") or "{}"))
    except (ValueError, TypeError):
        return None
    if not isinstance(content, dict):
        return None
    text = str(content.get("text") or "")
    mentions = getattr(message, "mentions", None) or []
    bot_open_id = os.environ.get("FEISHU_BOT_OPEN_ID", "").strip()
    addressed = any(
        bot_open_id and str(getattr(getattr(mention, "id", None), "open_id", "") or "") == bot_open_id
        for mention in mentions
    )
    for mention in mentions:
        key = str(getattr(mention, "key", "") or "")
        if key:
            text = text.replace(key, "")
    result = {
        "open_id": str(getattr(sender_id, "open_id", "") or ""),
        "chat_id": str(getattr(message, "chat_id", "") or ""),
        "chat_type": "group",
        "message_id": str(getattr(message, "message_id", "") or ""),
        "parent_id": str(getattr(message, "parent_id", "") or ""),
        "root_id": str(getattr(message, "root_id", "") or ""),
        "text": text.strip(),
        "mentioned": "1" if addressed else "",
    }
    if not all(result[key] for key in ("open_id", "chat_id", "message_id", "text")):
        return None
    return result


def _team_command(event: dict[str, str], transport: TransportStore) -> tuple[str, str] | None:
    text = event["text"]
    selected = registry()
    chat_id, open_id = event["chat_id"], event["open_id"]
    if text.lower() == "/tasks":
        tasks = selected.task_queue(chat_id, open_id)
        lines = [
            f"{task['task_id']} | {task['name']} | {task['status']} | "
            f"{task.get('claimant') or 'available'}"
            for task in tasks[:20]
        ]
        return "task-list", "\n".join(lines) if lines else "当前没有共享任务。"
    match = TASK_CREATE.fullmatch(text)
    if match:
        task_id, session_id, objective, acceptance = match.groups()
        created = selected.create_group_task(
            chat_id, open_id, session_id, objective.strip(),
            {"objective": objective.strip(), "acceptance": [acceptance.strip()], "team_queue": True},
            task_id=task_id, idempotency_key=event["message_id"],
        )
        return "task-created", f"任务已创建：{created['task_id']}。验收标准：{acceptance.strip()}"
    match = TASK_ACTION.fullmatch(text)
    if match:
        action, task_id = match.groups()
        action = action.lower()
        if action == "claim":
            claim = selected.claim_shared_task(chat_id, open_id, task_id)
            return "task-claimed", f"已领取 {task_id}：{claim['claim_id']}"
        if action == "release":
            selected.release_shared_task(chat_id, open_id, task_id)
            return "task-released", f"{task_id} 已回到待领取队列。"
        visible = {task["task_id"] for task in selected.task_queue(chat_id, open_id)}
        if task_id not in visible:
            raise AuthorizationDenied("任务未共享到当前群")
        approved = selected.approve_task(task_id, open_id)
        credit = approved.get("credit")
        return "task-approved", f"{task_id} 已验收。Credit: {credit['user_id'] if credit else '无领取记录'}"
    match = TASK_SUBMIT.fullmatch(text)
    if match:
        task_id, source = match.groups()
        evidence_id = "evidence-" + hashlib.sha256(event["message_id"].encode()).hexdigest()[:16]
        selected.current_shared_task_claim(chat_id, open_id, task_id, evidence_id=evidence_id)
        existing = next((item for item in selected.list_evidence(task_id) if item["evidence_id"] == evidence_id), None)
        if existing is None:
            selected.record_evidence(
                task_id, "submission", "Task submission", evidence_id=evidence_id,
                uri=source.strip()[:1000] if source.strip().startswith(("https://", "commit:", "sha256:")) else "",
                summary=source.strip()[:2000], created_by=open_id,
            )
        selected.submit_shared_task(chat_id, open_id, task_id, evidence_id)
        return "task-submitted", f"{task_id} 已提交证据 {evidence_id}，等待负责人验证和验收。"
    match = TASK_VERIFY.fullmatch(text)
    if match:
        task_id, evidence_id = match.groups()
        visible = {task["task_id"] for task in selected.task_queue(chat_id, open_id)}
        if task_id not in visible:
            raise AuthorizationDenied("任务未共享到当前群")
        selected.verify_evidence_as_task_owner(task_id, evidence_id, open_id)
        return "task-verified", f"证据 {evidence_id} 已验证。"
    match = HISTORY_TOGGLE.fullmatch(text)
    if match:
        mode, session_id = match.groups()
        result = selected.set_history_search(chat_id, open_id, session_id, enabled=mode.lower() == "on")
        return "history-toggle", f"历史检索已{'开启' if result['enabled'] else '关闭'}：{result['session_id']}"
    match = HISTORY_SEARCH.fullmatch(text)
    if match:
        session_id, query = match.groups()
        selected.authorize_history_search(open_id, chat_id, session_id)
        queued = transport.enqueue(
            message_id=event["message_id"], open_id=open_id, chat_id=chat_id,
            session_id=session_id, text=query.strip(), action="history_search", extra={"query": query.strip()},
        )
        return ("duplicate" if queued.get("duplicate") else "queued"), ""
    return None


def process_message(event: dict[str, str], routes: RouteStore, transport: TransportStore, client: Any | None = None) -> str:
    chat_id, open_id = event["chat_id"], event["open_id"]
    if registered_group(chat_id) is None:
        return "ignored"
    reply_target = routes.route(event.get("parent_id", ""), chat_id) or routes.route(event.get("root_id", ""), chat_id)
    if not event.get("mentioned") and not reply_target:
        return "ignored"
    ensure_group_member(chat_id, open_id)
    management = _team_command(event, transport)
    if management is not None:
        status, reply = management
        if reply and client is not None:
            send_reply(client, event["message_id"], reply, "team-command:" + event["message_id"])
        return status
    text = event["text"]
    match = EXPLICIT_SESSION.fullmatch(text)
    if match:
        requested, text = match.groups()
        if not SESSION_ID.fullmatch(requested):
            raise RegistryError("invalid session ID")
        session_id = requested.lower()
    elif reply_target:
        session_id = reply_target
    else:
        session_id = str(shared_session(chat_id, open_id)["session_id"])
    route = authorize_group_event(event, session_id, action="write")
    result = transport.enqueue(
        message_id=event["message_id"], open_id=route.open_id,
        chat_id=route.chat_id, session_id=route.session_id, text=text,
    )
    return "duplicate" if result.get("duplicate") else "queued"


def _reply_id(response: Any) -> str:
    data = getattr(response, "data", None)
    return str((data.get("message_id") if isinstance(data, dict) else getattr(data, "message_id", "")) or "")


def send_reply(client: Any, source_id: str, text: str, dedupe_key: str) -> str:
    from lark_oapi.api.im.v1.model.reply_message_request import ReplyMessageRequest
    from lark_oapi.api.im.v1.model.reply_message_request_body import ReplyMessageRequestBody

    body = (ReplyMessageRequestBody.builder()
            .content(json.dumps({"text": text[:MAX_REPLY]}, ensure_ascii=False))
            .msg_type("text").reply_in_thread(False)
            .uuid(hashlib.sha256(dedupe_key.encode()).hexdigest()[:48]).build())
    request = ReplyMessageRequest.builder().message_id(source_id).request_body(body).build()
    response = client.im.v1.message.reply(request)
    if not response.success() or not _reply_id(response):
        raise RuntimeError(f"Feishu reply failed: {getattr(response, 'code', 'unknown')}")
    return _reply_id(response)


def publish_one(client: Any, routes: RouteStore, transport: TransportStore) -> bool:
    pending = transport.next_event()
    if pending is None:
        return False
    claimed = transport.claim_event(int(pending["event_id"]))
    if claimed is None:
        return False
    payload = claimed["payload"]
    source_id = str(payload["message_id"])
    result = payload.get("result") or {}
    answer = str(result.get("answer") or result.get("text") or payload.get("error") or "Codex completed")
    if payload.get("request", {}).get("action") == "history_search":
        try:
            transport.registry.authorize_history_search(str(payload["open_id"]), str(payload["chat_id"]), str(payload["session_id"]))
        except RegistryError:
            answer = "历史检索授权已撤销，结果未发送。"
    try:
        reply_id = send_reply(client, source_id, answer, "agent-event:" + str(claimed["event_id"]))
        routes.bind(source_id, reply_id, str(payload["chat_id"]), str(payload["session_id"]))
        transport.complete_event(int(claimed["event_id"]), status="sent")
    except Exception as exc:
        LOG.warning("completion delivery failed for event %s: %s", claimed["event_id"], type(exc).__name__)
        transport.complete_event(int(claimed["event_id"]), status="failed", error=type(exc).__name__, retry_after=30)
    return True


def process_loop(client: Any, routes: RouteStore, transport: TransportStore, stop: threading.Event) -> None:
    while not stop.is_set():
        progressed = False
        event = routes.next_message()
        if event is not None:
            try:
                process_message(event, routes, transport, client)
            except (AuthorizationDenied, RegistryError) as exc:
                LOG.info("group command rejected: %s", exc)
                try:
                    if event["text"].startswith("/"):
                        send_reply(client, event["message_id"], str(exc)[:300], "team-error:" + event["message_id"])
                    routes.finish(event["message_id"])
                except Exception:
                    LOG.exception("group error reply failed; inbox item retained")
            except Exception:
                LOG.exception("group command processing failed; inbox item retained")
                stop.wait(2.0)
            else:
                routes.finish(event["message_id"])
            progressed = True
        try:
            progressed = publish_one(client, routes, transport) or progressed
        except Exception:
            LOG.exception("completion outbox processing failed")
        stop.wait(0.1 if progressed else 0.5)


def main() -> int:
    parser = argparse.ArgumentParser(description="TLS Feishu group ingress")
    parser.add_argument("--routes-db", default=os.environ.get("TLS_FEISHU_ROUTES_DB", str(Path.home() / ".local/state/tls-group-chat/routes.sqlite3")))
    args = parser.parse_args()
    app_id, app_secret = os.environ.get("FEISHU_APP_ID", ""), os.environ.get("FEISHU_APP_SECRET", "")
    if not app_id or not app_secret or not os.environ.get("FEISHU_BOT_OPEN_ID"):
        parser.error("FEISHU_APP_ID, FEISHU_APP_SECRET and FEISHU_BOT_OPEN_ID are required")
    import lark_oapi as lark
    from lark_oapi.api.im.v1 import P2ImMessageReceiveV1
    from lark_oapi.event.dispatcher_handler import EventDispatcherHandler

    logging.basicConfig(level=logging.INFO)
    routes, transport = RouteStore(args.routes_db), TransportStore()
    client = lark.Client.builder().app_id(app_id).app_secret(app_secret).build()

    def receive(data: P2ImMessageReceiveV1) -> None:
        event = parse_message(data)
        if event is not None:
            routes.receive(event)

    handler = EventDispatcherHandler.builder("", "").register_p2_im_message_receive_v1(receive).build()
    stop = threading.Event()
    threading.Thread(target=process_loop, args=(client, routes, transport, stop), daemon=True).start()
    lark.ws.Client(app_id, app_secret, event_handler=handler).start()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
