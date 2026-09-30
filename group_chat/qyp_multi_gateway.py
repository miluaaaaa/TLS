#!/usr/bin/env python3
"""Small standard-library HTTP gateway for local TLS Agents.

TLS Agents make outbound HTTPS requests to this service.  The gateway never
starts Codex and never reads a user's transcript; it only exposes the durable
pairing, heartbeat, command, and result endpoints backed by SQLite.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import secrets
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from qyp_multi_registry import RegistryError
from qyp_multi_transport import (
    DEFAULT_RECOVERY_SCAN_SECONDS,
    DEFAULT_SESSION_FRESHNESS_SECONDS,
    DEFAULT_RELEASE_ID,
    PROTOCOL_VERSION,
    TransportError,
    TransportStore,
)


MAX_BODY = 256 * 1024
MAX_MEDIA_BYTES = 20 * 1024 * 1024
MEDIA_ID = re.compile(r"^[0-9a-f]{64}$")
MEDIA_SUFFIXES = {".png", ".jpg", ".gif", ".webp", ".bmp"}


def media_root() -> Path:
    return Path(
        os.environ.get(
            "TLS_FEISHU_STATE_DIR",
            str(Path.home() / ".local/state/tls/feishu-direct"),
        )
    ) / "media"


def media_file(media_id: str) -> Path | None:
    if not MEDIA_ID.fullmatch(media_id):
        return None
    root = media_root()
    try:
        candidates = [
            path
            for path in root.glob(f"{media_id}.*")
            if path.is_file() and not path.is_symlink() and path.suffix.casefold() in MEDIA_SUFFIXES
        ]
    except OSError:
        return None
    return candidates[0] if len(candidates) == 1 else None


def _json_bytes(payload: object) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class GatewayHandler(BaseHTTPRequestHandler):
    server_version = "TLSAgentGateway/1"

    @property
    def store(self) -> TransportStore:
        return self.server.store  # type: ignore[attr-defined]

    def _request_id(self) -> str:
        return self.headers.get("x-request-id", "")[:80] or secrets.token_hex(8)

    def _write(self, status: int, payload: object) -> None:
        body = _json_bytes(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Request-ID", self._request_id())
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, error: str) -> None:
        self._write(status, {"ok": False, "error": error})

    def _write_media(self, path: Path) -> None:
        try:
            size = path.stat().st_size
            if size <= 0 or size > MAX_MEDIA_BYTES:
                self._error(HTTPStatus.NOT_FOUND, "media-not-found")
                return
            content_type = {
                ".png": "image/png",
                ".jpg": "image/jpeg",
                ".gif": "image/gif",
                ".webp": "image/webp",
                ".bmp": "image/bmp",
            }[path.suffix.casefold()]
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(size))
            self.send_header("X-Request-ID", self._request_id())
            self.end_headers()
            with path.open("rb") as handle:
                while chunk := handle.read(64 * 1024):
                    self.wfile.write(chunk)
        except (KeyError, OSError):
            self._error(HTTPStatus.NOT_FOUND, "media-not-found")

    def _read_json(self) -> dict[str, Any]:
        length_text = self.headers.get("Content-Length", "")
        try:
            length = int(length_text)
        except ValueError as exc:
            raise TransportError("Content-Length 无效") from exc
        if length < 0 or length > MAX_BODY:
            raise TransportError("请求体过大")
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TransportError("请求 JSON 无效") from exc
        if not isinstance(payload, dict):
            raise TransportError("请求 JSON 必须是对象")
        return payload

    def _token(self) -> str:
        value = self.headers.get("Authorization", "")
        scheme, _, token = value.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            raise PermissionError
        return token.strip()

    def _dispatch_error(self, error: BaseException) -> None:
        if isinstance(error, PermissionError):
            self._error(HTTPStatus.UNAUTHORIZED, "unauthorized")
        elif isinstance(error, (TransportError, RegistryError, ValueError)):
            self._error(HTTPStatus.BAD_REQUEST, str(error)[:240] or "bad-request")
        else:
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "internal-error")

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path.rstrip("/") or "/"
        try:
            if path == "/health":
                self._write(HTTPStatus.OK, {
                    "ok": True,
                    "service": "tls-agent-gateway",
                    "version": 2,
                    "protocol_version": PROTOCOL_VERSION,
                    "release_id": os.environ.get("TLS_RELEASE_ID", DEFAULT_RELEASE_ID),
                })
                return
            if path == "/v1/agent/commands":
                token = self._token()
                query = parse_qs(urlsplit(self.path).query)
                try:
                    limit = int(query.get("limit", ["10"])[0])
                except ValueError as exc:
                    raise TransportError("limit 无效") from exc
                self._write(HTTPStatus.OK, {"ok": True, "commands": self.store.poll(token, limit=limit)})
                return
            media_prefix = "/v1/agent/media/"
            if path.startswith(media_prefix):
                self.store.info(self._token())
                media_id = path[len(media_prefix) :]
                target = media_file(media_id)
                if target is None:
                    self._error(HTTPStatus.NOT_FOUND, "media-not-found")
                    return
                self._write_media(target)
                return
            if path == "/v1/agent/info":
                self._write(HTTPStatus.OK, {"ok": True, **self.store.info(self._token())})
                return
            if path == "/v1/agent/channels":
                query = parse_qs(urlsplit(self.path).query)
                task_id = str(query.get("task_id", [""])[0]).strip()
                self._write(
                    HTTPStatus.OK,
                    {"ok": True, "channels": self.store.list_channels(self._token(), task_id)},
                )
                return
            self._error(HTTPStatus.NOT_FOUND, "not-found")
        except BaseException as error:  # Keep malformed public requests JSON-shaped.
            self._dispatch_error(error)

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path.rstrip("/") or "/"
        try:
            payload = self._read_json()
            if path == "/v1/agent/pair":
                result = self.store.pair(
                    str(payload.get("code", "")),
                    name=str(payload.get("name", "用户端 TLS Agent")),
                    hostname=str(payload.get("hostname", "")),
                )
                self._write(HTTPStatus.CREATED, {"ok": True, **result})
                return
            token = self._token()
            if path == "/v1/agent/heartbeat":
                sessions = payload.get("sessions", [])
                if not isinstance(sessions, list):
                    raise TransportError("sessions 必须是列表")
                self._write(HTTPStatus.OK, {"ok": True, **self.store.heartbeat(
                    token,
                    sessions,
                    protocol_version=str(payload.get("protocol_version", "")),
                    release_id=str(payload.get("release_id", "")),
                )})
                return
            if path == "/v1/agent/complete":
                result = payload.get("result", {})
                if not isinstance(result, dict):
                    raise TransportError("result 必须是对象")
                self._write(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        **self.store.complete(
                            token,
                            str(payload.get("command_id", "")),
                            attempts=int(payload.get("attempts", 0) or 0),
                            writer_epoch=int(payload.get("writer_epoch", 0) or 0),
                            status=str(payload.get("status", "")),
                            result=result,
                            error=str(payload.get("error", "")),
                            transcript_proof=str(payload.get("transcript_proof", "")),
                            turn_id=str(payload.get("turn_id", "")),
                        ),
                    },
                )
                return
            if path == "/v1/agent/completion-notification":
                self._write(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "notification": self.store.publish_completion_notification(
                            token,
                            event_key=str(payload.get("event_key", "")),
                            session_id=str(payload.get("session_id", "")),
                            conversation=str(payload.get("conversation", "")),
                            user_message=str(payload.get("user_message", "")),
                            answer=str(payload.get("answer", "")),
                        ),
                    },
                )
                return
            if path == "/v1/agent/release":
                self._write(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        **self.store.release(
                            token,
                            str(payload.get("command_id", "")),
                            attempts=int(payload.get("attempts", 0) or 0),
                            writer_epoch=int(payload.get("writer_epoch", 0) or 0),
                            reason=str(payload.get("reason", "")),
                        ),
                    },
                )
                return
            if path == "/v1/agent/retry-failed":
                self._write(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        **self.store.retry_failed(
                            token,
                            str(payload.get("command_id", "")),
                            reason=str(payload.get("reason", "")),
                        ),
                    },
                )
                return
            if path == "/v1/agent/renew":
                self._write(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        **self.store.renew(
                            token,
                            str(payload.get("command_id", "")),
                            attempts=int(payload.get("attempts", 0) or 0),
                            writer_epoch=int(payload.get("writer_epoch", 0) or 0),
                            lease_seconds=int(payload.get("lease_seconds", 120) or 120),
                        ),
                    },
                )
                return
            if path == "/v1/agent/recovery/claim":
                self._write(HTTPStatus.OK, {"ok": True, "ticket": self.store.claim_recovery(
                    token,
                    str(payload.get("ticket_id", "")),
                    str(payload.get("lease_owner", "")),
                    lease_seconds=int(payload.get("lease_seconds", 30) or 30),
                )})
                return
            if path == "/v1/agent/recovery/renew":
                self._write(HTTPStatus.OK, {"ok": True, "ticket": self.store.renew_recovery(
                    token,
                    str(payload.get("ticket_id", "")),
                    str(payload.get("lease_owner", "")),
                    int(payload.get("writer_epoch", 0) or 0),
                    lease_seconds=int(payload.get("lease_seconds", 30) or 30),
                )})
                return
            if path == "/v1/agent/recovery/report":
                evidence = payload.get("evidence", {})
                if not isinstance(evidence, dict):
                    raise TransportError("evidence 必须是对象")
                self._write(HTTPStatus.OK, {"ok": True, "ticket": self.store.report_recovery(
                    token,
                    str(payload.get("ticket_id", "")),
                    str(payload.get("event", "")),
                    lease_owner=str(payload.get("lease_owner", "")),
                    writer_epoch=int(payload.get("writer_epoch", 0) or 0),
                    evidence=evidence,
                    error=str(payload.get("error", "")),
                )})
                return
            if path == "/v1/agent/repair/event":
                details = payload.get("details", {})
                if not isinstance(details, dict):
                    raise TransportError("details 必须是对象")
                self._write(HTTPStatus.OK, {"ok": True, "event": self.store.record_repair_event(
                    token,
                    str(payload.get("event_type", "")),
                    session_id=str(payload.get("session_id", "")),
                    command_id=str(payload.get("command_id", "")),
                    status=str(payload.get("status", "open")),
                    details=details,
                )})
                return
            if path == "/v1/agent/channel/request":
                capabilities = payload.get("capabilities", [])
                if not isinstance(capabilities, list):
                    raise TransportError("capabilities 必须是列表")
                self._write(
                    HTTPStatus.CREATED,
                    {
                        "ok": True,
                        "channel": self.store.request_channel(
                            token,
                            str(payload.get("task_id", "")),
                            str(payload.get("from_run_id", "")),
                            str(payload.get("to_run_id", "")),
                            capabilities,
                            ttl_seconds=int(payload.get("ttl_seconds", 3600)),
                        ),
                    },
                )
                return
            if path == "/v1/agent/channel/accept":
                self._write(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "channel": self.store.accept_channel(
                            token,
                            str(payload.get("channel_id", "")),
                            str(payload.get("accepting_run_id", "")),
                        ),
                    },
                )
                return
            if path == "/v1/agent/channel/revoke":
                self._write(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "channel": self.store.revoke_channel(
                            token,
                            str(payload.get("channel_id", "")),
                        ),
                    },
                )
                return
            if path == "/v1/agent/channel/message":
                channel_payload = payload.get("payload", {})
                if not isinstance(channel_payload, dict):
                    raise TransportError("payload 必须是对象")
                self._write(
                    HTTPStatus.CREATED,
                    {
                        "ok": True,
                        "message": self.store.send_channel_message(
                            token,
                            str(payload.get("channel_id", "")),
                            str(payload.get("sender_run_id", "")),
                            str(payload.get("message_id", "")),
                            channel_payload,
                        ),
                    },
                )
                return
            if path == "/v1/agent/channel/poll":
                self._write(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "messages": self.store.poll_channel_messages(
                            token,
                            str(payload.get("channel_id", "")),
                            str(payload.get("recipient_run_id", "")),
                            limit=int(payload.get("limit", 20)),
                            lease_seconds=int(payload.get("lease_seconds", 120)),
                        ),
                    },
                )
                return
            if path == "/v1/agent/channel/ack":
                self._write(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "message": self.store.ack_channel_message(
                            token,
                            str(payload.get("message_id", "")),
                            str(payload.get("recipient_run_id", "")),
                            status=str(payload.get("status", "acknowledged")),
                        ),
                    },
                )
                return
            self._error(HTTPStatus.NOT_FOUND, "not-found")
        except BaseException as error:  # Keep malformed public requests JSON-shaped.
            self._dispatch_error(error)

    def log_message(self, format: str, *args: object) -> None:
        # Request targets may include credentials in their query string.
        return


class GatewayServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], store: TransportStore):
        super().__init__(address, GatewayHandler)
        self.store = store


def recovery_monitor(
    store: TransportStore,
    stop_event: threading.Event,
    *,
    interval: float,
    max_age: int,
) -> None:
    """Continuously create idempotent recovery tickets for expired Sessions."""

    while not stop_event.is_set():
        try:
            store.scan_recovery_tickets(max_age=max_age)
        except (OSError, TransportError, RegistryError, ValueError) as error:
            print(f"tls-agent-gateway recovery scan failed: {type(error).__name__}", flush=True)
        stop_event.wait(interval)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("TLS_AGENT_GATEWAY_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("TLS_AGENT_GATEWAY_PORT", "8766")))
    parser.add_argument(
        "--recovery-scan-seconds",
        type=float,
        default=float(os.environ.get("TLS_RECOVERY_SCAN_SECONDS", str(DEFAULT_RECOVERY_SCAN_SECONDS))),
    )
    parser.add_argument(
        "--session-freshness-seconds",
        type=int,
        default=int(os.environ.get("TLS_SESSION_FRESHNESS_SECONDS", str(DEFAULT_SESSION_FRESHNESS_SECONDS))),
    )
    args = parser.parse_args()
    try:
        if not ipaddress.ip_address(args.host).is_loopback:
            parser.error("--host must be a loopback IP; use a TLS reverse proxy for remote access")
    except ValueError:
        parser.error("--host must be a loopback IP address")
    if args.recovery_scan_seconds < 1 or args.recovery_scan_seconds > 3600:
        parser.error("--recovery-scan-seconds 必须在 1 到 3600 之间")
    if args.session_freshness_seconds < 1 or args.session_freshness_seconds > 3600:
        parser.error("--session-freshness-seconds 必须在 1 到 3600 之间")
    store = TransportStore()
    store.init()
    server = GatewayServer((args.host, args.port), store)
    monitor_stop = threading.Event()
    monitor = threading.Thread(
        target=recovery_monitor,
        args=(store, monitor_stop),
        kwargs={"interval": args.recovery_scan_seconds, "max_age": args.session_freshness_seconds},
        name="tls-recovery-monitor",
        daemon=True,
    )
    monitor.start()
    print(f"tls-agent-gateway listening on {args.host}:{args.port}", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        monitor_stop.set()
        monitor.join(timeout=2.0)
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
