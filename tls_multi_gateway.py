#!/usr/bin/env python3
"""Small standard-library HTTP gateway for local TLS Agents.

TLS Agents make outbound HTTPS requests to this service.  The gateway never
starts Codex and never reads a user's transcript; it only exposes the durable
pairing, heartbeat, command, and result endpoints backed by SQLite.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from tls_multi_registry import RegistryError
from tls_multi_transport import TransportError, TransportStore


MAX_BODY = 256 * 1024


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
                self._write(HTTPStatus.OK, {"ok": True, "service": "tls-agent-gateway", "version": 1})
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
            if path == "/v1/agent/info":
                self._write(HTTPStatus.OK, {"ok": True, **self.store.info(self._token())})
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
                self._write(HTTPStatus.OK, {"ok": True, **self.store.heartbeat(token, sessions)})
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
                            status=str(payload.get("status", "")),
                            result=result,
                            error=str(payload.get("error", "")),
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
                            lease_seconds=int(payload.get("lease_seconds", 120) or 120),
                        ),
                    },
                )
                return
            self._error(HTTPStatus.NOT_FOUND, "not-found")
        except BaseException as error:  # Keep malformed public requests JSON-shaped.
            self._dispatch_error(error)

    def log_message(self, format: str, *args: object) -> None:
        # Avoid writing credentials or message bodies to the service journal.
        print(f"tls-agent-gateway {self.address_string()} {format % args}", flush=True)


class GatewayServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], store: TransportStore):
        super().__init__(address, GatewayHandler)
        self.store = store


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("TLS_AGENT_GATEWAY_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("TLS_AGENT_GATEWAY_PORT", "8766")))
    args = parser.parse_args()
    store = TransportStore()
    store.init()
    server = GatewayServer((args.host, args.port), store)
    print(f"tls-agent-gateway listening on {args.host}:{args.port}", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
