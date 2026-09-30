#!/usr/bin/env python3
"""Create signed mobile reply links and deliver queued replies to Codex app-server."""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import signal
import socket
import stat
import struct
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from session_policy import is_session_excluded
from mobile_reply_runtime import (
    atomic_json,
    b64url,
    load_env,
    process_state,
    resumed_session_from_process as resumed_session_from_process,
    resolve_runtime,
    route_path,
)


CONFIG_PATH = Path(
    os.environ.get("TLS_MOBILE_REPLY_CONFIG", str(Path.home() / ".config/tls/mobile-reply.env"))
)
STATE_DIR = Path(
    os.environ.get("TLS_MOBILE_REPLY_STATE_DIR", str(Path.home() / ".local/state/tls/mobile-reply"))
)
_configured_runtime_roots = os.environ.get("TLS_CODEX_RUNTIME_ROOTS", "")
RUNTIME_ROOTS = (
    tuple(Path(value) for value in _configured_runtime_roots.split(":") if value)
    if _configured_runtime_roots
    else (Path.home() / ".codex/app-server-control/cv-hotplug",)
)
DEFAULT_INTERVAL = 1.0
MAX_REPLY_CHARS = 4000
SESSION_ID = re.compile(r"^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$")
CURSOR_BRIDGE_SOCKET = Path(
    os.environ.get(
        "TLS_CURSOR_BRIDGE_SOCKET",
        str(Path.home() / ".local/state/tls/cursor-terminal-bridge.sock"),
    )
)
CURSOR_BRIDGE_DIRECTORY = Path(
    os.environ.get(
        "TLS_CURSOR_BRIDGE_DIRECTORY",
        str(Path.home() / ".local/state/tls/cursor-terminal-bridge"),
    )
)


def create_reply_link(session_id: str, topic: str, transcript: Path, now: int | None = None) -> str:
    if is_session_excluded(session_id) or is_session_excluded(transcript):
        return ""
    config = load_env()
    if not {"WORKER_URL", "LINK_SECRET", "POLL_TOKEN"}.issubset(config):
        return ""
    runtime = resolve_runtime(session_id, transcript)
    if runtime is None:
        return ""
    now = int(time.time()) if now is None else now
    route_id = secrets.token_urlsafe(18)
    nonce = secrets.token_urlsafe(18)
    expires_at = now + 7 * 24 * 60 * 60
    atomic_json(
        route_path(route_id),
        {
            "version": 1,
            "session_id": session_id,
            "socket": runtime["socket"],
            "transcript": str(transcript),
            "created_at": now,
            "expires_at": expires_at,
        },
    )
    payload = {"v": 1, "r": route_id, "n": nonce, "t": str(topic)[:80], "e": expires_at}
    encoded = b64url(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    signature = b64url(hmac.new(config["LINK_SECRET"].encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).digest())
    return config["WORKER_URL"].rstrip("/") + "/r?" + urllib.parse.urlencode({"t": f"{encoded}.{signature}"})


def create_tmux_test_reply_link(session_id: str, topic: str, transcript: Path, tmux_session: str, now: int | None = None) -> str:
    """Create a reply route for the isolated TLS mobile test window."""
    if is_session_excluded(session_id) or is_session_excluded(transcript):
        return ""
    if not re.fullmatch(r"tls-mobile-test-[0-9]{10,}", tmux_session):
        return ""
    config = load_env()
    if not {"WORKER_URL", "LINK_SECRET", "POLL_TOKEN"}.issubset(config):
        return ""
    now = int(time.time()) if now is None else now
    route_id = secrets.token_urlsafe(18)
    nonce = secrets.token_urlsafe(18)
    expires_at = now + 60 * 60
    atomic_json(route_path(route_id), {"version": 1, "backend": "tmux-test", "tmux_session": tmux_session, "session_id": session_id, "transcript": str(transcript), "created_at": now, "expires_at": expires_at})
    payload = {"v": 1, "r": route_id, "n": nonce, "t": str(topic)[:80], "e": expires_at}
    encoded = b64url(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    signature = b64url(hmac.new(config["LINK_SECRET"].encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).digest())
    return config["WORKER_URL"].rstrip("/") + "/r?" + urllib.parse.urlencode({"t": f"{encoded}.{signature}"})


def latest_conversation_event(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            size = path.stat().st_size
            handle.seek(max(0, size - 1_000_000))
            data = handle.read().decode("utf-8", errors="replace")
    except OSError:
        return "unknown"
    latest = "unknown"
    for line in data.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        payload = record.get("payload") if isinstance(record, dict) else None
        if not isinstance(payload, dict):
            continue
        event_type = payload.get("type")
        if record.get("type") == "event_msg" and event_type in {"user_message", "task_started"}:
            latest = "working"
        elif record.get("type") == "event_msg" and event_type == "task_complete":
            latest = "idle"
        elif record.get("type") == "response_item" and event_type in {
            "reasoning",
            "custom_tool_call",
            "custom_tool_call_output",
            "function_call",
            "function_call_output",
            "message",
        }:
            latest = "working"
    return latest


class AppServerClient:
    def __init__(self, socket_path: str, timeout: float = 10.0) -> None:
        self.connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.connection.settimeout(timeout)
        self.connection.connect(socket_path)
        self._handshake()
        self.next_id = 1

    def close(self) -> None:
        self.connection.close()

    def _receive_exact(self, length: int) -> bytes:
        chunks: list[bytes] = []
        while length:
            chunk = self.connection.recv(length)
            if not chunk:
                raise RuntimeError("app-server disconnected")
            chunks.append(chunk)
            length -= len(chunk)
        return b"".join(chunks)

    def _handshake(self) -> None:
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            "GET / HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.connection.sendall(request.encode("ascii"))
        response = b""
        while b"\r\n\r\n" not in response:
            response += self._receive_exact(1)
        if b" 101 " not in response.split(b"\r\n", 1)[0]:
            raise RuntimeError("app-server websocket handshake failed")

    def _send_frame(self, opcode: int, data: bytes) -> None:
        header = bytearray([0x80 | opcode])
        length = len(data)
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", length))
        mask = os.urandom(4)
        header.extend(mask)
        header.extend(byte ^ mask[index % 4] for index, byte in enumerate(data))
        self.connection.sendall(header)

    def _receive_frame(self) -> dict[str, Any] | None:
        first, second = self._receive_exact(2)
        opcode = first & 0x0F
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._receive_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._receive_exact(8))[0]
        mask = self._receive_exact(4) if second & 0x80 else b""
        data = self._receive_exact(length)
        if mask:
            data = bytes(byte ^ mask[index % 4] for index, byte in enumerate(data))
        if opcode == 0x8:
            raise RuntimeError("app-server closed websocket")
        if opcode == 0x9:
            self._send_frame(0xA, data)
            return None
        if opcode != 0x1:
            return None
        return json.loads(data.decode("utf-8"))

    def send(self, payload: dict[str, object]) -> None:
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._send_frame(0x1, data)

    def request(self, method: str, params: dict[str, object]) -> dict[str, Any]:
        request_id = self.next_id
        self.next_id += 1
        self.send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        while True:
            message = self._receive_frame()
            if message is None:
                continue
            if message.get("id") != request_id:
                continue
            if "error" in message:
                raise RuntimeError(str(message["error"])[:300])
            result = message.get("result")
            return result if isinstance(result, dict) else {}


def start_turn(
    socket_path: str,
    session_id: str,
    message: str,
    model: str | None = None,
    effort: str | None = None,
) -> str:
    client = AppServerClient(socket_path)
    try:
        client.request(
            "initialize",
            {
                "clientInfo": {"name": "tls-mobile-reply", "title": "TLS Mobile Reply", "version": "1.0"},
                "capabilities": {"experimentalApi": True},
            },
        )
        client.send({"jsonrpc": "2.0", "method": "initialized", "params": {}})
        client.request("thread/resume", {"threadId": session_id, "excludeTurns": True})
        params: dict[str, object] = {
            "threadId": session_id,
            "input": [{"type": "text", "text": message}],
            "clientUserMessageId": "tls-mobile-" + secrets.token_hex(12),
        }
        if model:
            params["model"] = model
        if effort:
            params["effort"] = effort
        result = client.request("turn/start", params)
        turn = result.get("turn") if isinstance(result, dict) else None
        turn_id = str(turn.get("id", "") or "") if isinstance(turn, dict) else ""
        if not turn_id:
            raise RuntimeError("turn/start did not return a turn id")
        return turn_id
    finally:
        client.close()


def process_ancestors(pid: int) -> set[int]:
    ancestors: set[int] = set()
    while pid > 1 and pid not in ancestors:
        ancestors.add(pid)
        try:
            fields = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").split()
            pid = int(fields[3])
        except (OSError, ValueError, IndexError):
            break
    return ancestors


def tmux_pane_for_socket(socket_path: str) -> str:
    try:
        client_pid = int((Path(socket_path).parent / "client.pid").read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return ""
    ancestors = process_ancestors(client_pid)
    try:
        result = subprocess.run(
            ["tmux", "list-panes", "-a", "-F", "#{pane_id}\t#{pane_pid}"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    matches = []
    for line in result.stdout.splitlines():
        try:
            pane_id, pane_pid_text = line.split("\t", 1)
            if int(pane_pid_text) in ancestors:
                matches.append(pane_id)
        except ValueError:
            continue
    return matches[0] if len(matches) == 1 else ""


def prepare_question_freeform_via_tmux(socket_path: str) -> bool:
    """Focus the native question's final option and its notes field."""
    pane_id = tmux_pane_for_socket(socket_path)
    if not pane_id:
        return False
    try:
        subprocess.run(["tmux", "send-keys", "-t", pane_id, "End"], check=True, timeout=5)
        time.sleep(0.075)
        subprocess.run(["tmux", "send-keys", "-t", pane_id, "Tab"], check=True, timeout=5)
        subprocess.run(
            ["tmux", "capture-pane", "-p", "-t", pane_id, "-S", "-20"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return True


def start_turn_via_tmux_pane(pane_id: str, message: str) -> bool:
    if not pane_id:
        return False
    buffer_name = "tls-mobile-" + secrets.token_hex(12)
    try:
        subprocess.run(["tmux", "set-buffer", "-b", buffer_name, "--", message], check=True, timeout=5)
        verified = subprocess.run(
            ["tmux", "save-buffer", "-b", buffer_name, "-"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if verified.stdout != message:
            raise RuntimeError("tmux buffer verification failed")
        subprocess.run(["tmux", "send-keys", "-t", pane_id, "C-u"], check=True, timeout=5)
        time.sleep(0.075)
        subprocess.run(["tmux", "paste-buffer", "-p", "-d", "-b", buffer_name, "-t", pane_id], check=True, timeout=5)
        time.sleep(0.25)
        subprocess.run(["tmux", "send-keys", "-t", pane_id, "Enter"], check=True, timeout=5)
        subprocess.run(
            ["tmux", "capture-pane", "-p", "-t", pane_id, "-S", "-20"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError, RuntimeError):
        subprocess.run(["tmux", "delete-buffer", "-b", buffer_name], check=False, capture_output=True, timeout=5)
        raise
    return True


def start_turn_via_tmux(socket_path: str, message: str) -> bool:
    return start_turn_via_tmux_pane(tmux_pane_for_socket(socket_path), message)


def deliver_tmux_session_turn(session_name: str, message: str) -> None:
    result = subprocess.run(
        ["tmux", "list-panes", "-t", f"={session_name}", "-F", "#{pane_id}"],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    panes = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if len(panes) != 1 or not start_turn_via_tmux_pane(panes[0], message):
        raise RuntimeError("未找到唯一可控制的 tmux Codex pane。")


def _send_cursor_keys(runtime: dict[str, object], keys: tuple[str, ...]) -> bool:
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(5.0)
    try:
        connection.connect(str(runtime["cursor_socket"]))
        request = {
            "shell_pid": int(runtime["cursor_shell_pid"]),
            "keys": list(keys),
        }
        connection.sendall(json.dumps(request, separators=(",", ":")).encode("utf-8") + b"\n")
        response = b""
        while b"\n" not in response and len(response) <= 4096:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response += chunk
        result = json.loads(response.split(b"\n", 1)[0].decode("utf-8"))
        return isinstance(result, dict) and result.get("ok") is True
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    finally:
        connection.close()


def prepare_question_freeform(runtime: dict[str, object]) -> bool:
    """Put either supported terminal backend into native question free-text mode."""
    cursor_socket = str(runtime.get("cursor_socket", "") or "")
    if cursor_socket:
        return _send_cursor_keys(runtime, ("END", "TAB"))
    socket_path = str(runtime.get("socket", "") or "")
    return bool(socket_path) and prepare_question_freeform_via_tmux(socket_path)


def deliver_turn(
    socket_path: str,
    session_id: str,
    message: str,
    model: str | None = None,
    effort: str | None = None,
    require_turn_id: bool = False,
) -> str:
    # A tmux keystroke cannot carry native turn/start overrides. Use the
    # app-server protocol whenever a model or effort was selected for the turn.
    if not require_turn_id and not model and not effort and start_turn_via_tmux(socket_path, message):
        return ""
    return start_turn(socket_path, session_id, message, model=model, effort=effort)


def _secure_cursor_bridge_socket(socket_path: Path) -> bool:
    try:
        metadata = socket_path.stat()
    except OSError:
        return False
    return stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == os.getuid() and not metadata.st_mode & 0o077


def _cursor_bridge_candidates(socket_path: Path | None) -> list[Path]:
    if socket_path is not None:
        return [socket_path]
    candidates = [CURSOR_BRIDGE_SOCKET]
    try:
        candidates.extend(sorted(CURSOR_BRIDGE_DIRECTORY.glob("bridge-*.sock")))
    except OSError:
        pass
    return list(dict.fromkeys(candidates))


def _cursor_bridge_has_terminal(socket_path: Path, shell_pid: int) -> bool:
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(1.0)
    try:
        connection.connect(str(socket_path))
        request = {"action": "probe", "shell_pid": shell_pid}
        connection.sendall(json.dumps(request, separators=(",", ":")).encode("utf-8") + b"\n")
        response = b""
        while b"\n" not in response and len(response) <= 4096:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response += chunk
        result = json.loads(response.split(b"\n", 1)[0].decode("utf-8"))
        return isinstance(result, dict) and result.get("ok") is True
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    finally:
        connection.close()


def cursor_terminal_runtime(
    shell_pid: int,
    socket_path: Path | None = None,
    codex_pid: int = 0,
) -> dict[str, object] | None:
    try:
        os.kill(shell_pid, 0)
    except OSError:
        return None
    for candidate in _cursor_bridge_candidates(socket_path):
        if not _secure_cursor_bridge_socket(candidate) or not _cursor_bridge_has_terminal(candidate, shell_pid):
            continue
        return {
            "cursor_shell_pid": shell_pid,
            "cursor_socket": str(candidate),
            "codex_pid": codex_pid,
        }
    return None


def _process_cmdline(pid: int) -> list[str]:
    try:
        return [
            item.decode("utf-8", errors="replace")
            for item in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            if item
        ]
    except OSError:
        return []


def _process_environment_value(pid: int, key: str) -> str:
    prefix = f"{key}=".encode("utf-8")
    try:
        for item in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0"):
            if item.startswith(prefix):
                return item[len(prefix) :].decode("utf-8", errors="replace")
    except OSError:
        pass
    return ""


def _cursor_session_pids(session_id: str) -> list[int]:
    needle = session_id.lower().encode("ascii", errors="ignore")
    if not needle:
        return []
    matches: list[int] = []
    try:
        entries = list(Path("/proc").iterdir())
    except OSError:
        return matches
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            pid = int(entry.name)
            raw = (entry / "cmdline").read_bytes()
        except (OSError, ValueError):
            continue
        if needle not in raw or b"codex" not in raw.lower():
            continue
        if process_state(pid) in {"T", "Z", "X"}:
            continue
        matches.append(pid)
    return matches


def _cursor_codex_binary(codex_pid: int) -> str:
    for argument in _process_cmdline(codex_pid):
        path = Path(argument)
        if path.name in {"codex", "codex-real"} and path.is_file():
            return str(path)
    return os.environ.get("TLS_CODEX_BIN", "codex")


def _cursor_resume_command(codex_pid: int, session_id: str, model: str, effort: str) -> str:
    arguments = [
        _cursor_codex_binary(codex_pid),
        "-c",
        f'model_reasoning_effort="{effort}"',
        "--model",
        model,
        "resume",
        session_id,
    ]
    environment: list[str] = []
    for key in ("CODEX_HOME", "CV_GLOBAL_CODEX_HOME"):
        value = _process_environment_value(codex_pid, key)
        if value:
            environment.append(f"{key}={shlex.quote(value)}")
    prefix = " ".join(environment)
    command = " ".join(shlex.quote(argument) for argument in arguments)
    return f"{prefix} {command}".strip()


def _send_cursor_text(runtime: dict[str, object], text: str) -> None:
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(5.0)
    try:
        connection.connect(str(runtime["cursor_socket"]))
        request = {
            "shell_pid": int(runtime["cursor_shell_pid"]),
            "text": text[: MAX_REPLY_CHARS - 1] + ("" if text.endswith("\r") else "\r"),
        }
        connection.sendall(json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n")
        response = b""
        while b"\n" not in response and len(response) <= 4096:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response += chunk
        result = json.loads(response.split(b"\n", 1)[0].decode("utf-8"))
        if not isinstance(result, dict) or result.get("ok") is not True:
            raise RuntimeError(str(result.get("error", "cursor terminal delivery failed"))[:200])
    finally:
        connection.close()


def deliver_cursor_turn(runtime: dict[str, object], message: str) -> None:
    # A trailing CR submits immediately and remains compatible with older bridge versions.
    _send_cursor_text(runtime, message)


def submit_cursor_turn(runtime: dict[str, object]) -> None:
    """Submit text already present in the terminal composer without rewriting it."""
    if not _send_cursor_keys(runtime, ("ENTER",)):
        raise RuntimeError("cursor terminal submit retry failed")


def switch_cursor_model(
    runtime: dict[str, object],
    session_id: str,
    model: str,
    effort: str,
    timeout: float = 4.0,
) -> None:
    """Apply a model choice to a native terminal TUI by resuming the same session.

    Native TUI sessions have no app-server socket.  When idle, `/exit` preserves
    the rollout and returns to the terminal shell; launching the same binary with
    `resume` and explicit model settings is the non-interactive equivalent of the
    TUI's `/model` selection and avoids sending a model choice as a user prompt.
    """
    codex_pid = int(runtime.get("codex_pid", 0) or 0)
    pids = _cursor_session_pids(session_id)
    if codex_pid > 1 and codex_pid not in pids:
        if process_state(codex_pid) not in {"", "T", "Z", "X"}:
            pids.insert(0, codex_pid)
    if not pids:
        raise RuntimeError("未找到可安全重启的 Codex 窗口。")

    # Capture the launcher and environment while the current process still exists.
    command = _cursor_resume_command(codex_pid or pids[0], session_id, model, effort)
    _send_cursor_text(runtime, "/exit")
    deadline = time.monotonic() + max(1.0, timeout)

    def process_still_alive() -> bool:
        return any(process_state(pid) not in {"", "T", "Z", "X"} for pid in pids)

    alive = True
    while time.monotonic() < deadline:
        alive = process_still_alive()
        if not alive:
            break
        time.sleep(0.1)
    if alive:
        raise RuntimeError("Codex 窗口未能安全退出，模型尚未切换。")

    _send_cursor_text(runtime, command)


def api_request(config: dict[str, str], path: str, payload: dict[str, object] | None = None) -> dict[str, Any]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        config["WORKER_URL"].rstrip("/") + path,
        data=data,
        method="GET" if data is None else "POST",
        headers={"Authorization": f"Bearer {config['POLL_TOKEN']}", "Content-Type": "application/json", "User-Agent": "tls-mobile-reply/1"},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        result = json.loads(response.read().decode("utf-8"))
    return result if isinstance(result, dict) else {}


def load_route(route_id: str) -> dict[str, Any] | None:
    if not route_id or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for character in route_id):
        return None
    try:
        payload = json.loads(route_path(route_id).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def poll_once() -> int:
    config = load_env()
    if not {"WORKER_URL", "LINK_SECRET", "POLL_TOKEN"}.issubset(config):
        return 0
    try:
        payload = api_request(config, "/api/replies")
    except (OSError, ValueError, urllib.error.URLError):
        return 0
    delivered = 0
    replies = payload.get("replies", [])
    if not isinstance(replies, list):
        return 0
    for reply in replies:
        if not isinstance(reply, dict):
            continue
        reply_id = reply.get("id")
        route = load_route(str(reply.get("route_id", "")))
        error = ""
        if route is None:
            error = "local-route-unavailable"
        elif is_session_excluded(route.get("session_id", "")) or is_session_excluded(route.get("transcript", "")):
            try:
                api_request(config, "/api/ack", {"id": reply_id, "status": "delivered", "error": "session-excluded"})
            except (OSError, ValueError, urllib.error.URLError):
                pass
            continue
        elif int(route.get("expires_at", 0)) < int(time.time()):
            error = "local-route-expired"
        elif latest_conversation_event(Path(str(route.get("transcript", "")))) != "idle":
            continue
        else:
            if route.get("backend") == "tmux-test":
                tmux_session = str(route.get("tmux_session", ""))
                try:
                    if not re.fullmatch(r"tls-mobile-test-[0-9]{10,}", tmux_session):
                        raise RuntimeError("invalid tmux test session")
                    deliver_tmux_session_turn(tmux_session, str(reply.get("message", ""))[:MAX_REPLY_CHARS])
                    delivered += 1
                    api_request(config, "/api/ack", {"id": reply_id, "status": "delivered", "error": ""})
                    continue
                except (OSError, RuntimeError, ValueError, socket.timeout) as exception:
                    error = type(exception).__name__
                try:
                    api_request(config, "/api/ack", {"id": reply_id, "status": "retry", "error": error})
                except (OSError, ValueError, urllib.error.URLError):
                    pass
                continue
            socket_path = str(route.get("socket", ""))
            try:
                metadata = Path(socket_path).stat()
                if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.getuid():
                    raise OSError("invalid socket")
                session_id = str(route.get("session_id", ""))
                message = str(reply.get("message", ""))[:MAX_REPLY_CHARS]
                deliver_turn(socket_path, session_id, message)
                delivered += 1
                api_request(config, "/api/ack", {"id": reply_id, "status": "delivered", "error": ""})
                continue
            except (OSError, RuntimeError, ValueError, socket.timeout) as exception:
                error = type(exception).__name__
        try:
            api_request(config, "/api/ack", {"id": reply_id, "status": "retry", "error": error})
        except (OSError, ValueError, urllib.error.URLError):
            pass
    return delivered


def daemon(interval: float) -> int:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    lock_path = STATE_DIR / "daemon.lock"
    with lock_path.open("a+", encoding="utf-8") as lock:
        os.chmod(lock_path, 0o600)
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0
        running = True

        def stop(_signum: int, _frame: object) -> None:
            nonlocal running
            running = False

        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGTERM, stop)
        while running:
            poll_once()
            deadline = time.monotonic() + interval
            while running and time.monotonic() < deadline:
                time.sleep(min(1.0, deadline - time.monotonic()))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("poll", "daemon"), nargs="?", default="poll")
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL)
    args = parser.parse_args()
    return daemon(max(1.0, args.interval)) if args.command == "daemon" else poll_once()


if __name__ == "__main__":
    raise SystemExit(main())
