#!/usr/bin/env python3
"""Run the user-side TLS Agent next to the user's local Codex windows.

The agent makes outbound HTTPS requests only.  It discovers local sessions,
executes commands through the existing local TLS delivery helpers, and sends
back a short result.  No transcript or local socket is uploaded.
"""

from __future__ import annotations

import argparse
from collections import deque
import fcntl
import json
import logging
import os
import re
import signal
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from gateway_url import gateway_base_url


ROOT = Path(__file__).resolve().parent
TLS_LIB = Path(os.environ.get("TLS_AGENT_LOCAL_LIB", str(ROOT)))
if str(TLS_LIB) not in os.sys.path:
    os.sys.path.insert(0, str(TLS_LIB))

from codex_session_watch import active_session_files, active_session_terminals, session_roots  # noqa: E402
from codex_completion_watch import message_text  # noqa: E402
from mobile_reply import (  # noqa: E402
    cursor_terminal_runtime,
    deliver_cursor_turn,
    deliver_turn,
    latest_conversation_event,
    resolve_runtime,
)
from session_policy import is_session_excluded, session_label  # noqa: E402


CONFIG_FILE = Path(
    os.environ.get("TLS_AGENT_CONFIG_FILE", str(Path.home() / ".config/tls/agent.env"))
)
STATE_DIR = Path(
    os.environ.get("TLS_AGENT_STATE_DIR", str(Path.home() / ".local/state/tls/agent"))
)
DEFAULT_HEARTBEAT_INTERVAL = 5.0
MIN_HEARTBEAT_INTERVAL = 2.0
DEFAULT_POLL_INTERVAL = 1.0
DEFAULT_BIND_TIMEOUT = 20.0
DEFAULT_TURN_TIMEOUT = 1800.0
DEFAULT_COMMAND_LEASE_SECONDS = 30
DEFAULT_LEASE_RENEW_INTERVAL = 5.0
DEFAULT_RECOVERY_COOLDOWN_SECONDS = 60.0
PROTOCOL_VERSION = "2"
RELEASE_ID = os.environ.get("TLS_RELEASE_ID", "tls-group-chat-v1")
DEFAULT_RECOVERY_LAUNCH_TIMEOUT = 30.0
MAX_REPLY_CHARS = 12000
COMPLETE_RETRY_DELAYS = (0.5, 1.0, 2.0)
HEARTBEAT_RETRY_DELAYS = (1.0, 2.0)
LOGGER = logging.getLogger("tls.qyp_multi_agent")
INFLIGHT_COMMAND_FILE = "inflight-command.json"
FAILURE_REPAIR_SCRIPT = Path(os.environ.get("TLS_FAILURE_REPAIR_SCRIPT", str(ROOT.parent / "tls_fault_healer.py")))


class AgentError(RuntimeError):
    """Expected local Agent or gateway error."""


def load_env(path: Path = CONFIG_FILE) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _config_value(config: dict[str, str], key: str, default: str = "") -> str:
    return str(os.environ.get(key, config.get(key, default)) or "").strip()


def _api_url(config: dict[str, str], path: str) -> str:
    base = _config_value(config, "TLS_AGENT_URL")
    if not base:
        raise AgentError("TLS_AGENT_URL 未配置")
    try:
        base = gateway_base_url(base)
    except ValueError as exc:
        raise AgentError(str(exc)) from exc
    return base + "/" + path.lstrip("/")


def api_request(
    config: dict[str, str],
    path: str,
    *,
    payload: dict[str, Any] | None = None,
    authenticated: bool = True,
    timeout: float = 20.0,
) -> dict[str, Any]:
    body = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {"Accept": "application/json", "User-Agent": "tls-local-agent/1"}
    if body is not None:
        headers["Content-Type"] = "application/json; charset=utf-8"
    if authenticated:
        token = _config_value(config, "TLS_AGENT_TOKEN")
        if not token:
            raise AgentError("TLS_AGENT_TOKEN 未配置，请先 pair")
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(_api_url(config, path), data=body, headers=headers, method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(512 * 1024)
    except urllib.error.HTTPError as exc:
        raw = exc.read(64 * 1024)
        try:
            detail = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            detail = {}
        raise AgentError(str(detail.get("error", f"gateway-http-{exc.code}"))[:240]) from exc
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        raise AgentError(f"gateway-unreachable:{type(exc).__name__}") from exc
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgentError("gateway 返回了无效 JSON") from exc
    if not isinstance(result, dict):
        raise AgentError("gateway 返回格式无效")
    if result.get("ok") is False:
        raise AgentError(str(result.get("error", "gateway-error"))[:240])
    return result


def complete_request(config: dict[str, str], payload: dict[str, Any]) -> dict[str, Any]:
    """Report a command result without turning a transient callback failure into task failure."""

    for attempt in range(len(COMPLETE_RETRY_DELAYS) + 1):
        try:
            return api_request(config, "/v1/agent/complete", payload=payload)
        except AgentError as exc:
            retryable = str(exc).startswith("gateway-unreachable:")
            if not retryable or attempt == len(COMPLETE_RETRY_DELAYS):
                raise
            time.sleep(COMPLETE_RETRY_DELAYS[attempt])
    raise AssertionError("unreachable")


def _session_id_list(config: dict[str, str]) -> list[str]:
    raw = _config_value(config, "TLS_AGENT_SESSION_IDS")
    return [item.strip().lower() for item in raw.replace(";", ",").split(",") if item.strip()]


def _transcript_for(session_id: str) -> Path | None:
    for root in session_roots():
        if not root.is_dir():
            continue
        try:
            matches = sorted(root.rglob(f"*{session_id}*.jsonl"), key=lambda path: path.stat().st_mtime_ns)
        except OSError:
            continue
        if matches:
            return matches[-1]
    return None


def _workspace(transcript: Path) -> str:
    try:
        with transcript.open(encoding="utf-8", errors="replace") as handle:
            first = json.loads(handle.readline())
        payload = first.get("payload") if isinstance(first, dict) else None
        if isinstance(payload, dict) and payload.get("cwd"):
            return str(payload["cwd"])[:500]
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    return ""


def discover_sessions(config: dict[str, str]) -> list[dict[str, Any]]:
    active = active_session_files()
    terminals = active_session_terminals()
    # The launch switch controls creation only. Existing recovery runtimes must
    # remain visible for heartbeat and command delivery while launch is paused.
    recovery_active = _active_recovery_sessions()
    requested = set(_session_id_list(config))
    requested.update(recovery_active)
    if not requested:
        requested.update(str(session_id).lower() for session_id in active)
    records: list[dict[str, Any]] = []
    for session_id in sorted(requested):
        transcript = active.get(session_id) or _transcript_for(session_id)
        if transcript is None:
            continue
        status = latest_conversation_event(transcript)
        if session_id in recovery_active:
            status = "idle"
        elif session_id not in active and session_id not in terminals:
            status = "offline"
        label = session_label(session_id) or f"用户端 Codex · {session_id[:8]}"
        status_map = {"working": "running", "idle": "idle", "unknown": "unknown", "offline": "offline"}
        records.append(
            {
                "session_id": session_id,
                "label": label[:160],
                "workspace": _workspace(transcript),
                "status": status_map.get(status, "unknown"),
            }
        )
    return records


def heartbeat_once(config: dict[str, str]) -> dict[str, Any]:
    payload = {
        "sessions": discover_sessions(config),
        "protocol_version": PROTOCOL_VERSION,
        "release_id": RELEASE_ID,
    }
    for attempt in range(len(HEARTBEAT_RETRY_DELAYS) + 1):
        try:
            return api_request(config, "/v1/agent/heartbeat", payload=payload)
        except AgentError:
            if attempt >= len(HEARTBEAT_RETRY_DELAYS):
                raise
            time.sleep(HEARTBEAT_RETRY_DELAYS[attempt])
    raise AssertionError("unreachable")


def recovery_enabled(config: dict[str, str]) -> bool:
    if _config_value(config, "TLS_AGENT_RECOVERY_EMERGENCY_DISABLED", "0").lower() in {"1", "true", "yes", "on"}:
        return False
    return _config_value(config, "TLS_AGENT_RECOVERY_ENABLED", "1").lower() in {"1", "true", "yes", "on"}


def recovery_config_status(config: dict[str, str]) -> dict[str, Any]:
    emergency = _config_value(config, "TLS_AGENT_RECOVERY_EMERGENCY_DISABLED", "0")
    source = "process-environment" if "TLS_AGENT_RECOVERY_ENABLED" in os.environ else "agent.env" if "TLS_AGENT_RECOVERY_ENABLED" in config else "default"
    return {
        "enabled": recovery_enabled(config),
        "configured_value": _config_value(config, "TLS_AGENT_RECOVERY_ENABLED", "1"),
        "source": source,
        "emergency_override": emergency.lower() in {"1", "true", "yes", "on"},
    }


def _recovery_state_path() -> Path:
    return STATE_DIR / "recovery-launches.json"


def _recovery_launches() -> dict[str, float]:
    try:
        value = json.loads(_recovery_state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return {}
    return {str(key): float(timestamp) for key, timestamp in value.items()} if isinstance(value, dict) else {}


def _save_recovery_launches(value: dict[str, float]) -> None:
    path = _recovery_state_path()
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def _active_recovery_sessions() -> set[str]:
    sessions: set[str] = set()
    for key in _recovery_launches():
        _, separator, session_id = key.partition(":")
        if not separator or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", session_id):
            continue
        ticket_id = key.split(":", 1)[0]
        name = f"tls-recovery-{ticket_id[-8:]}-{session_id[:8]}"
        if subprocess.run(["tmux", "has-session", "-t", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            sessions.add(session_id)
    return sessions


def _recovery_tmux_name(session_id: str) -> str:
    for key in _recovery_launches():
        ticket_id, separator, candidate = key.partition(":")
        if separator and candidate == session_id:
            name = f"tls-recovery-{ticket_id[-8:]}-{session_id[:8]}"
            if subprocess.run(["tmux", "has-session", "-t", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                return name
    return ""


def _recovery_runtime(session_id: str) -> dict[str, Any] | None:
    name = _recovery_tmux_name(session_id)
    return {"tmux_target": f"{name}:0.0"} if name else None


def deliver_recovery_tmux_turn(runtime: dict[str, Any], text: str) -> None:
    target = str(runtime.get("tmux_target", ""))
    if not re.fullmatch(r"tls-recovery-[0-9a-f]{8}-[0-9a-f]{8}:0\.0", target):
        raise AgentError("invalid-recovery-tmux-target")
    buffer_name = f"tls-command-{os.getpid()}-{threading.get_ident()}"
    try:
        subprocess.run(["tmux", "send-keys", "-t", target, "C-u"], check=True, timeout=5)
        subprocess.run(["tmux", "set-buffer", "-b", buffer_name, "--", text], check=True, timeout=5)
        subprocess.run(["tmux", "paste-buffer", "-d", "-b", buffer_name, "-t", target], check=True, timeout=5)
        subprocess.run(["tmux", "send-keys", "-t", target, "Enter"], check=True, timeout=5)
    except (OSError, subprocess.SubprocessError) as error:
        raise AgentError("recovery-tmux-delivery-failed") from error
    finally:
        subprocess.run(["tmux", "delete-buffer", "-b", buffer_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def launch_recovery_tickets(config: dict[str, str], heartbeat: dict[str, Any]) -> None:
    """Claim, launch, and explicitly verify recovery of the original Session."""

    if not recovery_enabled(config):
        return
    if not isinstance(heartbeat, dict) or not heartbeat.get("recovery_compatible"):
        return
    tickets = heartbeat.get("recovery_tickets", [])
    if not isinstance(tickets, list):
        return
    launches = _recovery_launches()
    timestamp = time.time()
    codex = _config_value(config, "TLS_AGENT_RECOVERY_CODEX") or shutil.which("codex") or str(Path.home() / ".local/bin/codex")
    lease_owner = f"{os.uname().nodename}:{os.getpid()}"
    recovery_session_ids = {
        item.strip().lower()
        for item in _config_value(config, "TLS_AGENT_RECOVERY_SESSION_IDS").replace(";", ",").split(",")
        if item.strip()
    }
    for ticket in tickets:
        if not isinstance(ticket, dict):
            continue
        ticket_id = str(ticket.get("ticket_id", ""))
        session_id = str(ticket.get("session_id", "")).lower()
        if not ticket_id or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", session_id):
            continue
        if recovery_session_ids and session_id not in recovery_session_ids:
            continue
        key = f"{ticket_id}:{session_id}"
        terminals = active_session_terminals()
        if session_id in active_session_files() or session_id in terminals:
            api_request(config, "/v1/agent/recovery/report", payload={
                "ticket_id": ticket_id,
                "event": "cancelled_live",
                "evidence": {"active_transcript": session_id in active_session_files(), "active_terminal": session_id in terminals},
            })
            _audit("recovery_cancelled_live", ticket_id=ticket_id, session_id=session_id)
            continue
        claimed = api_request(config, "/v1/agent/recovery/claim", payload={
            "ticket_id": ticket_id, "lease_owner": lease_owner, "lease_seconds": 30,
        }).get("ticket", {})
        if not isinstance(claimed, dict):
            continue
        writer_epoch = int(claimed.get("writer_epoch", 0) or 0)
        name = f"tls-recovery-{ticket_id[-8:]}-{session_id[:8]}"
        transcript = _transcript_for(session_id)
        workspace = _workspace(transcript) if transcript is not None else ""
        cwd = workspace if workspace and Path(workspace).is_dir() else str(Path.home())
        environment = os.environ.copy()
        environment["PATH"] = ":".join([str(Path.home() / ".local/bin"), environment.get("PATH", "")])
        try:
            api_request(config, "/v1/agent/recovery/report", payload={
                "ticket_id": ticket_id, "event": "launching", "lease_owner": lease_owner,
                "writer_epoch": writer_epoch, "evidence": {"tmux_session": name},
            })
            subprocess.run(["tmux", "new-session", "-d", "-s", name, "-c", cwd, codex, "resume", session_id], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, env=environment)
            launches[key] = timestamp
            _save_recovery_launches(launches)
            _audit("recovery_launch", ticket_id=ticket_id, session_id=session_id, tmux_session=name)
            deadline = time.monotonic() + max(10.0, float(_config_value(config, "TLS_AGENT_RECOVERY_LAUNCH_TIMEOUT", str(DEFAULT_RECOVERY_LAUNCH_TIMEOUT))))
            next_renew = 0.0
            verified = False
            while time.monotonic() < deadline:
                if time.monotonic() >= next_renew:
                    api_request(config, "/v1/agent/recovery/renew", payload={
                        "ticket_id": ticket_id, "lease_owner": lease_owner,
                        "writer_epoch": writer_epoch, "lease_seconds": 30,
                    })
                    next_renew = time.monotonic() + 10.0
                if subprocess.run(["tmux", "has-session", "-t", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
                    break
                runtime = _runtime_for(session_id, transcript or Path("/nonexistent"))
                if runtime is not None and _transcript_for(session_id) is not None:
                    proof_sessions = discover_sessions(config)
                    for record in proof_sessions:
                        if record.get("session_id") == session_id:
                            record["recovery_ticket_id"] = ticket_id
                            record["writer_epoch"] = writer_epoch
                    proof = api_request(config, "/v1/agent/heartbeat", payload={
                        "sessions": proof_sessions, "protocol_version": PROTOCOL_VERSION, "release_id": RELEASE_ID,
                    })
                    confirmed = proof.get("recovery_heartbeats", [])
                    if isinstance(confirmed, list) and ticket_id in confirmed:
                        verified = True
                        break
                time.sleep(1.0)
            if not verified:
                raise AgentError("recovery-verification-timeout")
            api_request(config, "/v1/agent/recovery/report", payload={
                "ticket_id": ticket_id, "event": "recovered", "lease_owner": lease_owner,
                "writer_epoch": writer_epoch,
                "evidence": {"tmux_session": name, "session_id": session_id, "runtime_writable": True, "heartbeat_confirmed": True},
            })
            _audit("recovery_verified", ticket_id=ticket_id, session_id=session_id, writer_epoch=writer_epoch)
        except (OSError, subprocess.SubprocessError) as error:
            launches[key] = timestamp
            _audit("recovery_launch_failed", ticket_id=ticket_id, session_id=session_id, error=type(error).__name__)
            api_request(config, "/v1/agent/recovery/report", payload={
                "ticket_id": ticket_id, "event": "launch_failed", "lease_owner": lease_owner,
                "writer_epoch": writer_epoch, "error": type(error).__name__,
            })
        except AgentError as error:
            launches[key] = timestamp
            _audit("recovery_launch_failed", ticket_id=ticket_id, session_id=session_id, error=str(error)[:160])
            api_request(config, "/v1/agent/recovery/report", payload={
                "ticket_id": ticket_id, "event": "launch_failed", "lease_owner": lease_owner,
                "writer_epoch": writer_epoch, "error": str(error)[:500],
            })
    _save_recovery_launches(launches)


def _runtime_for(session_id: str, transcript: Path) -> dict[str, Any] | None:
    runtime = resolve_runtime(session_id, transcript)
    if runtime is not None:
        return runtime
    runtime = _recovery_runtime(session_id)
    if runtime is not None:
        return runtime
    target = active_session_terminals().get(session_id)
    if not isinstance(target, dict):
        return None
    terminal_name = str(target.get("terminal_name", ""))
    if target.get("backend") == "tmux" and re.fullmatch(
        r"tls-recovery-[0-9a-f]{8}-[0-9a-f]{8}", terminal_name
    ):
        return {"tmux_target": f"{terminal_name}:0.0"}
    return cursor_terminal_runtime(
        int(target.get("shell_pid", 0) or 0),
        codex_pid=int(target.get("codex_pid", 0) or 0),
    )


def _audit(event: str, **fields: object) -> None:
    """Emit correlation evidence to the Agent service journal."""

    LOGGER.warning("tls_agent_audit %s", json.dumps({"event": event, **fields}, ensure_ascii=False, sort_keys=True))


def _request_failure_repair(config: dict[str, str], reason: str, session_id: str = "", command_id: str = "") -> None:
    """Record a hard TLS failure and ask the bounded repair controller to inspect it."""

    if _config_value(config, "TLS_FAILURE_REPAIR_ENABLED", "0") != "1":
        return
    try:
        subprocess.run(
            [
                sys.executable,
                str(FAILURE_REPAIR_SCRIPT),
                "trigger",
                "--reason",
                reason[:240],
                "--session-id",
                session_id,
                "--command-id",
                command_id,
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=8,
        )
    except (OSError, subprocess.SubprocessError):
        _audit("failure_repair_trigger_failed", reason=reason[:160], session_id=session_id, command_id=command_id)


def _complete_failed_command(
    config: dict[str, str], command_id: str, error: str, session_id: str = "",
    attempts: int = 0, writer_epoch: int = 0, transcript_proof: str = "", turn_id: str = "",
) -> None:
    try:
        complete_request(
            config,
            {
                "command_id": command_id,
                "attempts": attempts,
                "writer_epoch": writer_epoch,
                "status": "failed",
                "error": error[:500],
                "transcript_proof": transcript_proof,
                "turn_id": turn_id,
                "result": {"session_id": session_id} if session_id else {},
            },
        )
    finally:
        _request_failure_repair(config, error, session_id, command_id)


def _inflight_command_path() -> Path:
    return STATE_DIR / INFLIGHT_COMMAND_FILE


def _save_inflight_command(record: dict[str, Any]) -> None:
    """Persist an accepted turn so a restarted Agent can finish its callback."""

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)
    target = _inflight_command_path()
    temporary = target.with_name(f".{target.name}.tmp")
    temporary.write_text(json.dumps(record, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(target)


def _load_inflight_command() -> dict[str, Any] | None:
    try:
        value = json.loads(_inflight_command_path().read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _clear_inflight_command(command_id: str = "") -> None:
    target = _inflight_command_path()
    record = _load_inflight_command()
    if command_id and record is not None and str(record.get("command_id", "")) != command_id:
        return
    try:
        target.unlink()
    except FileNotFoundError:
        pass


def release_command(
    config: dict[str, str], command_id: str, attempts: int, reason: str, writer_epoch: int = 0
) -> dict[str, Any]:
    return api_request(
        config,
        "/v1/agent/release",
        payload={"command_id": command_id, "attempts": attempts, "writer_epoch": writer_epoch, "reason": reason[:500]},
    )


def _new_completion(path: Path, offset: int, expected_turn_id: str) -> str:
    try:
        with path.open("rb") as handle:
            handle.seek(max(0, offset))
            for raw_line in handle:
                try:
                    record = json.loads(raw_line.decode("utf-8", errors="replace"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if not isinstance(record, dict) or record.get("type") != "event_msg":
                    continue
                payload = record.get("payload")
                if (
                    isinstance(payload, dict)
                    and payload.get("type") == "turn_aborted"
                    and str(payload.get("turn_id", "")) == expected_turn_id
                ):
                    raise AgentError("turn-aborted")
                if (
                    isinstance(payload, dict)
                    and payload.get("type") == "task_complete"
                    and str(payload.get("turn_id", "")) == expected_turn_id
                ):
                    answer = str(payload.get("last_agent_message", "") or "").strip()
                    if answer:
                        return answer[:MAX_REPLY_CHARS]
    except OSError:
        pass
    return ""


def _new_bound_turn_id(path: Path, offset: int, expected_text: str) -> str:
    """Find the Cursor-submitted user message and its transcript turn ID."""

    expected = expected_text.strip()
    try:
        with path.open("rb") as handle:
            handle.seek(max(0, offset))
            for raw_line in handle:
                try:
                    record = json.loads(raw_line.decode("utf-8", errors="replace"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if not isinstance(record, dict) or record.get("type") != "response_item":
                    continue
                payload = record.get("payload")
                if not isinstance(payload, dict) or payload.get("type") != "message" or payload.get("role") != "user":
                    continue
                if message_text(payload).strip() != expected:
                    continue
                metadata = payload.get("internal_chat_message_metadata_passthrough")
                if isinstance(metadata, dict):
                    turn_id = str(metadata.get("turn_id", "") or "").strip()
                    if turn_id:
                        return turn_id
    except OSError:
        pass
    return ""


def _new_user_message_present(path: Path, offset: int, expected_text: str) -> bool:
    expected = expected_text.strip()
    try:
        with path.open("rb") as handle:
            handle.seek(max(0, offset))
            for raw_line in handle:
                try:
                    record = json.loads(raw_line.decode("utf-8", errors="replace"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                payload = record.get("payload") if isinstance(record, dict) else None
                if isinstance(payload, dict) and record.get("type") == "response_item" and payload.get("type") == "message" and payload.get("role") == "user" and message_text(payload).strip() == expected:
                    return True
    except OSError:
        return True
    return False


def _wait_for_bound_turn(
    path: Path,
    offset: int,
    expected_text: str,
    timeout: float,
    stop_event: threading.Event | None = None,
) -> str:
    deadline = time.monotonic() + max(10.0, timeout)
    while time.monotonic() < deadline:
        turn_id = _new_bound_turn_id(path, offset, expected_text)
        if turn_id:
            return turn_id
        if stop_event is not None:
            if stop_event.wait(1.0):
                raise AgentError("agent-stopping")
        else:
            time.sleep(1.0)
    _audit("turn_bind_timeout", transcript=str(path), text_chars=len(expected_text))
    raise AgentError("turn-id-unavailable-cursor-runtime")


def _wait_for_completion(
    path: Path,
    offset: int,
    expected_turn_id: str,
    timeout: float,
    stop_event: threading.Event | None = None,
) -> str:
    deadline = time.monotonic() + max(10.0, timeout)
    while time.monotonic() < deadline:
        answer = _new_completion(path, offset, expected_turn_id)
        if answer:
            return answer
        if stop_event is not None:
            if stop_event.wait(1.0):
                raise AgentError("agent-stopping")
        else:
            time.sleep(1.0)
    _audit("turn_timeout", transcript=str(path), expected_turn_id=expected_turn_id)
    raise AgentError("codex-turn-timeout")


def _find_transcript(session_id: str) -> Path | None:
    active = active_session_files()
    return active.get(session_id) or _transcript_for(session_id)


def transcript_snapshot(transcript: Path, limit: int = 3) -> str:
    entries: list[str] = []
    try:
        for raw in transcript.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                record = json.loads(raw)
            except json.JSONDecodeError:
                continue
            payload = record.get("payload") if isinstance(record, dict) else None
            if not isinstance(payload, dict):
                continue
            role = str(payload.get("role", ""))
            if record.get("type") == "response_item" and role in {"user", "assistant"}:
                text = message_text(payload).strip()
                if text:
                    entries.append(f"{'用户' if role == 'user' else 'Codex'}：{' '.join(text.split())[:500]}")
            elif record.get("type") == "event_msg" and payload.get("type") == "task_complete":
                text = str(payload.get("last_agent_message", "")).strip()
                if text:
                    entries.append(f"Codex：{' '.join(text.split())[:500]}")
    except OSError:
        return "无法读取该会话的消息记录。"
    return "最近 3 条消息：\n" + "\n".join(entries[-limit:]) if entries else "该会话尚无可读取消息。"


def search_transcript(transcript: Path, query: str, *, limit: int = 5) -> str:
    term = " ".join(str(query).split()).strip()
    if len(term) < 2 or len(term) > 80:
        raise AgentError("history-query-length-invalid")
    matches: deque[str] = deque(maxlen=limit)
    scanned = 0
    truncated = False
    try:
        with transcript.open("rb") as handle:
            for raw in handle:
                scanned += len(raw)
                if scanned > 64 * 1024 * 1024:
                    truncated = True
                    break
                if len(raw) > 1024 * 1024:
                    continue
                try:
                    record = json.loads(raw)
                except (ValueError, UnicodeDecodeError):
                    continue
                payload = record.get("payload") if isinstance(record, dict) else None
                if not isinstance(payload, dict) or record.get("type") != "response_item" or payload.get("role") not in {"user", "assistant"}:
                    continue
                content = " ".join(message_text(payload).split())
                offset = content.casefold().find(term.casefold())
                if offset < 0:
                    continue
                start = max(0, offset - 90)
                snippet = content[start : start + 240]
                snippet = re.sub(r"(?i)(bearer\s+|api[_-]?key\s*[=:]\s*|sk-)[A-Za-z0-9_.-]{8,}", "[redacted]", snippet)
                matches.append(f"{'用户' if payload['role'] == 'user' else 'Codex'}：{snippet}")
    except OSError as exc:
        raise AgentError("history-read-failed") from exc
    if not matches:
        return "未找到匹配的会话记录。" + ("（只检索了前 64 MiB）" if truncated else "")
    return f"最近 {len(matches)} 条匹配：\n" + "\n".join(matches) + ("\n（只检索了前 64 MiB）" if truncated else "")


def _process_command(
    config: dict[str, str],
    command: dict[str, Any],
    stop_event: threading.Event | None = None,
) -> str:
    command_id = str(command.get("command_id", ""))
    attempts = int(command.get("attempts", 0) or 0)
    writer_epoch = int(command.get("writer_epoch", 0) or 0)
    payload = command.get("payload") if isinstance(command.get("payload"), dict) else {}
    session_id = str(command.get("session_id") or payload.get("session_id") or "").lower()
    transcript = _find_transcript(session_id)
    if transcript is None or is_session_excluded(session_id) or is_session_excluded(transcript):
        _complete_failed_command(config, command_id, "session-offline-or-excluded", session_id, attempts, writer_epoch)
        return "failed"
    if str(command.get("action", "")) == "snapshot":
        complete_request(config, {"command_id": command_id, "attempts": attempts, "writer_epoch": writer_epoch, "status": "completed", "result": {"answer": transcript_snapshot(transcript), "session_id": session_id, "snapshot": True}})
        return "completed"
    if str(command.get("action", "")) == "history_search":
        try:
            answer = search_transcript(transcript, str(payload.get("query", "")))
        except AgentError as exc:
            _complete_failed_command(config, command_id, str(exc), session_id, attempts, writer_epoch)
            return "failed"
        complete_request(config, {"command_id": command_id, "attempts": attempts, "writer_epoch": writer_epoch, "status": "completed", "result": {"answer": answer, "session_id": session_id, "history_search": True}})
        return "completed"
    runtime = _runtime_for(session_id, transcript)
    if runtime is None:
        _complete_failed_command(config, command_id, "runtime-unavailable", session_id, attempts, writer_epoch, "absent")
        return "failed"
    text = str(payload.get("text", ""))[:MAX_REPLY_CHARS]
    model = str(payload.get("model", "") or "").strip()
    effort = str(payload.get("effort", "") or "").strip()
    if not text:
        _complete_failed_command(config, command_id, "empty-command", session_id, attempts, writer_epoch)
        return "failed"
    turn_id = ""
    offset = 0
    try:
        offset = transcript.stat().st_size
        timeout = float(_config_value(config, "TLS_AGENT_TURN_TIMEOUT", str(DEFAULT_TURN_TIMEOUT)))
        bind_timeout = float(_config_value(config, "TLS_AGENT_BIND_TIMEOUT", str(DEFAULT_BIND_TIMEOUT)))
        if runtime.get("tmux_target"):
            deliver_recovery_tmux_turn(runtime, text)
            turn_id = _wait_for_bound_turn(transcript, offset, text, bind_timeout, stop_event)
        elif runtime.get("cursor_socket"):
            deliver_cursor_turn(runtime, text)
            turn_id = _wait_for_bound_turn(
                transcript, offset, text, bind_timeout, stop_event
            )
        else:
            turn_id = deliver_turn(
                str(runtime["socket"]),
                session_id,
                text,
                model=model or None,
                effort=effort or None,
                require_turn_id=True,
            )
        if not turn_id:
            raise AgentError("turn-id-unavailable")
        _audit("turn_bound", command_id=command_id, session_id=session_id, turn_id=turn_id)
        _save_inflight_command(
            {
                "attempts": attempts,
                "writer_epoch": writer_epoch,
                "command_id": command_id,
                "deadline_at": time.time() + timeout,
                "effort": effort,
                "model": model,
                "offset": offset,
                "session_id": session_id,
                "transcript": str(transcript),
                "turn_id": turn_id,
            }
        )
        answer = _wait_for_completion(
            transcript,
            offset,
            turn_id,
            timeout,
            stop_event,
        )
        _audit("turn_completed", command_id=command_id, session_id=session_id, turn_id=turn_id, answer_chars=len(answer))
    except AgentError as exc:
        if str(exc) == "agent-stopping":
            if turn_id:
                _audit("turn_handoff", command_id=command_id, session_id=session_id, turn_id=turn_id)
                return "interrupted"
            try:
                release_command(config, command_id, attempts, "agent-stopping-before-turn-bound", writer_epoch)
            except AgentError:
                pass
            _audit("turn_released", command_id=command_id, session_id=session_id, reason="agent-stopping")
            return "interrupted"
        _audit("turn_failed", command_id=command_id, session_id=session_id, error=str(exc)[:160])
        proof = "absent" if not turn_id and not _new_user_message_present(transcript, offset, text) else "present" if turn_id or _new_user_message_present(transcript, offset, text) else "unknown"
        _complete_failed_command(config, command_id, str(exc), session_id, attempts, writer_epoch, proof, turn_id)
        _clear_inflight_command(command_id)
        return "failed"
    except (OSError, RuntimeError, ValueError) as exc:
        _audit("turn_failed", command_id=command_id, session_id=session_id, error=type(exc).__name__)
        proof = "absent" if not turn_id and not _new_user_message_present(transcript, offset, text) else "present" if turn_id else "unknown"
        _complete_failed_command(config, command_id, type(exc).__name__, session_id, attempts, writer_epoch, proof, turn_id)
        _clear_inflight_command(command_id)
        return "failed"
    complete_request(
        config,
        {
            "command_id": command_id,
            "attempts": attempts,
            "writer_epoch": writer_epoch,
            "status": "completed",
            "turn_id": turn_id,
            "result": {
                "answer": answer,
                "session_id": session_id,
                "model": model,
                "effort": effort,
            },
        },
    )
    _clear_inflight_command(command_id)
    return "completed"


def renew_command_lease(
    config: dict[str, str], command_id: str, attempts: int, lease_seconds: int, writer_epoch: int = 0
) -> dict[str, Any]:
    """Renew one claimed command without waiting for its Codex turn."""

    return api_request(
        config,
        "/v1/agent/renew",
        payload={
            "command_id": command_id,
            "attempts": attempts,
            "writer_epoch": writer_epoch,
            "lease_seconds": lease_seconds,
        },
    )


def _lease_renew_loop(
    config: dict[str, str],
    command_id: str,
    attempts: int,
    lease_seconds: int,
    stop_event: threading.Event,
    writer_epoch: int = 0,
) -> None:
    interval = min(
        max(2.0, float(_config_value(config, "TLS_AGENT_LEASE_RENEW_INTERVAL", str(DEFAULT_LEASE_RENEW_INTERVAL)))),
        max(2.0, lease_seconds / 2),
    )
    while not stop_event.wait(interval):
        try:
            renew_command_lease(config, command_id, attempts, lease_seconds, writer_epoch)
        except AgentError as error:
            _audit("command_lease_renew_failed", command_id=command_id, attempts=attempts, writer_epoch=writer_epoch, error=str(error)[:160])
            _request_failure_repair(config, "command-lease-renew-failed", command_id=command_id)


def process_command(
    config: dict[str, str],
    command: dict[str, Any],
    stop_event: threading.Event | None = None,
) -> str:
    """Execute one command while an independent thread renews its lease."""

    command_id = str(command.get("command_id", "")).strip()
    attempts = int(command.get("attempts", 0) or 0)
    writer_epoch = int(command.get("writer_epoch", 0) or 0)
    if not command_id or attempts < 1:
        return _process_command(config, command, stop_event)
    lease_seconds = max(
        10,
        int(_config_value(config, "TLS_AGENT_COMMAND_LEASE_SECONDS", str(DEFAULT_COMMAND_LEASE_SECONDS))),
    )
    lease_stop = threading.Event()
    renewer = threading.Thread(
        target=_lease_renew_loop,
        args=(config, command_id, attempts, lease_seconds, lease_stop, writer_epoch),
        name=f"tls-agent-lease-{command_id[-8:]}",
        daemon=True,
    )
    renewer.start()
    try:
        return _process_command(config, command, stop_event)
    finally:
        lease_stop.set()
        renewer.join(timeout=1.0)


def _wait_for_recovered_completion(
    config: dict[str, str],
    command_id: str,
    attempts: int,
    transcript: Path,
    offset: int,
    turn_id: str,
    timeout: float,
    stop_event: threading.Event | None,
    writer_epoch: int = 0,
) -> str:
    """Keep a restarted Agent's original command lease while awaiting its turn."""

    if attempts < 1:
        return _wait_for_completion(transcript, offset, turn_id, timeout, stop_event)
    lease_seconds = max(
        10,
        int(_config_value(config, "TLS_AGENT_COMMAND_LEASE_SECONDS", str(DEFAULT_COMMAND_LEASE_SECONDS))),
    )
    lease_stop = threading.Event()
    renewer = threading.Thread(
        target=_lease_renew_loop,
        args=(config, command_id, attempts, lease_seconds, lease_stop, writer_epoch),
        name=f"tls-agent-recovery-lease-{command_id[-8:]}",
        daemon=True,
    )
    renewer.start()
    try:
        return _wait_for_completion(transcript, offset, turn_id, timeout, stop_event)
    finally:
        lease_stop.set()
        renewer.join(timeout=1.0)


def recover_inflight_command(
    config: dict[str, str], stop_event: threading.Event | None = None
) -> str:
    """Finish the exact Codex turn accepted before a local Agent restart."""

    record = _load_inflight_command()
    if record is None:
        return "none"
    command_id = str(record.get("command_id", "")).strip()
    session_id = str(record.get("session_id", "")).strip().lower()
    turn_id = str(record.get("turn_id", "")).strip()
    transcript = Path(str(record.get("transcript", "")))
    try:
        offset = int(record.get("offset", 0) or 0)
        deadline_at = float(record.get("deadline_at", 0) or 0)
        attempts = int(record.get("attempts", 0) or 0)
        writer_epoch = int(record.get("writer_epoch", 0) or 0)
    except (TypeError, ValueError):
        _clear_inflight_command()
        return "invalid"
    if not command_id or not session_id or not turn_id or not transcript.is_file():
        _clear_inflight_command()
        return "invalid"
    timeout = max(10.0, deadline_at - time.time()) if deadline_at else DEFAULT_TURN_TIMEOUT
    try:
        answer = _wait_for_recovered_completion(
            config, command_id, attempts, transcript, offset, turn_id, timeout, stop_event, writer_epoch
        )
    except AgentError as exc:
        if str(exc) == "agent-stopping":
            _audit("turn_handoff", command_id=command_id, session_id=session_id, turn_id=turn_id)
            return "interrupted"
        _audit("turn_failed", command_id=command_id, session_id=session_id, error=str(exc)[:160])
        complete_request(
            config,
            {
                "command_id": command_id,
                "attempts": attempts,
                "writer_epoch": writer_epoch,
                "status": "failed",
                "error": str(exc)[:500],
                "turn_id": turn_id,
                "result": {"session_id": session_id},
            },
        )
        if str(exc) == "turn-aborted":
            _request_failure_repair(config, "turn-aborted", session_id, command_id)
        _clear_inflight_command(command_id)
        return "failed"
    _audit("turn_recovered", command_id=command_id, session_id=session_id, turn_id=turn_id, answer_chars=len(answer))
    complete_request(
        config,
        {
            "command_id": command_id,
            "attempts": attempts,
            "writer_epoch": writer_epoch,
            "status": "completed",
            "turn_id": turn_id,
            "result": {
                "answer": answer,
                "session_id": session_id,
                "model": str(record.get("model", "")),
                "effort": str(record.get("effort", "")),
            },
        },
    )
    _clear_inflight_command(command_id)
    return "completed"


def poll_once(config: dict[str, str], stop_event: threading.Event | None = None) -> int:
    payload = api_request(config, "/v1/agent/commands")
    commands = payload.get("commands", [])
    if not isinstance(commands, list):
        raise AgentError("commands 响应格式无效")
    completed = 0
    for command in commands:
        if stop_event is not None and stop_event.is_set():
            break
        if not isinstance(command, dict):
            continue
        state = process_command(config, command, stop_event)
        completed += int(state == "completed")
    return completed


def _write_env(path: Path, values: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        "".join(f"{key}={value}\n" for key, value in values.items()),
        encoding="utf-8",
    )
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
    os.chmod(path, 0o600)


def pair(args: argparse.Namespace) -> int:
    config = load_env(Path(args.config))
    config["TLS_AGENT_URL"] = gateway_base_url(args.url)
    result = api_request(
        config,
        "/v1/agent/pair",
        payload={"code": args.code, "name": args.name, "hostname": args.hostname},
        authenticated=False,
    )
    values = dict(config)
    values.update({
        "TLS_AGENT_URL": config["TLS_AGENT_URL"],
        "TLS_AGENT_TOKEN": str(result["token"]),
        "TLS_AGENT_INSTALLATION_ID": str(result["installation_id"]),
        "TLS_AGENT_RECOVERY_ENABLED": "1",
    })
    if args.session_id:
        values["TLS_AGENT_SESSION_IDS"] = args.session_id.lower()
    _write_env(Path(args.config), values)
    print({"paired": True, "installation_id": values["TLS_AGENT_INSTALLATION_ID"], "config": str(args.config)})
    return 0


def channel_command(config: dict[str, str], args: argparse.Namespace) -> int:
    command = str(args.command)
    if command == "channel-list":
        result = api_request(
            config,
            "/v1/agent/channels?task_id=" + urllib.parse.quote(str(args.task_id), safe=""),
        )
    elif command == "channel-request":
        result = api_request(
            config,
            "/v1/agent/channel/request",
            payload={
                "task_id": args.task_id,
                "from_run_id": args.from_run_id,
                "to_run_id": args.to_run_id,
                "capabilities": args.capability,
                "ttl_seconds": args.ttl_seconds,
            },
        )
    elif command == "channel-accept":
        result = api_request(
            config,
            "/v1/agent/channel/accept",
            payload={"channel_id": args.channel_id, "accepting_run_id": args.run_id},
        )
    elif command == "channel-revoke":
        result = api_request(
            config,
            "/v1/agent/channel/revoke",
            payload={"channel_id": args.channel_id},
        )
    elif command == "channel-send":
        try:
            message_payload = json.loads(args.payload_json)
        except json.JSONDecodeError as exc:
            raise AgentError("payload-json 必须是 JSON") from exc
        if not isinstance(message_payload, dict):
            raise AgentError("payload-json 必须是 JSON 对象")
        result = api_request(
            config,
            "/v1/agent/channel/message",
            payload={
                "channel_id": args.channel_id,
                "sender_run_id": args.run_id,
                "message_id": args.message_id,
                "payload": message_payload,
            },
        )
    elif command == "channel-poll":
        result = api_request(
            config,
            "/v1/agent/channel/poll",
            payload={
                "channel_id": args.channel_id,
                "recipient_run_id": args.run_id,
                "limit": args.limit,
                "lease_seconds": args.lease_seconds,
            },
        )
    else:
        result = api_request(
            config,
            "/v1/agent/channel/ack",
            payload={
                "message_id": args.message_id,
                "recipient_run_id": args.run_id,
                "status": args.status,
            },
        )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def _heartbeat_loop(
    config: dict[str, str], heartbeat_interval: float, stop_event: threading.Event
) -> None:
    interval = max(MIN_HEARTBEAT_INTERVAL, heartbeat_interval)
    while not stop_event.is_set():
        started = time.monotonic()
        try:
            launch_recovery_tickets(config, heartbeat_once(config))
        except Exception as error:
            _audit("heartbeat_failed", error=f"{type(error).__name__}:{str(error)[:160]}")
            _request_failure_repair(config, f"heartbeat-failed:{type(error).__name__}")
        stop_event.wait(max(0.0, started + interval - time.monotonic()))


def daemon(config: dict[str, str], heartbeat_interval: float, poll_interval: float) -> int:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)
    lock_path = STATE_DIR / "agent.lock"
    with lock_path.open("a+", encoding="utf-8") as lock:
        os.chmod(lock_path, 0o600)
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0
        stop_event = threading.Event()

        def stop(_signum: int, _frame: object) -> None:
            stop_event.set()

        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGTERM, stop)
        heartbeat_thread = threading.Thread(
            target=_heartbeat_loop,
            args=(config, heartbeat_interval, stop_event),
            name="tls-agent-heartbeat",
            daemon=True,
        )
        heartbeat_thread.start()
        try:
            recovered = recover_inflight_command(config, stop_event)
            if recovered == "interrupted":
                return 0
            while not stop_event.is_set():
                try:
                    poll_once(config, stop_event)
                except AgentError:
                    pass
                stop_event.wait(max(0.2, poll_interval))
        finally:
            stop_event.set()
            heartbeat_thread.join(timeout=1.0)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=str(CONFIG_FILE))
    sub = parser.add_subparsers(dest="command", required=True)
    pair_parser = sub.add_parser("pair")
    pair_parser.add_argument("--url", required=True)
    pair_parser.add_argument("--code", required=True)
    pair_parser.add_argument("--name", default="用户端 TLS Agent")
    pair_parser.add_argument("--hostname", default=os.uname().nodename)
    pair_parser.add_argument("--session-id", default="")
    pair_parser.set_defaults(func=pair)
    sub.add_parser("heartbeat")
    sub.add_parser("poll")
    sub.add_parser("status")
    channel_list_parser = sub.add_parser("channel-list")
    channel_list_parser.add_argument("--task-id", required=True)
    channel_request_parser = sub.add_parser("channel-request")
    channel_request_parser.add_argument("--task-id", required=True)
    channel_request_parser.add_argument("--from-run-id", required=True)
    channel_request_parser.add_argument("--to-run-id", required=True)
    channel_request_parser.add_argument("--capability", action="append", required=True)
    channel_request_parser.add_argument("--ttl-seconds", type=int, default=3600)
    channel_accept_parser = sub.add_parser("channel-accept")
    channel_accept_parser.add_argument("--channel-id", required=True)
    channel_accept_parser.add_argument("--run-id", required=True)
    channel_revoke_parser = sub.add_parser("channel-revoke")
    channel_revoke_parser.add_argument("--channel-id", required=True)
    channel_send_parser = sub.add_parser("channel-send")
    channel_send_parser.add_argument("--channel-id", required=True)
    channel_send_parser.add_argument("--run-id", required=True)
    channel_send_parser.add_argument("--message-id", required=True)
    channel_send_parser.add_argument("--payload-json", required=True)
    channel_poll_parser = sub.add_parser("channel-poll")
    channel_poll_parser.add_argument("--channel-id", required=True)
    channel_poll_parser.add_argument("--run-id", required=True)
    channel_poll_parser.add_argument("--limit", type=int, default=20)
    channel_poll_parser.add_argument("--lease-seconds", type=int, default=120)
    channel_ack_parser = sub.add_parser("channel-ack")
    channel_ack_parser.add_argument("--message-id", required=True)
    channel_ack_parser.add_argument("--run-id", required=True)
    channel_ack_parser.add_argument("--status", choices=("acknowledged", "rejected"), default="acknowledged")
    daemon_parser = sub.add_parser("daemon")
    daemon_parser.add_argument("--heartbeat-interval", type=float, default=DEFAULT_HEARTBEAT_INTERVAL)
    daemon_parser.add_argument("--poll-interval", type=float, default=DEFAULT_POLL_INTERVAL)
    args = parser.parse_args()
    if args.command == "pair":
        try:
            return pair(args)
        except (AgentError, ValueError) as exc:
            parser.error(str(exc))
    config = load_env(Path(args.config))
    if args.command == "heartbeat":
        print(json.dumps(heartbeat_once(config), ensure_ascii=False, indent=2))
        return 0
    if args.command == "poll":
        print({"completed": poll_once(config)})
        return 0
    if args.command == "status":
        status = api_request(config, "/v1/agent/info")
        status["local_release_id"] = RELEASE_ID
        status["local_protocol_version"] = PROTOCOL_VERSION
        status["recovery_config"] = recovery_config_status(config)
        print(json.dumps(status, ensure_ascii=False, indent=2))
        return 0
    if args.command.startswith("channel-"):
        return channel_command(config, args)
    return daemon(config, args.heartbeat_interval, args.poll_interval)


if __name__ == "__main__":
    raise SystemExit(main())
