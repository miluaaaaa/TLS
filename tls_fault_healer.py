#!/usr/bin/env python3
"""Portable TLS Fault Healer installed by the TLS pairing helper.

Local TLS bridges report hard delivery failures with ``trigger``.  This
component records one pending incident and starts one bounded, local Codex
repair session.  It deliberately has no authority to replay user messages or
touch a remote TLS gateway.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


STATE_ROOT = Path.home() / ".local/state/tls-fault-healer"
STATE_FILE = STATE_ROOT / "state.json"
LOCK_FILE = STATE_ROOT / "repair.lock"
COOLDOWN_SECONDS = 60


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def _load_state() -> dict[str, Any]:
    try:
        value = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _session_alive(name: str) -> bool:
    return bool(name) and subprocess.run(
        ["tmux", "has-session", "-t", name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0


def _prompt(event: dict[str, Any]) -> str:
    return f"""You are an isolated TLS Fault Healer. A local TLS delivery failure was reported: {json.dumps(event, ensure_ascii=False)}.

Diagnose only this machine. Inspect user-level TLS services and journals, the local TLS bridge configuration, and any configured local proxy. You may restart the local TLS bridge, its independent heartbeat service/timer, or its local managed proxy only when current evidence supports that repair.

Do not modify remote TLS gateway or Feishu configuration. Do not resume, restart, duplicate, rebind, or send messages to a Codex conversation. Do not replay the failed user message. Record the diagnosis and verification in the local fault-healer state directory, then exit when resolved or blocked."""


def _run_repair() -> int:
    state = _load_state()
    event = state.get("pending_event")
    if not isinstance(event, dict):
        return 0
    active = str(state.get("active_session", ""))
    now = int(time.time())
    if _session_alive(active):
        state.update({"last_decision": "active-repair-session", "last_checked_at": now})
        _atomic_json(STATE_FILE, state)
        return 0
    if now - int(state.get("last_launch_at", 0) or 0) < COOLDOWN_SECONDS:
        state.update({"last_decision": "cooldown", "last_checked_at": now})
        _atomic_json(STATE_FILE, state)
        return 0
    if shutil.which("tmux") is None or shutil.which("codex") is None:
        state.update({"last_decision": "runtime-unavailable", "last_checked_at": now})
        _atomic_json(STATE_FILE, state)
        return 1
    session = f"tmux-OMXTLSRepair{time.strftime('%Y%m%d%H%M%S')}{secrets.token_hex(3)}"
    command = [
        "codex", "exec", "--model", "gpt-5.6-terra", "-c", 'model_reasoning_effort="medium"',
        "--dangerously-bypass-approvals-and-sandbox", "--cd", str(Path.home()),
        "--skip-git-repo-check", _prompt(event),
    ]
    try:
        subprocess.run(
            ["tmux", "new-session", "-d", "-s", session, "-c", str(Path.home()), *command],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as error:
        state.update({"last_decision": "launch-failed", "last_error": type(error).__name__, "last_checked_at": now})
        _atomic_json(STATE_FILE, state)
        return 1
    state.update({
        "active_session": session, "last_launch_at": now, "last_decision": "launched",
        "last_checked_at": now, "last_event": event,
    })
    state.pop("pending_event", None)
    _atomic_json(STATE_FILE, state)
    return 0


def trigger(reason: str, session_id: str, command_id: str) -> int:
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_ROOT, 0o700)
    with LOCK_FILE.open("a+", encoding="utf-8") as lock:
        os.chmod(LOCK_FILE, 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        state = _load_state()
        state["pending_event"] = {
            "at": int(time.time()), "reason": reason[:240],
            "session_id": session_id[:80], "command_id": command_id[:80],
        }
        _atomic_json(STATE_FILE, state)
    result = subprocess.run(
        ["systemctl", "--user", "start", "--no-block", "tls-fault-healer.service"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
    )
    return 0 if result.returncode == 0 else run()


def run() -> int:
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_ROOT, 0o700)
    with LOCK_FILE.open("a+", encoding="utf-8") as lock:
        os.chmod(LOCK_FILE, 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        return _run_repair()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    trigger_parser = sub.add_parser("trigger")
    trigger_parser.add_argument("--reason", required=True)
    trigger_parser.add_argument("--session-id", default="")
    trigger_parser.add_argument("--command-id", default="")
    sub.add_parser("run")
    args = parser.parse_args(argv)
    if args.command == "trigger":
        return trigger(args.reason, args.session_id, args.command_id)
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
