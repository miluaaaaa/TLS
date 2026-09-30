#!/usr/bin/env python3
"""Shared runtime and idle-state helpers for local Codex watchers."""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Callable


CODEX_PROCESS = re.compile(r"(?:^|\s)(?:\S*/)?codex(?:-real)?(?:\s|$)", re.IGNORECASE)
TMUX_PROCESS = re.compile(r"(?:^|\s)(?:\S*/)?tmux(?:\s|:|$)", re.IGNORECASE)
ORCHESTRATOR_PROCESS = re.compile(
    r"(?:^|\s)(?:\S*/)?omx(?:\s|$)|model_instructions_file=.*(?:/|\\)\.omx(?:/|\\)state",
    re.IGNORECASE,
)
ORCHESTRATION_TRANSCRIPT = re.compile(
    r"model_instructions_file=.*(?:/|\\)\.omx(?:/|\\)state(?:/|\\)sessions",
    re.IGNORECASE,
)
SESSION_UUID = re.compile(r"([0-9a-f]{8}-[0-9a-f-]{27,})$", re.IGNORECASE)
SESSION_START_TOLERANCE_SECONDS = 30.0

ProcessRecord = tuple[str, str, str, bool, float, bool, str]
SnapshotProvider = Callable[[], list[ProcessRecord] | None]


def _has_tmux_ancestor(pid: str, process_table: dict[str, tuple[str, str]]) -> bool:
    """Identify Codex processes launched inside a tmux server, including raw TCX panes."""
    parent_args = process_table.get(pid)
    current = parent_args[0] if parent_args else ""
    visited: set[str] = set()
    while current and current not in visited:
        visited.add(current)
        parent_args = process_table.get(current)
        if parent_args is None:
            return False
        parent, args = parent_args
        if TMUX_PROCESS.search(args):
            return True
        current = parent
    return False


def _unpack_process_record(record: tuple[object, ...]) -> tuple[str, str, str, bool, float, bool, str]:
    """Accept legacy five-field test snapshots while using tmux-aware records at runtime."""
    if len(record) >= 7:
        pid, args, cwd, orchestrator, process_start, in_tmux, tty = record[:7]
        return str(pid), str(args), str(cwd), bool(orchestrator), float(process_start), bool(in_tmux), str(tty)
    if len(record) == 6:
        pid, args, cwd, orchestrator, process_start, in_tmux = record
        return str(pid), str(args), str(cwd), bool(orchestrator), float(process_start), bool(in_tmux), "pts"
    pid, args, cwd, orchestrator, process_start = record[:5]
    return str(pid), str(args), str(cwd), bool(orchestrator), float(process_start), False, "pts"


def process_snapshot() -> list[ProcessRecord] | None:
    """Return active Codex processes with tmux ancestry and terminal metadata."""
    try:
        output = subprocess.run(
            ["ps", "-eo", "pid=,ppid=,tty=,etimes=,args="],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    process_table: dict[str, tuple[str, str]] = {}
    parsed: list[tuple[str, str, str, str, str]] = []
    for raw_line in output.splitlines():
        fields = raw_line.strip().split(maxsplit=4)
        if len(fields) != 5 or not fields[0].isdigit():
            continue
        pid, parent, tty, elapsed_text, args = fields
        process_table[pid] = (parent, args)
        parsed.append((pid, parent, tty, elapsed_text, args))

    processes: list[ProcessRecord] = []
    for pid, _parent, tty, elapsed_text, args in parsed:
        if not CODEX_PROCESS.search(args):
            continue
        try:
            start_epoch = time.time() - float(elapsed_text)
        except ValueError:
            continue
        try:
            cwd = os.readlink(f"/proc/{pid}/cwd")
        except OSError:
            cwd = ""
        processes.append(
            (
                pid,
                args,
                cwd,
                bool(ORCHESTRATOR_PROCESS.search(args)),
                start_epoch,
                _has_tmux_ancestor(pid, process_table),
                tty,
            )
        )
    return processes


def session_tokens(session: str) -> set[str]:
    tokens = {session}
    match = SESSION_UUID.search(session)
    if match:
        tokens.add(match.group(1))
    return tokens


def timestamp_epoch(value: str) -> float | None:
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None


def window_status(
    session: str,
    context: dict[str, str],
    snapshot_provider: SnapshotProvider | None = None,
) -> tuple[bool, bool]:
    """Return (window_is_active, belongs_to_a_silent_runtime)."""
    workspace = context.get("workspace", "")
    workspace_path = ""
    if workspace:
        try:
            workspace_path = str(Path(workspace).resolve())
        except (OSError, RuntimeError, ValueError):
            workspace_path = workspace
    tokens = session_tokens(session)
    session_start = timestamp_epoch(context.get("session_started_at", ""))
    snapshot = (snapshot_provider or process_snapshot)()
    if snapshot is None:
        # Failure to prove that the window has ended is a hard no-notify.
        return True, False
    for record in snapshot:
        _pid, args, cwd, orchestrator, process_start, in_tmux, tty = _unpack_process_record(record)
        session_match = any(token and token in args for token in tokens)
        workspace_match = False
        if workspace_path and cwd:
            try:
                workspace_match = str(Path(cwd).resolve()) == workspace_path
            except (OSError, RuntimeError, ValueError):
                workspace_match = cwd == workspace_path
        start_match = session_start is not None and abs(process_start - session_start) <= SESSION_START_TOLERANCE_SECONDS
        if session_match or (workspace_match and (session_start is None or start_match)):
            return True, orchestrator or in_tmux or tty in {"", "?"}
    return False, False


def user_activity_after(path: Path, offset: int) -> bool:
    """Detect a new user turn after a terminal event waiting to flush."""
    try:
        with path.open("rb") as handle:
            handle.seek(max(0, offset))
            for raw_line in handle:
                try:
                    record = json.loads(raw_line.decode("utf-8", errors="replace"))
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue
                payload = record.get("payload")
                if not isinstance(payload, dict):
                    continue
                if record.get("type") == "event_msg" and payload.get("type") == "user_message":
                    return True
                if record.get("type") == "response_item" and payload.get("type") == "message" and payload.get("role") == "user":
                    return True
    except OSError:
        return False
    return False


def transcript_state(path: Path) -> tuple[int, int] | None:
    """Return the size and mtime used to prove a transcript stayed unchanged."""
    try:
        stat = path.stat()
    except OSError:
        return None
    return stat.st_size, stat.st_mtime_ns
