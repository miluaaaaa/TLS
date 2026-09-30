#!/usr/bin/env python3
"""Notify when an active local Codex session completes a task."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import logging
import os
import re
import signal
import sqlite3
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from codex_completion_watch import is_goal_context, primary_completion_context
from codex_transcript_events import (
    canonical_transcript as canonical_transcript,
    function_call_answered as function_call_answered,
    read_events as read_events,
    read_new_events as _read_new_events,
    request_user_input as request_user_input,
    request_user_input_pending as request_user_input_pending,
    task_complete as task_complete,
    visible_plan_before as visible_plan_before,
)
from session_policy import is_session_excluded, session_label


DEFAULT_STATE_DIR = Path.home() / ".local/state/tls/codex-session-watch"
DEFAULT_INTERVAL = 180.0
MAX_PENDING_RETRIES_PER_POLL = 5
PENDING_RETRY_INTERVAL = 60
STATE_VERSION = 1
SESSION_ID = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$", re.IGNORECASE)
ROLLOUT_ID = re.compile(r"rollout-[^/]*-([0-9a-f]{8}-[0-9a-f-]{27,})\.jsonl$", re.IGNORECASE)
CONTROLLER_TMUX = re.compile(r"(?:^|[-_])(?:TCX|OMX)[A-Za-z0-9]*$", re.IGNORECASE)
SHELL_NAMES = {"bash", "dash", "fish", "nu", "pwsh", "sh", "zsh"}
LOGGER = logging.getLogger("tls.codex_session_watch")


def state_dir() -> Path:
    return Path(os.environ.get("TLS_CODEX_SESSION_STATE_DIR", str(DEFAULT_STATE_DIR)))


def session_roots() -> list[Path]:
    configured = os.environ.get("TLS_CODEX_SESSION_ROOTS")
    if configured:
        return [Path(value) for value in configured.split(":") if value]
    codex_home = Path(os.environ.get("TLS_CODEX_HOME", os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))))
    recovery_home = os.environ.get("TLS_CODEX_RECOVERY_HOME", "")
    return [codex_home / "sessions"] + ([Path(recovery_home) / "sessions"] if recovery_home else [])


def ensure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


def atomic_json(path: Path, payload: object) -> None:
    ensure_directory(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise


def load_json(path: Path) -> dict[str, object]:
    empty = {"version": STATE_VERSION, "initialized": False, "files": {}, "pending": {}}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return empty
    if not isinstance(payload, dict) or payload.get("version") != STATE_VERSION or not isinstance(payload.get("files"), dict):
        return empty
    if not isinstance(payload.get("pending"), dict):
        payload["pending"] = {}
    return payload


def _process_rows() -> list[dict[str, object]]:
    try:
        output = subprocess.run(
            ["ps", "-eo", "pid=,ppid=,tty=,stat=,comm="],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    rows: list[dict[str, object]] = []
    for line in output.splitlines():
        parts = line.split(None, 4)
        if len(parts) != 5:
            continue
        try:
            rows.append({"pid": int(parts[0]), "ppid": int(parts[1]), "tty": parts[2], "stat": parts[3], "comm": parts[4]})
        except ValueError:
            continue
    return rows


def _tmux_panes() -> dict[str, tuple[str, bool]]:
    try:
        output = subprocess.run(
            ["tmux", "list-panes", "-a", "-F", "#{pane_tty}\t#{session_name}\t#{session_attached}"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return {}
    panes: dict[str, tuple[str, bool]] = {}
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) == 3:
            panes[parts[0].removeprefix("/dev/")] = (parts[1], parts[2].isdigit() and int(parts[2]) > 0)
    return panes


def _proc_value(pid: int, name: str) -> bytes:
    try:
        return (Path("/proc") / str(pid) / name).read_bytes()
    except OSError:
        return b""


def _candidate_ids(pid: int, parents: dict[int, int]) -> list[str]:
    candidates: list[str] = []
    client_arguments = [
        item.decode("utf-8", errors="ignore")
        for item in _proc_value(pid, "cmdline").split(b"\0")
        if item
    ]
    remote_client = "--remote" in client_arguments
    environment = _proc_value(pid, "environ")
    inherited_thread_ids: list[str] = []
    for item in environment.split(b"\0"):
        if item.startswith(b"CODEX_THREAD_ID="):
            inherited_thread_ids.append(item.partition(b"=")[2].decode("ascii", errors="ignore").lower())

    current = pid
    for _ in range(8):
        arguments = [
            item.decode("utf-8", errors="ignore")
            for item in _proc_value(current, "cmdline").split(b"\0")
            if item
        ]
        for index, argument in enumerate(arguments):
            if argument not in {"resume", "fork"}:
                continue
            match = next((item for item in arguments[index + 1 :] if SESSION_ID.fullmatch(item)), "")
            if match:
                candidates.append(match.lower())
        current = parents.get(current, 0)
        if current <= 1:
            break

    try:
        descriptors = (Path("/proc") / str(pid) / "fd").iterdir()
        for descriptor in descriptors:
            try:
                match = ROLLOUT_ID.search(os.readlink(descriptor))
            except OSError:
                continue
            if match:
                candidates.append(match.group(1).lower())
    except OSError:
        pass
    # A terminal wrapper or long-lived tmux server may inherit a stale
    # CODEX_THREAD_ID. Prefer the rollout actually opened by this Codex process.
    # A remote app-server client can create or select a different thread while
    # retaining the launcher's stale CODEX_THREAD_ID. Require an explicit
    # terminal binding when no rollout descriptor identifies the live thread.
    if not remote_client:
        candidates.extend(inherited_thread_ids)
    return list(dict.fromkeys(value for value in candidates if value))


def _user_cli_session_ids(candidates: set[str]) -> set[str]:
    """Return visible user sessions launched by a local Codex frontend.

    Codex records terminal sessions launched through the regular CLI as
    ``source='cli'`` and sessions launched through an app-server-backed
    frontend as ``source='vscode'``. A persisted exec thread is also valid
    after it has been resumed in a visible terminal. Candidate IDs already
    come exclusively from live TTY Codex processes, while agent/controller
    threads remain excluded by the ``thread_source`` predicate below.
    """
    if not candidates:
        return set()
    configured = os.environ.get("TLS_CODEX_STATE_DATABASES", "")
    codex_home = Path(os.environ.get("TLS_CODEX_HOME", os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))))
    databases = [Path(value) for value in configured.split(":") if value] if configured else sorted(codex_home.glob("state_*.sqlite"))
    accepted: set[str] = set()
    placeholders = ",".join("?" for _ in candidates)
    for database in databases:
        try:
            with sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=1) as connection:
                rows = connection.execute(
                    f"SELECT id FROM threads WHERE id IN ({placeholders}) "
                    "AND source IN ('cli', 'vscode', 'exec') AND thread_source = 'user'",
                    tuple(candidates),
                ).fetchall()
        except (OSError, sqlite3.Error):
            continue
        accepted.update(str(row[0]).lower() for row in rows)
    return accepted


def _terminal_shell_pid(pid: int, parents: dict[int, int]) -> int:
    current = pid
    fallback = 0
    for _ in range(12):
        parent = parents.get(current, 0)
        if parent <= 1:
            return fallback
        if b"--type=ptyHost" in _proc_value(parent, "cmdline"):
            return current
        arguments = [item for item in _proc_value(parent, "cmdline").split(b"\0") if item]
        if arguments and Path(arguments[0].decode("utf-8", errors="ignore")).name in SHELL_NAMES:
            fallback = parent
        current = parent
    return fallback


def _process_start_time(pid: int) -> str:
    try:
        suffix = (Path("/proc") / str(pid) / "stat").read_text(encoding="ascii").rsplit(")", 1)[1].split()
    except (OSError, IndexError):
        return ""
    return suffix[19] if len(suffix) > 19 else ""


def _owned_process(pid: int) -> bool:
    try:
        return (Path("/proc") / str(pid)).stat().st_uid == os.getuid()
    except OSError:
        return False


def _terminal_identity(pid: int, tty: str, tmux: tuple[str, bool] | None) -> str:
    backend = f"tmux:{tmux[0]}" if tmux is not None else "terminal"
    return f"v1|{backend}|{tty}|{pid}|{_process_start_time(pid)}"


def terminal_token(record: dict[str, object]) -> str:
    identity = str(record.get("identity", ""))
    return hashlib.sha256(f"tls-terminal:{identity}".encode("utf-8")).hexdigest()[:16] if identity else ""


def terminal_bindings_file() -> Path:
    return state_dir() / "terminal-bindings.json"


def _load_terminal_bindings() -> dict[str, dict[str, object]]:
    try:
        payload = json.loads(terminal_bindings_file().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    bindings = payload.get("bindings") if isinstance(payload, dict) else None
    if not isinstance(bindings, dict):
        return {}
    return {str(key): dict(value) for key, value in bindings.items() if isinstance(value, dict)}


def _explicit_detached_session_ids() -> set[str]:
    raw = os.environ.get("TLS_ALLOW_DETACHED_SESSION_IDS", "")
    return {
        value.strip().lower()
        for value in raw.replace(";", ",").split(",")
        if SESSION_ID.fullmatch(value.strip())
    }


def _monitor_detached_tmux() -> bool:
    return os.environ.get("TLS_MONITOR_DETACHED_TMUX", "0").strip().lower() in {"1", "true", "yes", "on"}


def _scan_terminal_records(apply_bindings: bool = True) -> list[dict[str, object]]:
    rows = _process_rows()
    parents = {int(row["pid"]): int(row["ppid"]) for row in rows}
    tmux_panes = _tmux_panes()
    allowed_detached = _explicit_detached_session_ids()
    candidate_groups: list[tuple[int, str, tuple[str, bool] | None, list[str]]] = []
    for row in rows:
        if row["comm"] != "codex" or row["tty"] == "?" or "Z" in str(row["stat"]):
            continue
        pid = int(row["pid"])
        if not _owned_process(pid):
            continue
        tty = str(row["tty"]).removeprefix("/dev/")
        tmux = tmux_panes.get(tty)
        candidates = _candidate_ids(pid, parents)
        if tmux is not None:
            session_name, attached = tmux
            if CONTROLLER_TMUX.search(session_name) or (
                not attached
                and not _monitor_detached_tmux()
                and not any(session_id in allowed_detached for session_id in candidates)
            ):
                continue
        candidate_groups.append((pid, tty, tmux, candidates))
    accepted = _user_cli_session_ids({value for _pid, _tty, _tmux, group in candidate_groups for value in group})
    records: list[dict[str, object]] = []
    for pid, tty, tmux, group in candidate_groups:
        shell_pid = _terminal_shell_pid(pid, parents)
        if not shell_pid and tmux is None:
            continue
        session_id = next((value for value in group if value in accepted), "")
        identity = _terminal_identity(pid, tty, tmux)
        records.append(
            {
                "identity": identity,
                "token": hashlib.sha256(f"tls-terminal:{identity}".encode("utf-8")).hexdigest()[:16],
                "session_id": session_id,
                "codex_pid": pid,
                "shell_pid": shell_pid,
                "tty": tty,
                "backend": "tmux" if tmux is not None else "terminal",
                "terminal_name": tmux[0] if tmux is not None else tty,
                "binding_source": "automatic" if session_id else "unresolved",
            }
        )
    if not apply_bindings:
        return records
    bindings = _load_terminal_bindings()
    manual_ids = {
        str(binding.get("session_id", ""))
        for binding in bindings.values()
        if isinstance(binding, dict) and str(binding.get("session_id", ""))
    }
    accepted_manual = _user_cli_session_ids(manual_ids)
    for record in records:
        if record["session_id"]:
            continue
        binding = bindings.get(str(record["token"]))
        session_id = str(binding.get("session_id", "")) if isinstance(binding, dict) else ""
        if session_id in accepted_manual and binding.get("identity") == record["identity"]:
            record["session_id"] = session_id
            record["binding_source"] = "manual"
    return records


def active_terminal_records() -> list[dict[str, object]]:
    return _scan_terminal_records(apply_bindings=True)


def unresolved_terminal_records() -> list[dict[str, object]]:
    return [record for record in active_terminal_records() if not record.get("session_id")]


def bind_terminal_session(token: str, session_id: str) -> bool:
    session_id = session_id.strip().lower()
    if not SESSION_ID.fullmatch(session_id) or session_id not in _user_cli_session_ids({session_id}):
        return False
    matches = [
        record
        for record in _scan_terminal_records(apply_bindings=False)
        if record.get("token") == token and not record.get("session_id")
    ]
    if len(matches) != 1:
        return False
    record = matches[0]
    bindings = _load_terminal_bindings()
    bindings[token] = {
        "identity": str(record["identity"]),
        "session_id": session_id,
        "bound_at": int(time.time()),
        "uid": os.getuid(),
    }
    atomic_json(terminal_bindings_file(), {"version": 1, "bindings": bindings})
    return True


def active_session_terminals() -> dict[str, dict[str, object]]:
    terminals: dict[str, dict[str, object]] = {}
    for record in active_terminal_records():
        session_id = str(record.get("session_id", ""))
        if session_id:
            terminals[session_id] = {
                key: record[key]
                for key in ("codex_pid", "shell_pid", "tty", "backend", "terminal_name", "token", "binding_source")
            }
    return terminals


def active_session_ids() -> set[str]:
    return set(active_session_terminals())


def active_session_files() -> dict[str, Path]:
    files: dict[str, Path] = {}
    for session_id in active_session_ids():
        if is_session_excluded(session_id):
            continue
        for root in session_roots():
            try:
                candidates = root.glob(f"**/rollout-*{session_id}*.jsonl")
                path = next((candidate for candidate in candidates if candidate.is_file()), None)
            except OSError:
                path = None
            if path is not None:
                files[session_id] = canonical_transcript(path)
                break
    return files


def queue_mobile_completion(event_key: str, context: dict[str, object]) -> bool:
    """Mirror new local completions to the Cloudflare mobile status feed."""
    if os.environ.get("TLS_MOBILE_COMPLETION_SYNC", "0").strip().lower() not in {"1", "true", "yes", "on"}:
        return False
    try:
        from codex_completion_watch import fallback_summary, topic_with_project
        from tls_notify import queue_codex_summary

        summary = fallback_summary(context, "completed")
        summary["topic"] = topic_with_project(summary.get("topic", ""), context.get("project_label", ""))
        return bool(queue_codex_summary(event_key=event_key, reply_url="", **summary))
    except Exception as error:
        LOGGER.error("TLS mobile completion enqueue failed: event=%s error=%s", event_key, type(error).__name__)
        return False


def local_feishu_delivery_enabled() -> bool:
    """Return whether a live local ingress is expected to consume its outbox."""
    return os.environ.get("TLS_LOCAL_FEISHU_DELIVERY", "0").strip().lower() in {"1", "true", "yes", "on"}


def publish_agent_completion(
    session_id: str,
    conversation: str,
    user_message: str,
    answer: str,
    event_key: str,
) -> bool:
    """Send a completion to the remote private-workspace outbox.

    The same paired Agent credential used by heartbeats authenticates this
    write.  A failed request returns ``False`` so the watcher retains its
    existing durable retry record instead of silently dropping a completion.
    """

    config_path = Path(os.environ.get("TLS_AGENT_CONFIG_FILE", str(Path.home() / ".config/tls/agent.env")))
    try:
        values = {
            key.strip(): value.strip().strip('"').strip("'")
            for raw in config_path.read_text(encoding="utf-8").splitlines()
            if (line := raw.strip()) and not line.startswith("#") and "=" in line
            for key, value in [line.split("=", 1)]
        }
        base_url = str(os.environ.get("TLS_AGENT_URL", values.get("TLS_AGENT_URL", ""))).rstrip("/")
        token = str(os.environ.get("TLS_AGENT_TOKEN", values.get("TLS_AGENT_TOKEN", ""))).strip()
        if not base_url or not token:
            return False
        payload = json.dumps(
            {
                "event_key": event_key,
                "session_id": session_id,
                "conversation": conversation,
                "user_message": user_message,
                "answer": answer,
            },
            ensure_ascii=False,
        ).encode("utf-8")
        request = urllib.request.Request(
            base_url + "/v1/agent/completion-notification",
            data=payload,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json; charset=utf-8",
                "Accept": "application/json",
                "User-Agent": "tls-codex-session-watch/1",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            result = json.loads(response.read(256 * 1024).decode("utf-8"))
        return isinstance(result, dict) and bool(result.get("ok"))
    except (OSError, ValueError, urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError):
        return False


def notify(session_id: str, sequence: int, transcript: Path, event_offset: int | None = None) -> bool:
    if is_session_excluded(session_id) or is_session_excluded(transcript):
        return False
    context = primary_completion_context(transcript, event_offset)
    if context is None or is_goal_context(context):
        return False
    conversation = session_label(session_id) or context.get("project_label", "") or "Codex 对话"
    user_message = context.get("user_request", "") or "未提取到本轮原始消息。"
    answer = context.get("latest_answer", "") or "本轮已经结束，但没有提取到可读回复。"
    event_identity = event_offset if event_offset is not None else sequence
    event_key = f"{canonical_transcript(transcript)}:{event_identity}"
    queue_mobile_completion(event_key, context)
    if publish_agent_completion(session_id, conversation, user_message, answer, event_key):
        return True
    if not local_feishu_delivery_enabled():
        return False
    try:
        from feishu_direct import queue_owner_notification, route_completion

        if route_completion(session_id, user_message, answer):
            return True
        if queue_owner_notification(
            session_id,
            conversation,
            user_message,
            answer,
            event_key,
        ):
            return True
    except Exception as error:
        LOGGER.error(
            "TLS completion notification enqueue failed: session=%s offset=%s error=%s",
            session_id,
            event_offset if event_offset is not None else sequence,
            type(error).__name__,
        )
        pass
    return False


def notify_question(
    session_id: str,
    sequence: int,
    transcript: Path,
    event_offset: int,
    interaction: dict[str, object],
) -> bool:
    """Queue a native Codex input request before the turn can complete."""
    if is_session_excluded(session_id) or is_session_excluded(transcript):
        return False
    context = primary_completion_context(transcript, event_offset)
    if context is None:
        return False
    conversation = session_label(session_id) or context.get("project_label", "") or "Codex 对话"
    questions = interaction.get("questions")
    if not isinstance(questions, list) or not questions:
        return False
    plan = str(interaction.get("plan", "")) or visible_plan_before(transcript, event_offset)
    event_key = f"{canonical_transcript(transcript)}:question:{event_offset}"
    try:
        from feishu_direct import queue_owner_question

        return queue_owner_question(session_id, conversation, plan, questions, event_key)
    except Exception as error:
        LOGGER.error(
            "TLS question notification enqueue failed: session=%s offset=%s error=%s",
            session_id,
            event_offset,
            type(error).__name__,
        )
        return False


def _notification_retryable(session_id: str, transcript: Path, event_offset: int) -> bool:
    """Keep an event retryable unless policy explicitly suppresses it."""
    if is_session_excluded(session_id) or is_session_excluded(transcript):
        return False
    context = primary_completion_context(transcript, event_offset)
    return context is None or not is_goal_context(context)


def _remember_pending_notification(
    pending: dict[str, object],
    event_key: str,
    session_id: str,
    transcript: Path,
    event_offset: int,
    sequence: int,
    terminal_state: str,
    kind: str = "completion",
    interaction: dict[str, object] | None = None,
) -> None:
    previous = pending.get(event_key)
    attempts = int(previous.get("attempts", 0) or 0) + 1 if isinstance(previous, dict) else 1
    pending[event_key] = {
        "session": session_id,
        "state": terminal_state,
        "path": str(transcript),
        "offset": event_offset,
        "sequence": sequence,
        "kind": kind,
        "attempts": attempts,
        "last_attempt_at": int(time.time()),
    }
    if kind == "question" and isinstance(interaction, dict):
        pending[event_key]["plan"] = str(interaction.get("plan", ""))[:6000]
        pending[event_key]["questions"] = interaction.get("questions", [])
        pending[event_key]["call_id"] = str(interaction.get("call_id", ""))[:256]
    if attempts in {1, 10, 60}:
        LOGGER.warning(
            "TLS completion notification deferred: session=%s offset=%s attempts=%s",
            session_id,
            event_offset,
            attempts,
        )


def poll() -> int:
    directory = state_dir()
    ensure_directory(directory)
    lock_path = directory / "poll.lock"
    with lock_path.open("a+", encoding="utf-8") as lock_handle:
        os.chmod(lock_path, 0o600)
        try:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0
        state_path = directory / "state.json"
        state = load_json(state_path)
        files = state["files"]
        assert isinstance(files, dict)
        pending = state.get("pending")
        if not isinstance(pending, dict):
            pending = {}
            state["pending"] = pending
        next_files: dict[str, object] = {}
        alerts = 0
        retry_count = 0
        retry_now = time.time()
        for event_key, record in sorted(
            pending.items(),
            key=lambda item: int(item[1].get("last_attempt_at", 0) or 0) if isinstance(item[1], dict) else 0,
        ):
            if not isinstance(record, dict):
                pending.pop(event_key, None)
                continue
            if retry_count >= MAX_PENDING_RETRIES_PER_POLL:
                break
            if retry_now - int(record.get("last_attempt_at", 0) or 0) < PENDING_RETRY_INTERVAL:
                continue
            retry_count += 1
            session_id = str(record.get("session", ""))
            transcript = Path(str(record.get("path", "")))
            try:
                event_offset = int(record.get("offset", 0) or 0)
                sequence = int(record.get("sequence", 0) or 0)
            except (TypeError, ValueError):
                pending.pop(event_key, None)
                continue
            if not session_id or not transcript:
                pending.pop(event_key, None)
                continue
            kind = str(record.get("kind", "completion"))
            if kind == "question" and function_call_answered(path=transcript, end_offset=event_offset, call_id=str(record.get("call_id", ""))):
                pending.pop(event_key, None)
                continue
            if kind != "question" and not _notification_retryable(session_id, transcript, event_offset):
                pending.pop(event_key, None)
                continue
            if kind == "question":
                sent = notify_question(
                    session_id,
                    sequence,
                    transcript,
                    event_offset,
                    {
                        "call_id": str(record.get("call_id", "")),
                        "plan": str(record.get("plan", "")),
                        "questions": record.get("questions", []),
                    },
                )
            else:
                sent = notify(session_id, sequence, transcript, event_offset)
            if sent:
                alerts += 1
                pending.pop(event_key, None)
            else:
                _remember_pending_notification(
                    pending,
                    event_key,
                    session_id,
                    transcript,
                    event_offset,
                    sequence,
                    str(record.get("state", "completed")),
                    kind=kind,
                    interaction=record if kind == "question" else None,
                )
        for session_id, path in active_session_files().items():
            path = canonical_transcript(path)
            key = str(path)
            previous = files.get(key)
            previous_record = previous if isinstance(previous, dict) else {}
            offset = int(previous_record.get("offset", 0) or 0)
            sequence = int(previous_record.get("sequence", 0) or 0)
            if not previous_record:
                try:
                    offset = path.stat().st_size
                except OSError:
                    continue
                events: list[dict[str, object]] = []
            else:
                offset, events = _read_new_events(path, offset)
            if not previous_record.get("question_recovered", False):
                try:
                    size = path.stat().st_size
                except OSError:
                    size = offset
                recovery_start = max(0, size - 1_000_000)
                _recovery_offset, recovery_events = _read_new_events(path, recovery_start)
                known_questions = {
                    int(event.get("offset", 0) or 0)
                    for event in events
                    if event.get("kind") == "question"
                }
                for event in recovery_events:
                    event_offset = int(event.get("offset", 0) or 0)
                    if event.get("kind") == "question" and event_offset not in known_questions:
                        events.append(event)
                events.sort(key=lambda item: int(item.get("offset", 0) or 0))
            for event in events:
                sequence += 1
                event_offset = int(event.get("offset", 0) or 0)
                event_key = f"{path}:{event_offset}"
                kind = str(event.get("kind", "completion"))
                if kind == "question":
                    interaction = dict(event)
                    interaction["plan"] = visible_plan_before(path, event_offset)
                    sent = notify_question(session_id, sequence, path, event_offset, interaction)
                else:
                    interaction = None
                    sent = notify(session_id, sequence, path, event_offset)
                alerts += int(sent)
                retryable = kind == "question" or _notification_retryable(session_id, path, event_offset)
                if not sent and retryable:
                    _remember_pending_notification(
                        pending,
                        event_key,
                        session_id,
                        path,
                        event_offset,
                        sequence,
                        "completed",
                        kind=kind,
                        interaction=interaction,
                    )
            next_files[key] = {
                "session_id": session_id,
                "offset": offset,
                "sequence": sequence,
                "question_recovered": True,
                "last_observed_at": int(time.time()),
            }
        state["files"] = next_files
        state["initialized"] = True
        atomic_json(state_path, state)
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
    return alerts


def positive(value: str, fallback: float) -> float:
    try:
        return float(value) if float(value) > 0 else fallback
    except ValueError:
        return fallback


def daemon(interval: float) -> int:
    directory = state_dir()
    ensure_directory(directory)
    lock_path = directory / "daemon.lock"
    lock_handle = lock_path.open("a+", encoding="utf-8")
    os.chmod(lock_path, 0o600)
    try:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock_handle.close()
        return 0
    running = True

    def stop(_signum: int, _frame: object) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    try:
        while running:
            poll()
            deadline = time.monotonic() + interval
            while running and time.monotonic() < deadline:
                time.sleep(min(1.0, deadline - time.monotonic()))
    finally:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
        lock_handle.close()
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("poll", "daemon"), nargs="?", default="poll")
    parser.add_argument("--interval", type=float, default=positive(os.environ.get("TLS_CODEX_SESSION_POLL_SECONDS", "180"), DEFAULT_INTERVAL))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    return daemon(positive(str(args.interval), DEFAULT_INTERVAL)) if args.command == "daemon" else poll()


if __name__ == "__main__":
    raise SystemExit(main())
