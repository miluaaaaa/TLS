"""Runtime discovery and state helpers for mobile Codex replies."""

from __future__ import annotations

import base64
import datetime as dt
import json
import os
import re
import stat
import tempfile
from pathlib import Path


CONFIG_PATH = Path(
    os.environ.get("TLS_MOBILE_REPLY_CONFIG", str(Path.home() / ".config/tls/mobile-reply.env"))
)
STATE_DIR = Path(
    os.environ.get("TLS_MOBILE_REPLY_STATE_DIR", str(Path.home() / ".local/state/tls/mobile-reply"))
)
SESSION_ID = re.compile(r"^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$")
_configured_roots = os.environ.get("TLS_CODEX_RUNTIME_ROOTS", "")
RUNTIME_ROOTS = (
    tuple(Path(value) for value in _configured_roots.split(":") if value)
    if _configured_roots
    else (
        Path.home() / ".codex/app-server-control/cv-hotplug",
    )
)


def atomic_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def load_env(path: Path = CONFIG_PATH) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key in {"WORKER_URL", "LINK_SECRET", "POLL_TOKEN"} and value:
            values[key] = value
    return values


def runtime_value(path: Path, key: str) -> str:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ""
    prefix = f"{key}="
    return next((line[len(prefix) :].strip() for line in lines if line.startswith(prefix)), "")


def process_state(pid: int) -> str:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").split()
    except OSError:
        return ""
    return fields[2] if len(fields) > 2 else ""


def resumed_session_from_process(pid: int) -> str:
    try:
        arguments = [
            item.decode("utf-8", errors="replace")
            for item in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            if item
        ]
        resume_index = arguments.index("resume")
    except (OSError, ValueError):
        return ""
    return next((argument.lower() for argument in arguments[resume_index + 1 :] if SESSION_ID.fullmatch(argument)), "")


def transcript_started_at(path: Path) -> float | None:
    try:
        with path.open(encoding="utf-8", errors="replace") as handle:
            for _ in range(8):
                record = json.loads(handle.readline())
                value = record.get("timestamp")
                if isinstance(value, str):
                    return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    return None


def valid_runtime(runtime_file: Path) -> dict[str, object] | None:
    socket_path = Path(runtime_value(runtime_file, "socket"))
    try:
        client_pid_text = (runtime_file.parent / "client.pid").read_text(encoding="utf-8").strip()
        client_pid = int(client_pid_text)
        os.kill(client_pid, 0)
        metadata = socket_path.stat()
        socket_path.resolve(strict=False).relative_to(runtime_file.parent.parent.resolve())
    except (OSError, ValueError):
        return None
    if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.getuid() or process_state(client_pid) in {"T", "Z", "X"}:
        return None
    started = runtime_value(runtime_file, "started_at")
    try:
        started_at = dt.datetime.fromisoformat(started.replace("Z", "+00:00")).timestamp()
    except ValueError:
        started_at = 0.0
    return {
        "socket": str(socket_path),
        "client_pid": client_pid,
        "session_id": runtime_value(runtime_file, "session_id") or resumed_session_from_process(client_pid),
        "started_at": started_at,
    }


def resolve_runtime(
    session_id: str,
    transcript: Path,
    roots: tuple[Path, ...] = RUNTIME_ROOTS,
) -> dict[str, object] | None:
    candidates = [
        candidate
        for root in roots
        if root.is_dir()
        for runtime_file in root.glob("session.*/runtime.env")
        if (candidate := valid_runtime(runtime_file)) is not None
    ]
    exact = [candidate for candidate in candidates if candidate["session_id"] == session_id]
    if len(exact) == 1:
        return exact[0]
    if exact:
        return None
    started_at = transcript_started_at(transcript)
    if started_at is None:
        return None
    nearby = sorted(candidates, key=lambda candidate: abs(float(candidate["started_at"]) - started_at))
    if not nearby or abs(float(nearby[0]["started_at"]) - started_at) > 20:
        return None
    if len(nearby) > 1 and abs(float(nearby[1]["started_at"]) - started_at) - abs(float(nearby[0]["started_at"]) - started_at) < 3:
        return None
    return nearby[0]


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def route_path(route_id: str) -> Path:
    return STATE_DIR / "routes" / f"{route_id}.json"
