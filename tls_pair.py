#!/usr/bin/env python3
"""Exchange a private TLS pairing code for a local Agent credential.

This helper is intentionally independent from the user's Codex runtime.  It
only performs the one-time pairing exchange and stores the resulting token in
an owner-readable configuration file.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


DEFAULT_URL = "https://api.xhqcode.com/tls-agent"
DEFAULT_CONFIG = Path.home() / ".config/tls/agent.env"
FAULT_HEALER_SOURCE = Path(__file__).with_name("tls_fault_healer.py")
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


class PairingError(RuntimeError):
    """Expected pairing or gateway failure."""


def _base_url(value: str) -> str:
    base = str(value or "").strip().rstrip("/")
    parsed = urlsplit(base)
    if parsed.scheme == "https" and parsed.hostname:
        return base
    if parsed.scheme == "http" and parsed.hostname in LOCAL_HOSTS:
        return base
    raise PairingError("TLS 网关必须使用 HTTPS；HTTP 只允许本机测试地址")


def _load_config(path: Path) -> dict[str, str]:
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


def _write_config(path: Path, values: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            for key, value in values.items():
                handle.write(f"{key}={value}\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        os.chmod(path, 0o600)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise


def _install_fault_healer(config_path: Path, systemd_dir: Path) -> tuple[Path, str]:
    """Install the portable repair runtime and best-effort user service units."""

    if not FAULT_HEALER_SOURCE.is_file():
        raise PairingError("配对包缺少 TLS Fault Healer")
    runtime_dir = config_path.parent / "runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(runtime_dir, 0o700)
    script = runtime_dir / "tls_fault_healer.py"
    shutil.copyfile(FAULT_HEALER_SOURCE, script)
    os.chmod(script, 0o700)
    systemd_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(systemd_dir, 0o700)
    service = systemd_dir / "tls-fault-healer.service"
    timer = systemd_dir / "tls-fault-healer-retry.timer"
    service.write_text(
        "[Unit]\nDescription=TLS Fault Healer - launch bounded local repair\n\n"
        "[Service]\nType=oneshot\n"
        f"ExecStart={sys.executable} {script} run\nTimeoutStartSec=30\n"
        "NoNewPrivileges=true\nPrivateTmp=true\n",
        encoding="utf-8",
    )
    timer.write_text(
        "[Unit]\nDescription=TLS Fault Healer - retry pending repair\n\n"
        "[Timer]\nOnBootSec=30\nOnUnitInactiveSec=15\nUnit=tls-fault-healer.service\n\n"
        "[Install]\nWantedBy=timers.target\n",
        encoding="utf-8",
    )
    status = "installed-unmanaged"
    try:
        completed = subprocess.run(
            ["systemctl", "--user", "daemon-reload"], check=False,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
        )
        if completed.returncode == 0:
            completed = subprocess.run(
                ["systemctl", "--user", "enable", "--now", "tls-fault-healer-retry.timer"],
                check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
            )
            status = "enabled" if completed.returncode == 0 else "installed-unmanaged"
    except (OSError, subprocess.SubprocessError):
        pass
    return script, status


def _request(url: str, *, token: str = "", payload: dict[str, Any] | None = None) -> dict[str, Any]:
    body = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {"Accept": "application/json", "User-Agent": "tls-pair-helper/1"}
    if body is not None:
        headers["Content-Type"] = "application/json; charset=utf-8"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        url,
        data=body,
        headers=headers,
        method="POST" if body is not None else "GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read(512 * 1024)
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read(64 * 1024).decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            detail = {}
        message = str(detail.get("error", f"gateway-http-{exc.code}"))[:240]
        raise PairingError(message) from exc
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        raise PairingError(f"gateway-unreachable:{type(exc).__name__}") from exc
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PairingError("gateway 返回了无效 JSON") from exc
    if not isinstance(result, dict):
        raise PairingError("gateway 返回格式无效")
    if result.get("ok") is False:
        raise PairingError(str(result.get("error", "gateway-error"))[:240])
    return result


def _pair_code(args: argparse.Namespace) -> str:
    if args.code_stdin:
        value = sys.stdin.read(128)
    else:
        value = args.code
    code = str(value or "").strip().upper()
    if not code or len(code) > 64:
        raise PairingError("配对码为空或过长")
    return code


def pair(args: argparse.Namespace) -> int:
    base = _base_url(args.url)
    code = _pair_code(args)
    result = _request(
        f"{base}/v1/agent/pair",
        payload={
            "code": code,
            "name": str(args.name or "TLS Agent")[:120],
            "hostname": str(args.hostname or socket.gethostname())[:240],
        },
    )
    token = str(result.get("token", ""))
    installation_id = str(result.get("installation_id", ""))
    user_id = str(result.get("user_id", ""))
    if not token or not installation_id or not user_id:
        raise PairingError("配对响应缺少必要字段")
    config_path = Path(args.config).expanduser()
    existing = _load_config(config_path)
    existing.update(
        {
            "TLS_AGENT_URL": base,
            "TLS_AGENT_TOKEN": token,
            "TLS_AGENT_INSTALLATION_ID": installation_id,
            "TLS_AGENT_USER_ID": user_id,
        }
    )
    _write_config(config_path, existing)
    info = _request(f"{base}/v1/agent/info", token=token)
    if str(info.get("user_id", user_id)) != user_id:
        raise PairingError("配对后的身份校验不一致")
    script, fault_healer = _install_fault_healer(
        config_path, Path(args.systemd_dir).expanduser()
    )
    existing = _load_config(config_path)
    existing.update({
        "TLS_FAULT_HEALER_ENABLED": "1",
        "TLS_FAULT_HEALER_SCRIPT": str(script),
    })
    _write_config(config_path, existing)
    print(
        json.dumps(
            {
                "paired": True,
                "user_id": user_id,
                "installation_id": installation_id,
                "config": str(config_path),
                "fault_healer": fault_healer,
            },
            ensure_ascii=False,
        )
    )
    return 0


def status(args: argparse.Namespace) -> int:
    config_path = Path(args.config).expanduser()
    values = _load_config(config_path)
    base = _base_url(values.get("TLS_AGENT_URL", ""))
    token = values.get("TLS_AGENT_TOKEN", "")
    if not token:
        raise PairingError("本机尚未保存 TLS Agent 凭据")
    info = _request(f"{base}/v1/agent/info", token=token)
    print(
        json.dumps(
            {
                "paired": True,
                "user_id": info.get("user_id", values.get("TLS_AGENT_USER_ID", "")),
                "installation_id": info.get(
                    "installation_id", values.get("TLS_AGENT_INSTALLATION_ID", "")
                ),
                "status": info.get("status", "active"),
            },
            ensure_ascii=False,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--systemd-dir", default=str(Path.home() / ".config/systemd/user"))
    sub = parser.add_subparsers(dest="command", required=True)
    pair_parser = sub.add_parser("pair")
    pair_parser.add_argument("--url", default=os.environ.get("TLS_AGENT_URL", DEFAULT_URL))
    code = pair_parser.add_mutually_exclusive_group(required=True)
    code.add_argument("--code", default="")
    code.add_argument("--code-stdin", action="store_true")
    pair_parser.add_argument("--name", default="TLS Agent")
    pair_parser.add_argument("--hostname", default="")
    pair_parser.set_defaults(func=pair)
    status_parser = sub.add_parser("status")
    status_parser.set_defaults(func=status)
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (OSError, PairingError, ValueError) as exc:
        print(f"TLS pairing failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
