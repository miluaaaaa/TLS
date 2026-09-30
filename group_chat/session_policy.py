"""Shared per-session policy for TLS Codex notifications and replies."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path


DEFAULT_EXCLUDED_SESSIONS_FILE = Path.home() / ".config/tls/excluded-sessions"
DEFAULT_INCLUDED_SESSIONS_FILE = Path.home() / ".config/tls/included-sessions"
DEFAULT_SESSION_LABELS_FILE = Path.home() / ".config/tls/session-labels.tsv"
SESSION_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)


def excluded_sessions_file() -> Path:
    return Path(os.environ.get("TLS_EXCLUDED_SESSIONS_FILE", str(DEFAULT_EXCLUDED_SESSIONS_FILE)))


def included_sessions_file() -> Path:
    return Path(os.environ.get("TLS_INCLUDED_SESSIONS_FILE", str(DEFAULT_INCLUDED_SESSIONS_FILE)))


def session_labels_file() -> Path:
    return Path(os.environ.get("TLS_SESSION_LABELS_FILE", str(DEFAULT_SESSION_LABELS_FILE)))


def monitor_all_sessions() -> bool:
    """Return whether local TLS should observe every user Codex session."""
    value = os.environ.get("TLS_MONITOR_ALL_SESSIONS", "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


def session_ids(path: Path) -> set[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return set()
    values: set[str] = set()
    for raw_line in lines:
        value = raw_line.split("#", 1)[0].strip().lower()
        if SESSION_ID.fullmatch(value):
            values.add(value)
    return values


def excluded_session_ids(path: Path | None = None) -> set[str]:
    return session_ids(excluded_sessions_file() if path is None else path)


def included_session_ids(path: Path | None = None) -> set[str]:
    return session_ids(included_sessions_file() if path is None else path)


def session_label(value: object, path: Path | None = None) -> str:
    references = {match.group(0).lower() for match in SESSION_ID.finditer(str(value or ""))}
    if not references:
        return ""
    path = session_labels_file() if path is None else path
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ""
    for raw_line in lines:
        session_id, separator, label = raw_line.partition("\t")
        if separator and session_id.strip().lower() in references:
            return re.sub(r"\s+", " ", label).strip()[:40]
    return ""


def is_session_excluded(value: object, path: Path | None = None, included_path: Path | None = None) -> bool:
    references = {match.group(0).lower() for match in SESSION_ID.finditer(str(value or ""))}
    excluded = excluded_session_ids(path)
    if references & excluded:
        return True
    if monitor_all_sessions():
        return False
    included = included_session_ids(included_path)
    if not references:
        return False
    if not included:
        return True
    return references.isdisjoint(included)


def validate_policy(excluded_path: Path | None = None, included_path: Path | None = None) -> tuple[bool, str]:
    if monitor_all_sessions():
        return True, ""
    included = included_session_ids(included_path)
    if not included:
        return False, "TLS session allowlist is missing or contains no valid session IDs."
    overlap = included & excluded_session_ids(excluded_path)
    if overlap:
        return False, "TLS session allowlist conflicts with the exclusion list."
    return True, ""


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv != ["validate"]:
        print("usage: session_policy.py validate", file=sys.stderr)
        return 2
    valid, error = validate_policy()
    if not valid:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
