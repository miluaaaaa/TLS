"""Parse completion and native-input events from Codex transcripts."""

from __future__ import annotations

import json
from pathlib import Path

from codex_completion_watch import message_text


def task_complete(record: object) -> bool:
    if not isinstance(record, dict) or record.get("type") != "event_msg":
        return False
    payload = record.get("payload")
    return isinstance(payload, dict) and payload.get("type") == "task_complete"


def request_user_input(record: object) -> dict[str, object] | None:
    """Extract a native Codex ``request_user_input`` call from a transcript record."""
    if not isinstance(record, dict) or record.get("type") != "response_item":
        return None
    payload = record.get("payload")
    if not isinstance(payload, dict) or payload.get("type") not in {"function_call", "custom_tool_call"}:
        return None
    if str(payload.get("name", "")) != "request_user_input":
        return None
    arguments = payload.get("arguments", {})
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except (TypeError, ValueError, json.JSONDecodeError):
            return None
    if not isinstance(arguments, dict) or not isinstance(arguments.get("questions"), list):
        return None
    questions: list[dict[str, object]] = []
    for raw_question in arguments["questions"]:
        if not isinstance(raw_question, dict):
            continue
        options: list[dict[str, str]] = []
        raw_options = raw_question.get("options")
        if isinstance(raw_options, list):
            for raw_option in raw_options:
                if not isinstance(raw_option, dict):
                    continue
                label = str(raw_option.get("label", "")).strip()
                description = str(raw_option.get("description", "")).strip()
                if label or description:
                    options.append({"label": label[:180], "description": description[:500]})
        question = str(raw_question.get("question", "")).strip()
        if not question and not options:
            continue
        questions.append(
            {
                "header": str(raw_question.get("header", "")).strip()[:120],
                "id": str(raw_question.get("id", "")).strip()[:120],
                "question": question[:1800],
                "options": options[:8],
            }
        )
    if not questions:
        return None
    return {
        "call_id": str(payload.get("call_id", "") or payload.get("id", ""))[:256],
        "questions": questions[:10],
    }


def canonical_transcript(path: Path) -> Path:
    """Collapse the normal Codex home and its recovery symlink to one path."""
    try:
        return path.resolve()
    except OSError:
        return path


def read_new_events(path: Path, offset: int) -> tuple[int, list[dict[str, object]]]:
    """Read terminal events and unanswered native input requests after ``offset``."""
    try:
        size = path.stat().st_size
        if size < offset:
            offset = 0
        events: list[dict[str, object]] = []
        input_requests: list[dict[str, object]] = []
        answered_call_ids: set[str] = set()
        with path.open("rb") as handle:
            handle.seek(offset)
            for raw_line in handle:
                try:
                    record = json.loads(raw_line.decode("utf-8", errors="replace"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                event_offset = handle.tell()
                if task_complete(record):
                    events.append({"kind": "completion", "offset": event_offset})
                interaction = request_user_input(record)
                if interaction is not None:
                    interaction["offset"] = event_offset
                    input_requests.append(interaction)
                if isinstance(record, dict) and record.get("type") == "response_item":
                    payload = record.get("payload")
                    if isinstance(payload, dict) and payload.get("type") == "function_call_output":
                        call_id = str(payload.get("call_id", ""))
                        if call_id:
                            answered_call_ids.add(call_id)
            for interaction in input_requests:
                if not interaction.get("call_id") or str(interaction["call_id"]) not in answered_call_ids:
                    events.append({"kind": "question", **interaction})
            events.sort(key=lambda item: int(item.get("offset", 0) or 0))
            return handle.tell(), events
    except OSError:
        return offset, []


def read_events(path: Path, offset: int) -> tuple[int, list[int]]:
    new_offset, events = read_new_events(path, offset)
    return new_offset, [int(event["offset"]) for event in events if event.get("kind") == "completion"]


def visible_plan_before(path: Path, end_offset: int) -> str:
    try:
        with path.open("rb") as handle:
            start = max(0, int(end_offset) - 256_000)
            handle.seek(start)
            if start:
                handle.readline()
            raw_text = handle.read(max(0, int(end_offset) - handle.tell())).decode("utf-8", errors="replace")
    except OSError:
        return ""
    messages: list[str] = []
    for raw_line in raw_text.splitlines():
        try:
            record = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        payload = record.get("payload")
        if not isinstance(payload, dict):
            continue
        if record.get("type") == "event_msg" and payload.get("type") == "task_started":
            messages = []
            continue
        if record.get("type") != "response_item" or payload.get("type") != "message":
            continue
        role = str(payload.get("role", ""))
        text = message_text(payload).strip()
        if role == "user":
            messages = []
        elif role == "assistant" and payload.get("phase") in {"commentary", "final_answer"} and text:
            messages.append(text)
    return "\n\n".join(messages[-2:])[:6000].rstrip()


def function_call_answered(path: Path, end_offset: int, call_id: str) -> bool:
    if not call_id:
        return False
    try:
        with path.open("rb") as handle:
            handle.seek(max(0, int(end_offset)))
            for raw_line in handle:
                try:
                    record = json.loads(raw_line.decode("utf-8", errors="replace"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if not isinstance(record, dict) or record.get("type") != "response_item":
                    continue
                payload = record.get("payload")
                if isinstance(payload, dict) and payload.get("type") == "function_call_output":
                    if str(payload.get("call_id", "")) == call_id:
                        return True
    except OSError:
        pass
    return False


def request_user_input_pending(path: Path, tail_bytes: int = 8 * 1024 * 1024) -> bool:
    try:
        with path.open("rb") as handle:
            size = path.stat().st_size
            start = max(0, size - tail_bytes)
            handle.seek(start)
            if start:
                handle.readline()
            pending: set[str] = set()
            for raw_line in handle:
                try:
                    record = json.loads(raw_line.decode("utf-8", errors="replace"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                interaction = request_user_input(record)
                if interaction is not None:
                    call_id = str(interaction.get("call_id", ""))
                    if call_id:
                        pending.add(call_id)
                if not isinstance(record, dict) or record.get("type") != "response_item":
                    continue
                payload = record.get("payload")
                if isinstance(payload, dict) and payload.get("type") == "function_call_output":
                    pending.discard(str(payload.get("call_id", "")))
            return bool(pending)
    except OSError:
        return False
