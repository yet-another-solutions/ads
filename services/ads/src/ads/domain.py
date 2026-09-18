"""Domain helpers shared by the ads services: entry list, turns, engine history."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import msgspec

from ads.models import (
    KIND_MESSAGE,
    KIND_TOOL_CALL,
    KIND_TOOL_RESULT,
    ROLE_ASSISTANT,
    ROLE_USER,
    ChatSession,
    SessionEntry,
)
from ads.repository import SessionEntryRepository
from ads.views import PartView, TurnView
from ads_commons.engine import (
    AssistantHistoryTurn,
    HistoryTurn,
    ToolCall,
    ToolResult,
    UserHistoryTurn,
)
from ads_commons.security import SecurityContext


def utc_now() -> datetime:
    return datetime.now(UTC)


def detached_context(user_id: uuid.UUID) -> SecurityContext:
    """Identity for Kafka and watchdog work. No access token: this is not a user request."""
    return SecurityContext(
        subject=str(user_id),
        name="ads",
        roles=frozenset({"user"}),
        authorized_party="ads",
    )


def append_entry(
    entries: SessionEntryRepository,
    session: ChatSession,
    *,
    kind: str,
    role: str | None,
    text: str,
    run_id: uuid.UUID | None,
    now: datetime,
) -> SessionEntry:
    """Link a new tail after ``session.latest_entry_id`` and move ``latest`` onto it."""
    previous_id = session.latest_entry_id
    entry = SessionEntry(
        id=uuid.uuid4(),
        session_id=session.id,
        prev_id=previous_id,
        next_id=None,
        kind=kind,
        role=role,
        text=text,
        run_id=run_id,
        created_at=now,
    )
    entries.insert(entry)
    if previous_id is not None:
        previous = entries.get_entry(previous_id)
        if previous is not None:
            previous.next_id = entry.id
    session.latest_entry_id = entry.id
    session.updated_at = now
    return entry


def parse_tool_call(text: str) -> ToolCall | None:
    try:
        return msgspec.json.decode(text.encode(), type=ToolCall)
    except (msgspec.DecodeError, msgspec.ValidationError):
        return None


def parse_tool_result(text: str) -> ToolResult | None:
    try:
        return msgspec.json.decode(text.encode(), type=ToolResult)
    except (msgspec.DecodeError, msgspec.ValidationError):
        return None


def tool_call_display(call: ToolCall) -> str:
    if call.name == "exec_shell":
        command = call.arguments.get("command")
        if isinstance(command, str):
            return command
    if call.name == "exec_python":
        code = call.arguments.get("code")
        if isinstance(code, str):
            return code
    return msgspec.json.encode(call.arguments).decode()


def tool_result_display(result: ToolResult) -> str:
    content = result.content
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        structured = content.get("structuredContent")
        if isinstance(structured, dict):
            stdout = structured.get("stdout")
            if isinstance(stdout, str) and stdout:
                return stdout
        blocks = content.get("content")
        if isinstance(blocks, list):
            texts = [
                block["text"]
                for block in blocks
                if isinstance(block, dict) and isinstance(block.get("text"), str)
            ]
            if texts:
                return "".join(texts)
    try:
        return msgspec.json.encode(content).decode()
    except (TypeError, msgspec.EncodeError):
        return str(content)


def part_from_stored(kind: str, text: str, role: str | None, *, live: bool = False) -> PartView:
    if kind == KIND_TOOL_CALL:
        call = parse_tool_call(text)
        if call is None:
            return PartView(kind=kind, role=role, text=text, live=live)
        return PartView(
            kind=kind,
            role=role,
            text=tool_call_display(call),
            live=live,
            name=call.name,
            call_id=call.id,
            arguments=dict(call.arguments),
            metadata=dict(call.metadata),
        )
    if kind == KIND_TOOL_RESULT:
        result = parse_tool_result(text)
        if result is None:
            return PartView(kind=kind, role=role, text=text, live=live)
        return PartView(
            kind=kind,
            role=role,
            text=tool_result_display(result),
            live=live,
            name=result.name,
            call_id=result.tool_call_id,
            status=result.status,
            content=result.content,
            metadata=dict(result.metadata),
        )
    return PartView(kind=kind, role=role, text=text, live=live)


def history_from_entries(entries: list[SessionEntry]) -> list[HistoryTurn]:
    """Committed message and tool rows. Reasoning is never history."""
    turns: list[HistoryTurn] = []
    for entry in entries:
        if entry.kind == KIND_MESSAGE:
            if entry.role == ROLE_USER:
                turns.append(UserHistoryTurn(text=entry.text))
            elif entry.role == ROLE_ASSISTANT:
                turns.append(AssistantHistoryTurn(text=entry.text))
        elif entry.kind == KIND_TOOL_CALL:
            call = parse_tool_call(entry.text)
            if call is not None:
                turns.append(call)
        elif entry.kind == KIND_TOOL_RESULT:
            result = parse_tool_result(entry.text)
            if result is not None:
                turns.append(result)
    return turns


def turns_from_entries(
    entries: list[SessionEntry],
    live: list[PartView] | None = None,
) -> list[TurnView]:
    """Render the primitive list as YOU / ADS turns. Live parts join the trailing ADS turn."""
    turns: list[TurnView] = []
    pending: list[PartView] = []
    pending_at: datetime | None = None
    pending_id: uuid.UUID | None = None

    def flush() -> None:
        nonlocal pending, pending_at, pending_id
        if pending:
            turns.append(TurnView(who="ADS", at=pending_at, parts=pending, entry_id=pending_id))
        pending = []
        pending_at = None
        pending_id = None

    for entry in entries:
        if entry.kind == KIND_MESSAGE and entry.role == ROLE_USER:
            flush()
            turns.append(
                TurnView(
                    who="YOU",
                    at=entry.created_at,
                    parts=[PartView(kind=KIND_MESSAGE, role=ROLE_USER, text=entry.text)],
                    entry_id=entry.id,
                )
            )
            continue
        if pending_at is None:
            pending_at = entry.created_at
            pending_id = entry.id
        pending.append(part_from_stored(entry.kind, entry.text, entry.role))
    if live:
        if pending_at is None:
            pending_at = utc_now()
        pending.extend(live)
    flush()
    return turns
