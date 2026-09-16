"""Domain helpers shared by the ads services: entry list, turns, engine history."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from ads.models import (
    KIND_MESSAGE,
    KIND_REASONING,
    ROLE_ASSISTANT,
    ROLE_USER,
    ChatSession,
    SessionEntry,
)
from ads.repository import SessionEntryRepository
from ads.views import PartView, TurnView
from ads_commons.engine import AssistantHistoryTurn, HistoryTurn, UserHistoryTurn
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


def history_from_entries(entries: list[SessionEntry]) -> list[HistoryTurn]:
    """Committed ``message`` rows only. Reasoning is never history."""
    turns: list[HistoryTurn] = []
    for entry in entries:
        if entry.kind != KIND_MESSAGE:
            continue
        if entry.role == ROLE_USER:
            turns.append(UserHistoryTurn(text=entry.text))
        elif entry.role == ROLE_ASSISTANT:
            turns.append(AssistantHistoryTurn(text=entry.text))
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
        pending.append(
            PartView(
                kind=KIND_REASONING if entry.kind == KIND_REASONING else KIND_MESSAGE,
                role=entry.role,
                text=entry.text,
            )
        )
    if live:
        if pending_at is None:
            pending_at = utc_now()
        pending.extend(live)
    flush()
    return turns
