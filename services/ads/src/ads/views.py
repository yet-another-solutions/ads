"""Render DTOs. Never carry a bearer, an STE JWT, or a Kafka payload."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True, slots=True)
class SessionView:
    id: uuid.UUID
    project_id: uuid.UUID
    name: str
    description: str
    running: bool = False


@dataclass(frozen=True, slots=True)
class ProjectView:
    id: uuid.UUID
    name: str
    description: str
    sessions: list[SessionView] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class PartView:
    kind: str
    role: str | None
    text: str
    live: bool = False
    name: str | None = None
    call_id: str | None = None
    status: str | None = None
    arguments: dict[str, object] | None = None
    content: object | None = None
    metadata: dict[str, object] | None = None


@dataclass(frozen=True, slots=True)
class TurnView:
    who: str
    at: datetime | None
    parts: list[PartView]
    entry_id: uuid.UUID | None = None


@dataclass(frozen=True, slots=True)
class RunView:
    status: str
    message_id: uuid.UUID
    total_context: int | None = None
    used_context: int | None = None


@dataclass(frozen=True, slots=True)
class TranscriptView:
    session: SessionView
    project_name: str
    turns: list[TurnView]
    run: RunView | None


@dataclass(frozen=True, slots=True)
class ModelOption:
    id: uuid.UUID
    description: str


@dataclass(frozen=True, slots=True)
class ModelView:
    """Catalog row for the browser. The stored bearer is never part of it."""

    id: uuid.UUID
    description: str
    name: str
    type: str
    url: str
    model_name: str
    max_context_tokens: int
