from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, Text, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column

from ads.db import Base

KIND_MESSAGE = "message"
KIND_REASONING = "reasoning"
KIND_TOOL_CALL = "tool_call"
KIND_TOOL_RESULT = "tool_result"

ROLE_USER = "user"
ROLE_ASSISTANT = "assistant"

STATUS_PENDING = "pending"
STATUS_RUNNING = "running"
STATUS_FINISHING = "finishing"
STATUS_FINISHED = "finished"

IN_FLIGHT_STATUSES = (STATUS_PENDING, STATUS_RUNNING, STATUS_FINISHING)

_IN_FLIGHT_PREDICATE = "status IN ('pending', 'running', 'finishing')"


class Project(Base):
    __tablename__ = "project"
    __table_args__ = (Index("project_user_id_idx", "user_id"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ChatSession(Base):
    """One conversation. ``id`` is the engine ``session_id``."""

    __tablename__ = "session"
    __table_args__ = (
        Index("session_project_id_idx", "project_id"),
        Index("session_user_id_idx", "user_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("project.id", name="session_project_fk"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    latest_entry_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "session_entry.id",
            name="session_latest_entry_fk",
            use_alter=True,
            deferrable=True,
            initially="DEFERRED",
        ),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class SessionEntry(Base):
    """Bi-linked list node: one committed primitive of a session."""

    __tablename__ = "session_entry"
    __table_args__ = (Index("session_entry_session_id_idx", "session_id"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    session_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("session.id", name="session_entry_session_fk"),
        nullable=False,
    )
    prev_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("session_entry.id", name="session_entry_prev_fk"),
        nullable=True,
    )
    next_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("session_entry.id", name="session_entry_next_fk"),
        nullable=True,
    )
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str | None] = mapped_column(Text, nullable=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    run_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class SessionRun(Base):
    """One engine request. At most one in flight per session."""

    __tablename__ = "session_run"
    __table_args__ = (
        Index(
            "session_run_one_inflight",
            "session_id",
            unique=True,
            sqlite_where=text(_IN_FLIGHT_PREDICATE),
            postgresql_where=text(_IN_FLIGHT_PREDICATE),
        ),
        Index("session_run_session_id_idx", "session_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    session_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("session.id", name="session_run_session_fk"),
        nullable=False,
    )
    message_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False, unique=True)
    user_entry_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("session_entry.id", name="session_run_user_entry_fk"),
        nullable=False,
    )
    model_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    watermark: Mapped[int] = mapped_column(Integer, nullable=False)
    last_order: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finish_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class SessionRunBuffer(Base):
    """Strict deltas held until the continuous prefix reaches them."""

    __tablename__ = "session_run_buffer"

    run_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("session_run.id", name="session_run_buffer_run_fk"),
        primary_key=True,
    )
    order_no: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    text: Mapped[str] = mapped_column(Text, nullable=False)


class OidcRefreshToken(Base):
    """Keycloak refresh token for a browser SSO session. Never stored in the cookie."""

    __tablename__ = "oidc_refresh_token"
    __table_args__ = (Index("oidc_refresh_token_user_id_idx", "user_id"),)

    sid: Mapped[str] = mapped_column(Text, primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    refresh_token: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
