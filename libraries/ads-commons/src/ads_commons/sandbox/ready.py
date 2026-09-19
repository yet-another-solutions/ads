"""Manager ↔ ipc lifecycle types on ads.sandbox.ready."""

from __future__ import annotations

import uuid
from datetime import datetime

import msgspec


class SandboxReady(msgspec.Struct, frozen=True, tag="ready", tag_field="type"):
    sandbox_id: uuid.UUID


class SandboxShutdown(msgspec.Struct, frozen=True, tag="shutdown", tag_field="type"):
    sandbox_id: uuid.UUID
    transition: datetime | None = None


class SandboxShutdownAck(msgspec.Struct, frozen=True, tag="shutdown-ack", tag_field="type"):
    sandbox_id: uuid.UUID
    transition: datetime | None = None


class SandboxIpcError(msgspec.Struct, frozen=True, tag="error", tag_field="type"):
    sandbox_id: uuid.UUID
    text: str


SandboxReadyMessage = SandboxReady | SandboxShutdown | SandboxShutdownAck | SandboxIpcError


class _SandboxIdPeek(msgspec.Struct):
    sandbox_id: uuid.UUID | None = None


def peek_sandbox_id(raw: bytes) -> uuid.UUID | None:
    try:
        peek = msgspec.json.decode(raw, type=_SandboxIdPeek)
    except (msgspec.DecodeError, msgspec.ValidationError, TypeError, ValueError):
        return None
    return peek.sandbox_id


def decode_ready(raw: bytes) -> SandboxReadyMessage:
    message: SandboxReadyMessage = msgspec.json.decode(raw, type=SandboxReadyMessage)
    return message


def encode_ready(message: SandboxReadyMessage) -> bytes:
    return msgspec.json.encode(message)
