"""MCP ↔ manager ↔ ipc exec handshake wire types."""

from __future__ import annotations

import uuid
from typing import Literal

import msgspec

SandboxExecKind = Literal["shell", "python"]


class SandboxRequest(msgspec.Struct, frozen=True, tag="request", tag_field="type"):
    execution_id: uuid.UUID
    session_id: uuid.UUID
    message_id: uuid.UUID
    kind: SandboxExecKind
    payload: str


class SandboxAcknowledge(msgspec.Struct, frozen=True, tag="acknowledge", tag_field="type"):
    execution_id: uuid.UUID
    session_id: uuid.UUID
    message_id: uuid.UUID


class SandboxAckReply(msgspec.Struct, frozen=True, tag="ack-reply", tag_field="type"):
    execution_id: uuid.UUID
    session_id: uuid.UUID
    message_id: uuid.UUID


class SandboxAckReset(msgspec.Struct, frozen=True, tag="ack-reset", tag_field="type"):
    execution_id: uuid.UUID
    session_id: uuid.UUID
    message_id: uuid.UUID


class SandboxAbort(msgspec.Struct, frozen=True, tag="abort", tag_field="type"):
    execution_id: uuid.UUID
    session_id: uuid.UUID
    message_id: uuid.UUID


class SandboxResult(msgspec.Struct, frozen=True, tag="result", tag_field="type"):
    execution_id: uuid.UUID
    exit_code: int
    stdout: str
    stderr: str
    truncated: bool
    duration_ms: int
    is_error: bool
    text: str = ""


SandboxExecInbound = SandboxRequest | SandboxAckReply | SandboxAckReset | SandboxAbort
SandboxExecOutbound = SandboxAcknowledge | SandboxResult


class _ExecutionIdPeek(msgspec.Struct):
    execution_id: uuid.UUID | None = None


def peek_execution_id(raw: bytes) -> uuid.UUID | None:
    try:
        peek = msgspec.json.decode(raw, type=_ExecutionIdPeek)
    except (msgspec.DecodeError, msgspec.ValidationError, TypeError, ValueError):
        return None
    return peek.execution_id


def decode_inbound(raw: bytes) -> SandboxExecInbound:
    inbound: SandboxExecInbound = msgspec.json.decode(raw, type=SandboxExecInbound)
    return inbound


def decode_outbound(raw: bytes) -> SandboxExecOutbound:
    outbound: SandboxExecOutbound = msgspec.json.decode(raw, type=SandboxExecOutbound)
    return outbound


def encode_inbound(message: SandboxExecInbound) -> bytes:
    return msgspec.json.encode(message)


def encode_outbound(message: SandboxExecOutbound) -> bytes:
    return msgspec.json.encode(message)
