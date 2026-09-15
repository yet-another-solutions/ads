"""Kafka wire types for ads-engine."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Literal

import msgspec

AUTHORIZATION_HEADER = "authorization"


class OpenAiBearerToken(msgspec.Struct, frozen=True):
    token: str


class OpenAiStreamAuthentication(msgspec.Struct, frozen=True):
    openai_bearer: OpenAiBearerToken = msgspec.field(name="openai-bearer")


class OpenAiStreamModel(msgspec.Struct, frozen=True, tag="openai-stream", tag_field="type"):
    name: str
    url: str
    authentication: OpenAiStreamAuthentication


class Authorization(msgspec.Struct, frozen=True):
    token: str


class UserHistoryTurn(msgspec.Struct, frozen=True, tag="user", tag_field="type"):
    text: str


class AssistantHistoryTurn(msgspec.Struct, frozen=True, tag="assistant", tag_field="type"):
    text: str


HistoryTurn = UserHistoryTurn | AssistantHistoryTurn


class EngineRequest(msgspec.Struct, frozen=True, tag="request", tag_field="type"):
    session_id: uuid.UUID
    message_id: uuid.UUID
    history: list[HistoryTurn]
    user_input: str
    instructions: str
    model: OpenAiStreamModel
    authorization: Authorization


class AckResponse(msgspec.Struct, frozen=True, tag="ack-response", tag_field="type"):
    session_id: uuid.UUID
    message_id: uuid.UUID


class Abort(msgspec.Struct, frozen=True, tag="abort", tag_field="type"):
    session_id: uuid.UUID
    message_id: uuid.UUID


EngineInbound = EngineRequest | AckResponse | Abort


class Acknowledge(msgspec.Struct, frozen=True, tag="acknowledge", tag_field="type"):
    session_id: uuid.UUID
    message_id: uuid.UUID


class Reasoning(msgspec.Struct, frozen=True):
    text: str


class AssistantMessage(msgspec.Struct, frozen=True):
    text: str
    type: Literal["assistant"] = "assistant"


class PartialResponse(
    msgspec.Struct,
    frozen=True,
    tag="partial-response",
    tag_field="type",
    omit_defaults=True,
):
    session_id: uuid.UUID
    order: int
    reasoning: Reasoning | None = None
    message: AssistantMessage | None = None


class Ping(msgspec.Struct, frozen=True, tag="ping", tag_field="type"):
    session_id: uuid.UUID


class Finish(msgspec.Struct, frozen=True, tag="finish", tag_field="type"):
    session_id: uuid.UUID
    last_order: int


class ErrorOutput(msgspec.Struct, frozen=True, tag="error", tag_field="type"):
    session_id: uuid.UUID
    message_id: uuid.UUID
    text: str


EngineOutput = Acknowledge | PartialResponse | Ping | Finish | ErrorOutput


class _IdPeek(msgspec.Struct):
    session_id: uuid.UUID | None = None
    message_id: uuid.UUID | None = None


def peek_request_ids(raw: bytes) -> tuple[uuid.UUID, uuid.UUID] | None:
    try:
        peek = msgspec.json.decode(raw, type=_IdPeek)
    except (msgspec.DecodeError, msgspec.ValidationError, TypeError, ValueError):
        return None
    if peek.session_id is None or peek.message_id is None:
        return None
    return peek.session_id, peek.message_id


def decode_inbound(raw: bytes) -> EngineInbound:
    inbound: EngineInbound = msgspec.json.decode(raw, type=EngineInbound)
    return inbound


def decode_request(raw: bytes) -> EngineRequest:
    return msgspec.json.decode(raw, type=EngineRequest)


def encode_output(message: EngineOutput) -> bytes:
    return msgspec.json.encode(message)


def encode_request(request: EngineRequest) -> bytes:
    return msgspec.json.encode(request)


def encode_ack_response(message: AckResponse) -> bytes:
    return msgspec.json.encode(message)


def encode_abort(message: Abort) -> bytes:
    return msgspec.json.encode(message)


def authorization_headers(token: str) -> list[tuple[str, bytes]]:
    if not token.strip():
        raise ValueError("authorization token is required")
    return [(AUTHORIZATION_HEADER, token.encode("utf-8"))]


def authorization_token(
    headers: Sequence[tuple[str | bytes, bytes | None]] | None,
) -> str | None:
    if not headers:
        return None
    for key, value in headers:
        name = key.decode("utf-8") if isinstance(key, bytes) else key
        if name.lower() != AUTHORIZATION_HEADER:
            continue
        if not value:
            return None
        text = value.decode("utf-8")
        return text or None
    return None
