"""Kafka wire types for ads-engine."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any, Literal

import msgspec

from ads_commons.model_catalog import require_supported_model_name

AUTHORIZATION_HEADER = "authorization"


class OpenAiBearerToken(msgspec.Struct, frozen=True):
    token: str


class OpenAiStreamAuthentication(msgspec.Struct, frozen=True):
    openai_bearer: OpenAiBearerToken = msgspec.field(name="openai-bearer")


class OpenAiStreamOptions(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    model_name: str = msgspec.field(name="model-name")
    max_context_tokens: int

    def __post_init__(self) -> None:
        require_supported_model_name("openai-stream", self.model_name)
        if type(self.max_context_tokens) is not int or self.max_context_tokens <= 0:
            raise ValueError("max_context_tokens must be a positive integer")


class OpenAiStreamModel(msgspec.Struct, frozen=True, tag="openai-stream", tag_field="type"):
    url: str
    authentication: OpenAiStreamAuthentication
    options: OpenAiStreamOptions


class Authorization(msgspec.Struct, frozen=True):
    token: str


class UserHistoryTurn(msgspec.Struct, frozen=True, tag="user", tag_field="type"):
    text: str


class AssistantHistoryTurn(msgspec.Struct, frozen=True, tag="assistant", tag_field="type"):
    text: str


class ToolCall(msgspec.Struct, frozen=True, omit_defaults=True, tag="tool_call", tag_field="type"):
    id: str
    name: str
    arguments: dict[str, Any]
    metadata: dict[str, Any] = {}


class TaskTransition(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    task_id: str
    state: Literal["created", "succeeded", "failed", "cancelled"]


class ToolResult(
    msgspec.Struct, frozen=True, omit_defaults=True, tag="tool_result", tag_field="type"
):
    tool_call_id: str
    name: str
    status: Literal["success", "error"]
    content: Any
    metadata: dict[str, Any] = {}
    task_transitions: list[TaskTransition] = []


class Tombstone(
    msgspec.Struct, frozen=True, forbid_unknown_fields=True, tag="tombstone", tag_field="type"
):
    memory_id: uuid.UUID
    summarization: str
    messages: list[UserHistoryTurn | AssistantHistoryTurn | ToolCall | ToolResult]
    remaining_messages: list[UserHistoryTurn | AssistantHistoryTurn | ToolCall | ToolResult]
    inner_tombstone: Tombstone | None = None

    def __post_init__(self) -> None:
        if not self.summarization.strip():
            raise ValueError("summarization must be nonempty")


HistoryTurn = UserHistoryTurn | AssistantHistoryTurn | ToolCall | ToolResult | Tombstone


class ContextPressure(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    total_context: int
    used_context: int

    def __post_init__(self) -> None:
        if self.total_context <= 0 or self.used_context < 0:
            raise ValueError("invalid context pressure")


class CompactionStatus(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    type: Literal["compacting_context", "compacted_context"]


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
    tool_call: ToolCall | None = None
    tool_result: ToolResult | None = None
    compaction: CompactionStatus | None = None
    tombstone: Tombstone | None = None
    pressure: ContextPressure | None = None
    message_id: uuid.UUID | None = None


class Ping(msgspec.Struct, frozen=True, tag="ping", tag_field="type"):
    session_id: uuid.UUID


class Finish(msgspec.Struct, frozen=True, tag="finish", tag_field="type"):
    session_id: uuid.UUID
    last_order: int
    message_id: uuid.UUID | None = None


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
