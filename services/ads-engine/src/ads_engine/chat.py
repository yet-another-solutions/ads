from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from langchain_core.messages import (
    AIMessage,
    AIMessageChunk,
    BaseMessage,
    HumanMessage,
    SystemMessage,
)
from langchain_core.outputs import ChatGenerationChunk
from langchain_openai import ChatOpenAI

from ads_commons.engine import AssistantHistoryTurn, EngineRequest, UserHistoryTurn


@dataclass(frozen=True, slots=True)
class StreamDelta:
    kind: Literal["reasoning", "message"]
    text: str


class ChatStreamer(Protocol):
    def stream(self, request: EngineRequest) -> AsyncIterator[StreamDelta]: ...


def _history_messages(request: EngineRequest) -> list[BaseMessage]:
    messages: list[BaseMessage] = []
    if request.instructions:
        messages.append(SystemMessage(content=request.instructions))
    for turn in request.history:
        if isinstance(turn, UserHistoryTurn):
            messages.append(HumanMessage(content=turn.text))
        elif isinstance(turn, AssistantHistoryTurn):
            messages.append(AIMessage(content=turn.text))
    messages.append(HumanMessage(content=request.user_input))
    return messages


def _as_mapping(value: object) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    return None


def _text_from_value(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        for key in ("text", "reasoning", "thinking"):
            inner = value.get(key)
            if isinstance(inner, str) and inner:
                return inner
        summary = value.get("summary")
        if isinstance(summary, list):
            return "".join(_text_from_value(item) for item in summary)
    if isinstance(value, list):
        return "".join(_text_from_value(item) for item in value)
    return ""


def _text_from_block(block: object) -> str:
    return _text_from_value(block)


def _openai_delta(chunk: object) -> Mapping[str, Any]:
    data = _as_mapping(chunk)
    if data is None:
        return {}
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        nested = _as_mapping(data.get("chunk"))
        choices = nested.get("choices") if nested is not None else None
    if not isinstance(choices, list) or not choices:
        return {}
    choice = _as_mapping(choices[0])
    if choice is None:
        return {}
    delta = _as_mapping(choice.get("delta"))
    return delta if delta is not None else {}


def _reasoning_text_from_openai_chunk(chunk: object) -> str:
    delta = _openai_delta(chunk)
    for key in ("reasoning_content", "reasoning", "thinking"):
        text = _text_from_value(delta.get(key))
        if text:
            return text
    return ""


def _reasoning_text_from_extra(extra: Mapping[str, Any]) -> str:
    for key in ("reasoning_content", "reasoning", "thinking"):
        text = _text_from_value(extra.get(key))
        if text:
            return text
    return ""


def deltas_from_chunk(chunk: AIMessageChunk) -> list[StreamDelta]:
    deltas: list[StreamDelta] = []
    reasoning = _reasoning_text_from_extra(chunk.additional_kwargs)
    if reasoning:
        deltas.append(StreamDelta(kind="reasoning", text=reasoning))
    content = chunk.content
    if isinstance(content, str):
        if content:
            deltas.append(StreamDelta(kind="message", text=content))
        return deltas
    if isinstance(content, list):
        for block in content:
            text = _text_from_block(block)
            if not text:
                continue
            block_type = block.get("type") if isinstance(block, dict) else None
            if block_type in {"reasoning", "thinking"}:
                deltas.append(StreamDelta(kind="reasoning", text=text))
            else:
                deltas.append(StreamDelta(kind="message", text=text))
    return deltas


class AdsChatOpenAI(ChatOpenAI):
    """ChatOpenAI that keeps OpenAI-compatible reasoning fields on stream chunks."""

    def _convert_chunk_to_generation_chunk(
        self,
        chunk: dict[str, Any],
        default_chunk_class: type[Any],
        base_generation_info: dict[str, Any] | None,
    ) -> ChatGenerationChunk | None:
        generation_chunk = super()._convert_chunk_to_generation_chunk(
            chunk, default_chunk_class, base_generation_info
        )
        if generation_chunk is None:
            return None
        reasoning = _reasoning_text_from_openai_chunk(chunk)
        if reasoning:
            generation_chunk.message.additional_kwargs["reasoning_content"] = reasoning
        return generation_chunk


class LangChainChatStreamer:
    def stream(self, request: EngineRequest) -> AsyncIterator[StreamDelta]:
        return self._stream(request)

    async def _stream(self, request: EngineRequest) -> AsyncIterator[StreamDelta]:
        token = request.model.authentication.openai_bearer.token
        model = AdsChatOpenAI(
            model=request.model.options.model_name,
            base_url=request.model.url,
            api_key=lambda: token,
            streaming=True,
            max_retries=0,
        )
        async for chunk in model.astream(_history_messages(request)):
            if not isinstance(chunk, AIMessageChunk):
                continue
            for delta in deltas_from_chunk(chunk):
                yield delta
