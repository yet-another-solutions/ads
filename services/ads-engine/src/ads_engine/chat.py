from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Literal, Protocol

from langchain_core.messages import (
    AIMessage,
    AIMessageChunk,
    BaseMessage,
    HumanMessage,
    SystemMessage,
)
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


def _text_from_block(block: object) -> str:
    if isinstance(block, str):
        return block
    if isinstance(block, dict):
        text = block.get("text")
        if isinstance(text, str):
            return text
        reasoning = block.get("reasoning")
        if isinstance(reasoning, str):
            return reasoning
    return ""


def deltas_from_chunk(chunk: AIMessageChunk) -> list[StreamDelta]:
    deltas: list[StreamDelta] = []
    extra = chunk.additional_kwargs
    reasoning = extra.get("reasoning_content")
    if not isinstance(reasoning, str) or not reasoning:
        reasoning_value = extra.get("reasoning")
        reasoning = reasoning_value if isinstance(reasoning_value, str) else ""
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


class LangChainChatStreamer:
    def stream(self, request: EngineRequest) -> AsyncIterator[StreamDelta]:
        return self._stream(request)

    async def _stream(self, request: EngineRequest) -> AsyncIterator[StreamDelta]:
        token = request.model.authentication.openai_bearer.token
        model = ChatOpenAI(
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
