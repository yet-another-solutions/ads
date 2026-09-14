from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from typing import Protocol

import structlog

from ads_commons.engine import (
    Acknowledge,
    AssistantMessage,
    EngineOutput,
    EngineRequest,
    ErrorOutput,
    Finish,
    PartialResponse,
    Ping,
    Reasoning,
    decode_request,
    peek_request_ids,
)
from ads_engine.chat import ChatStreamer, StreamDelta
from ads_engine.store import ActiveSessionStore

log = structlog.get_logger("ads_engine")

OPENAI_ATTEMPTS = 3


class OutputPublisher(Protocol):
    async def publish(self, session_id: uuid.UUID, message: EngineOutput) -> None: ...


class EngineService:
    def __init__(
        self,
        store: ActiveSessionStore,
        publisher: OutputPublisher,
        chat: ChatStreamer,
        ping_interval_seconds: float,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._store = store
        self._publisher = publisher
        self._chat = chat
        self._ping_interval_seconds = ping_interval_seconds
        self._sleep = sleep

    async def handle_raw(self, raw: bytes) -> None:
        ids = peek_request_ids(raw)
        if ids is None:
            return
        session_id, message_id = ids
        try:
            request = decode_request(raw)
            _validate_request(request)
        except Exception as exc:
            await self._publisher.publish(
                session_id,
                ErrorOutput(
                    session_id=session_id,
                    message_id=message_id,
                    text=f"invalid request: {exc}",
                ),
            )
            return
        await self.handle(request)

    async def handle(self, request: EngineRequest) -> None:
        claimed = await self._store.claim(request.session_id, request.message_id)
        if not claimed:
            await self._publisher.publish(
                request.session_id,
                ErrorOutput(
                    session_id=request.session_id,
                    message_id=request.message_id,
                    text="session already active",
                ),
            )
            return
        ping_task = asyncio.create_task(self._ping(request.session_id))
        try:
            await self._publisher.publish(
                request.session_id,
                Acknowledge(session_id=request.session_id, message_id=request.message_id),
            )
            await self._run_model(request)
            await _cancel(ping_task)
            await self._publisher.publish(
                request.session_id,
                Finish(session_id=request.session_id),
            )
        except Exception as exc:
            await _cancel(ping_task)
            await self._publisher.publish(
                request.session_id,
                ErrorOutput(
                    session_id=request.session_id,
                    message_id=request.message_id,
                    text=str(exc),
                ),
            )
        finally:
            await _cancel(ping_task)
            await self._store.release(request.session_id)

    async def _run_model(self, request: EngineRequest) -> None:
        order = 0
        emitted_partial = False
        last_error: Exception | None = None
        for attempt in range(OPENAI_ATTEMPTS):
            try:
                async for delta in self._chat.stream(request):
                    await self._publisher.publish(
                        request.session_id,
                        _partial(request.session_id, order, delta),
                    )
                    order += 1
                    emitted_partial = True
                return
            except Exception as exc:
                last_error = exc
                if emitted_partial:
                    raise
                log.info(
                    "openai_retry",
                    session_id=str(request.session_id),
                    attempt=attempt + 1,
                )
        raise RuntimeError(str(last_error) if last_error is not None else "openai request failed")

    async def _ping(self, session_id: uuid.UUID) -> None:
        while True:
            await self._sleep(self._ping_interval_seconds)
            await self._publisher.publish(session_id, Ping(session_id=session_id))


async def _cancel(task: asyncio.Task[None]) -> None:
    if task.done():
        return
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        return


def _partial(session_id: uuid.UUID, order: int, delta: StreamDelta) -> PartialResponse:
    if delta.kind == "reasoning":
        return PartialResponse(
            session_id=session_id,
            order=order,
            reasoning=Reasoning(text=delta.text),
        )
    return PartialResponse(
        session_id=session_id,
        order=order,
        message=AssistantMessage(text=delta.text),
    )


def _validate_request(request: EngineRequest) -> None:
    if not request.user_input:
        raise ValueError("user_input is required")
    if not request.model.name.strip():
        raise ValueError("model.name is required")
    if not request.model.url.strip():
        raise ValueError("model.url is required")
    if not request.model.authentication.openai_bearer.token.strip():
        raise ValueError("model authentication token is required")
    if not request.authorization.token.strip():
        raise ValueError("authorization.token is required")
