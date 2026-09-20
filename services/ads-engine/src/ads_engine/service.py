from __future__ import annotations

import asyncio
import uuid
from collections.abc import Sequence
from contextlib import aclosing
from typing import Any, Protocol

import msgspec
import structlog

from ads_commons.engine import (
    Abort,
    Acknowledge,
    AckResponse,
    AssistantMessage,
    EngineOutput,
    EngineRequest,
    Finish,
    PartialResponse,
    Ping,
    Reasoning,
    authorization_headers,
)
from ads_commons.security import (
    SecurityContext,
    SecurityContextHolder,
    TokenExchangeError,
    require_caller,
)
from ads_engine.chat import ChatStreamer, StreamDelta
from ads_engine.config import Settings
from ads_engine.mcp_credentials import ExecutionFailed
from ads_engine.store import ActiveSessionStore

log = structlog.get_logger("ads_engine")

OPENAI_ATTEMPTS = 3


class SessionAlreadyActive(Exception):
    def __init__(self) -> None:
        super().__init__("session already active")


class AckTimedOut(Exception):
    def __init__(self) -> None:
        super().__init__("ack-response timed out")


class NoPartialResponse(Exception):
    def __init__(self) -> None:
        super().__init__("no partial-response")


class OutputPublisher(Protocol):
    async def publish(
        self,
        session_id: uuid.UUID,
        message: EngineOutput,
        headers: Sequence[tuple[str, bytes]] | None = None,
    ) -> None: ...


class TokenMinter(Protocol):
    def mint(self, audience: str) -> SecurityContext: ...


class EngineService:
    def __init__(
        self,
        store: ActiveSessionStore,
        publisher: OutputPublisher,
        chat: ChatStreamer,
        tokens: TokenMinter,
        settings: Settings,
    ) -> None:
        self._store = store
        self._publisher = publisher
        self._chat = chat
        self._ping_interval_seconds = settings.ping_interval_seconds
        self._ack_timeout_seconds = settings.ack_timeout_seconds
        self._tokens = tokens
        self._ack_audience = settings.ack_audience
        self.allowed_callers = frozenset(settings.allowed_callers)
        self._ack_waiters: dict[uuid.UUID, tuple[uuid.UUID, asyncio.Event]] = {}
        self._runs: dict[uuid.UUID, tuple[uuid.UUID, asyncio.Task[Any]]] = {}
        self._aborted: set[uuid.UUID] = set()

    @require_caller()
    async def handle(self, request: EngineRequest) -> None:
        _validate_request(request)
        claimed = await self._store.claim(request.session_id, request.message_id)
        if not claimed:
            log.info(
                "session_already_active",
                session_id=str(request.session_id),
                message_id=str(request.message_id),
            )
            raise SessionAlreadyActive()
        log.info(
            "session_claimed",
            session_id=str(request.session_id),
            message_id=str(request.message_id),
        )
        task = asyncio.current_task()
        if task is None:
            raise RuntimeError("engine handle requires a running task")
        self._runs[request.session_id] = (request.message_id, task)
        ping_task: asyncio.Task[None] | None = None
        try:
            minted = self._tokens.mint(self._ack_audience)
            token = minted.access_token
            if not token:
                raise TokenExchangeError("exchanged token is missing")
            minted = minted.with_attributes(
                session_id=request.session_id,
                message_id=request.message_id,
            )
            waiter = asyncio.Event()
            self._ack_waiters[request.session_id] = (request.message_id, waiter)
            with SecurityContextHolder.bound(minted):
                await self._publisher.publish(
                    request.session_id,
                    Acknowledge(session_id=request.session_id, message_id=request.message_id),
                    headers=authorization_headers(token),
                )
                log.info(
                    "acknowledge_published",
                    session_id=str(request.session_id),
                    message_id=str(request.message_id),
                )
                await self._wait_for_ack_response(request.session_id, waiter)
                self._ack_waiters.pop(request.session_id, None)
                ping_task = asyncio.create_task(self._ping(request.session_id))
                last_order = await self._run_model(request)
                await _cancel(ping_task)
                await self._publisher.publish(
                    request.session_id,
                    Finish(
                        session_id=request.session_id,
                        last_order=last_order,
                        message_id=request.message_id,
                    ),
                )
                log.info(
                    "finish_published",
                    session_id=str(request.session_id),
                    last_order=last_order,
                )
        except asyncio.CancelledError:
            if request.session_id not in self._aborted:
                raise
        finally:
            self._runs.pop(request.session_id, None)
            self._aborted.discard(request.session_id)
            self._ack_waiters.pop(request.session_id, None)
            if ping_task is not None:
                await _cancel(ping_task)
            await self._store.release(request.session_id)

    async def handle_ack_response(self, ack: AckResponse) -> None:
        pending = self._ack_waiters.get(ack.session_id)
        if pending is None:
            return
        message_id, waiter = pending
        if message_id != ack.message_id:
            return
        waiter.set()
        log.info(
            "ack_response_accepted",
            session_id=str(ack.session_id),
            message_id=str(ack.message_id),
        )

    async def handle_abort(self, abort: Abort) -> None:
        run = self._runs.get(abort.session_id)
        if run is None:
            return
        message_id, task = run
        if message_id != abort.message_id:
            return
        log.info(
            "abort_accepted",
            session_id=str(abort.session_id),
            message_id=str(abort.message_id),
        )
        self._aborted.add(abort.session_id)
        current = asyncio.current_task()
        task.cancel()
        if task is current:
            return
        await asyncio.gather(task, return_exceptions=True)

    async def _wait_for_ack_response(self, session_id: uuid.UUID, waiter: asyncio.Event) -> None:
        try:
            await asyncio.wait_for(waiter.wait(), timeout=self._ack_timeout_seconds)
        except TimeoutError:
            log.info("ack_response_timeout", session_id=str(session_id))
            raise AckTimedOut() from None

    async def _run_model(self, request: EngineRequest) -> int:
        order = 0
        emitted_partial = False
        last_error: Exception | None = None
        for attempt in range(OPENAI_ATTEMPTS):
            try:
                async with aclosing(self._chat.stream(request)) as stream:
                    async for delta in stream:
                        # Publication can fail after a tool side effect. Never
                        # restart a run once a delta reaches the output boundary.
                        emitted_partial = True
                        await self._publisher.publish(
                            request.session_id,
                            msgspec.structs.replace(
                                _partial(request.session_id, order, delta),
                                pressure=delta.pressure,
                                message_id=request.message_id,
                            ),
                        )
                        order += 1
                break
            except ExecutionFailed:
                raise
            except Exception as exc:
                last_error = exc
                if emitted_partial:
                    raise
                log.info(
                    "openai_retry",
                    session_id=str(request.session_id),
                    attempt=attempt + 1,
                )
        else:
            raise RuntimeError(
                str(last_error) if last_error is not None else "openai request failed"
            )
        if not emitted_partial:
            raise NoPartialResponse()
        return order - 1

    async def _ping(self, session_id: uuid.UUID) -> None:
        while True:
            await asyncio.sleep(self._ping_interval_seconds)
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
    if delta.kind == "compaction":
        return PartialResponse(session_id=session_id, order=order, compaction=delta.compaction)
    if delta.kind == "tombstone":
        return PartialResponse(session_id=session_id, order=order, tombstone=delta.tombstone)
    if delta.kind == "reasoning":
        return PartialResponse(
            session_id=session_id,
            order=order,
            reasoning=Reasoning(text=delta.text),
        )
    if delta.kind == "tool_call" and delta.tool_call is not None:
        return PartialResponse(
            session_id=session_id,
            order=order,
            tool_call=delta.tool_call,
        )
    if delta.kind == "tool_result" and delta.tool_result is not None:
        return PartialResponse(
            session_id=session_id,
            order=order,
            tool_result=delta.tool_result,
        )
    return PartialResponse(
        session_id=session_id,
        order=order,
        message=AssistantMessage(text=delta.text),
    )


def _validate_request(request: EngineRequest) -> None:
    if not request.user_input:
        raise ValueError("user_input is required")
    if not request.model.options.model_name.strip():
        raise ValueError("model.options.model-name is required")
    if not request.model.url.strip():
        raise ValueError("model.url is required")
    if not request.model.authentication.openai_bearer.token.strip():
        raise ValueError("model authentication token is required")
