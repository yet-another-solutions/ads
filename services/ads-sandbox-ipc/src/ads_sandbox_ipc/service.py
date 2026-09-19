from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol
from uuid import UUID

import structlog

from ads_commons.sandbox import (
    SandboxAbort,
    SandboxAcknowledge,
    SandboxAckReply,
    SandboxAckReset,
    SandboxExecInbound,
    SandboxExecOutbound,
    SandboxIpcError,
    SandboxPing,
    SandboxReady,
    SandboxReadyMessage,
    SandboxRequest,
    SandboxResult,
    SandboxShutdownAck,
)
from ads_sandbox_ipc.config import Settings
from ads_sandbox_ipc.guest import GuestExecutor

log = structlog.get_logger("ads_sandbox_ipc")
Outbound = SandboxExecOutbound | SandboxReadyMessage | SandboxPing


class Publisher(Protocol):
    async def publish(self, message: Outbound, subject_token: str | None = None) -> None: ...


@dataclass(frozen=True, slots=True)
class VerifiedMessage:
    message: SandboxExecInbound
    subject: str
    token: str = field(repr=False)
    expires_at: float


@dataclass(slots=True)
class Unit:
    request: SandboxRequest
    subject: str
    token: str = field(repr=False)
    deadline: float
    abort: asyncio.Event = field(default_factory=asyncio.Event)
    executing: bool = False


class IpcService:
    """One current unit and one terminal slot. All credentials remain in memory."""

    def __init__(self, settings: Settings, guest: GuestExecutor, publisher: Publisher) -> None:
        self.settings = settings
        self.guest = guest
        self.publisher = publisher
        self.http_ready = False
        self.kafka_ready = False
        self.failed = False
        self.stopping = False
        self.current: Unit | None = None
        self.last_id: UUID | None = None
        self.last_session_id: UUID | None = None
        self.last_message_id: UUID | None = None
        self.last_subject: str | None = None
        self.last_result: SandboxResult | None = None
        self._last_token: str | None = None
        self._result_delivered = True
        self._lock = asyncio.Lock()
        self._startup_task: asyncio.Task[None] | None = None
        self._execution_task: asyncio.Task[None] | None = None
        self._ack_task: asyncio.Task[None] | None = None
        self._shutdowns: list[tuple[str, datetime | None]] = []
        self._pings: set[asyncio.Task[object]] = set()

    def start(self) -> None:
        self._startup_task = asyncio.create_task(self._startup())

    async def _startup(self) -> None:
        try:
            async with asyncio.timeout(self.settings.startup_seconds):
                while not self.stopping:
                    try:
                        prepared = await self.guest.prepare()
                    except Exception:
                        prepared = False
                        log.warning("startup_guest_not_ready")
                    if prepared:
                        self.http_ready = True
                        await self.publisher.publish(SandboxReady(self.settings.sandbox_id))
                        if not self.stopping:
                            self.kafka_ready = True
                        return
                    await asyncio.sleep(self.settings.poll_seconds)
        except asyncio.CancelledError:
            raise
        except Exception:
            if not self.stopping:
                self.failed = True
                self.http_ready = False
                try:
                    await self.publisher.publish(
                        SandboxIpcError(self.settings.sandbox_id, "sandbox startup failed")
                    )
                except Exception:
                    log.warning("startup_error_publish_failed")

    def _remember(self, unit: Unit, result: SandboxResult | None = None) -> None:
        self.last_id = unit.request.execution_id
        self.last_session_id = unit.request.session_id
        self.last_message_id = unit.request.message_id
        self.last_subject = unit.subject
        self.last_result = result
        self._last_token = unit.token if result is not None else None
        self._result_delivered = result is None

    async def accept(self, delivery: VerifiedMessage) -> None:
        message = delivery.message
        if (
            isinstance(message, SandboxAckReply)
            and delivery.expires_at - time.time() < self.settings.timeout_seconds
        ):
            log.warning("ack_reply_ttl_below_exec_timeout", execution_id=str(message.execution_id))
        if not self.kafka_ready or self.stopping or self.failed:
            return
        async with self._lock:
            if self.stopping:
                return
            if message.execution_id == self.last_id:
                if (
                    isinstance(message, (SandboxRequest, SandboxAckReply))
                    and self.last_result is not None
                    and delivery.subject == self.last_subject
                    and message.session_id == self.last_session_id
                    and message.message_id == self.last_message_id
                ):
                    await self.publisher.publish(self.last_result, self._last_token)
                    self._result_delivered = True
                return
            unit = self.current
            if isinstance(message, SandboxRequest):
                if unit is not None:
                    if (
                        message == unit.request
                        and not unit.executing
                        and delivery.subject == unit.subject
                    ):
                        await self.publisher.publish(
                            SandboxAcknowledge(
                                message.execution_id, message.session_id, message.message_id
                            ),
                            delivery.token,
                        )
                    return
                unit = Unit(
                    message,
                    delivery.subject,
                    delivery.token,
                    time.monotonic() + self.settings.ack_seconds,
                )
                if len(message.payload.encode()) > self.settings.input_bytes:
                    result = SandboxResult(
                        message.execution_id, -1, "", "", False, 0, True, "input limit exceeded"
                    )
                    self._remember(unit, result)
                    await self.publisher.publish(result, delivery.token)
                    self._result_delivered = True
                    return
                self.current = unit
                self._ack_task = asyncio.create_task(self._ack_timeout(unit))
                try:
                    await self.publisher.publish(
                        SandboxAcknowledge(
                            message.execution_id, message.session_id, message.message_id
                        ),
                        delivery.token,
                    )
                except Exception:
                    self.current = None
                    self._remember(unit)
                    raise
                return
            if (
                unit is None
                or message.execution_id != unit.request.execution_id
                or message.session_id != unit.request.session_id
                or message.message_id != unit.request.message_id
                or delivery.subject != unit.subject
            ):
                return
            if isinstance(message, SandboxAbort):
                if unit.executing:
                    unit.abort.set()
                else:
                    self._drop_waiter(unit)
            elif isinstance(message, SandboxAckReset):
                if not unit.executing:
                    self._drop_waiter(unit)
            elif isinstance(message, SandboxAckReply) and not unit.executing:
                if time.monotonic() >= unit.deadline:
                    self._drop_waiter(unit)
                    return
                unit.token = delivery.token
                unit.executing = True
                if self._ack_task:
                    self._ack_task.cancel()
                self._execution_task = asyncio.create_task(self._execute(unit))

    def _drop_waiter(self, unit: Unit) -> None:
        self._remember(unit)
        self.current = None
        if self._ack_task is not None and self._ack_task is not asyncio.current_task():
            self._ack_task.cancel()

    async def _ack_timeout(self, unit: Unit) -> None:
        await asyncio.sleep(max(0, unit.deadline - time.monotonic()))
        async with self._lock:
            if self.current is unit and not unit.executing:
                self._drop_waiter(unit)

    async def _execute(self, unit: Unit) -> None:
        try:
            result = await self.guest.execute(unit.request, unit.abort)
        except Exception:
            self.guest.clean = False
            result = SandboxResult(
                unit.request.execution_id, -1, "", "", False, 0, True, "guest execution failed"
            )
        async with self._lock:
            self._remember(unit, result)
            self.current = None
            try:
                await self.publisher.publish(result, unit.token)
                self._result_delivered = True
            except Exception:
                # Keep the terminal slot; a duplicate can retry delivery, never execution.
                log.warning("result_publish_failed", execution_id=str(result.execution_id))
                # A shutdown must not acknowledge before its current result was delivered.
                return
            await self._finish_shutdown()

    async def ping(self, message: SandboxPing, token: str) -> None:
        task = asyncio.current_task()
        if self.kafka_ready and not self.stopping and task is not None:
            self._pings.add(task)
            try:
                await self.publisher.publish(message, token)
            finally:
                self._pings.discard(task)

    async def shutdown(self, token: str, transition: datetime | None = None) -> None:
        # Latch before awaits, including startup cancellation and the execution lock.
        self.stopping = True
        self.kafka_ready = False
        self._shutdowns.append((token, transition))
        for task in self._pings:
            task.cancel()
        if self._startup_task and not self._startup_task.done():
            self._startup_task.cancel()
            await asyncio.gather(self._startup_task, return_exceptions=True)
        async with self._lock:
            if self.current and not self.current.executing:
                self._drop_waiter(self.current)
            if self.current is None:
                # Retry a failed result produce before shutdown-ack, if necessary.
                if self.last_result is not None and not self._result_delivered:
                    await self.publisher.publish(self.last_result, self._last_token)
                    self._result_delivered = True
                await self._finish_shutdown()

    async def _finish_shutdown(self) -> None:
        while self._shutdowns:
            token, transition = self._shutdowns[0]
            await self.publisher.publish(
                SandboxShutdownAck(self.settings.sandbox_id, transition), token
            )
            self._shutdowns.pop(0)

    async def stop(self) -> None:
        self.stopping = True
        self.kafka_ready = False
        if self.current and self.current.executing:
            self.current.abort.set()
        for task in (self._startup_task, self._ack_task):
            if task is not None:
                task.cancel()
        tasks = [
            task for task in (self._startup_task, self._ack_task, self._execution_task) if task
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
        self.current = None
        self._last_token = None
        self._shutdowns.clear()
