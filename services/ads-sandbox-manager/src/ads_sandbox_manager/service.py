from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ads_commons.sandbox import (
    SandboxAbort,
    SandboxAcknowledge,
    SandboxAckReset,
    SandboxExecInbound,
    SandboxExecOutbound,
    SandboxRequest,
    SandboxResult,
    encode_inbound,
    encode_outbound,
)
from ads_sandbox_manager.auth import IPC, MCP, TokenMinter
from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.sessions import SessionProvisioner
from ads_sandbox_manager.store import SandboxSession, SessionRepository

REQUEST_TOPIC = "ads.sandbox.exec.request"
REPLY_TOPIC = "ads.sandbox.exec.reply"
READY_TOPIC = "ads.sandbox.ready"
log = logging.getLogger(__name__)


class Publisher(Protocol):
    async def send(self, topic: str, key: UUID, raw: bytes, token: str) -> None: ...


class Maintenance(Protocol):
    async def service_expired(self, row: SandboxSession) -> None: ...


@dataclass(frozen=True)
class VerifiedExec:
    """Constructed by the JWT/caller-checked boundary, never persisted or logged."""

    session_id: UUID
    message: SandboxExecInbound
    subject: str
    token: str = field(repr=False)


class TransitService:
    """Only initial requests ensure. Kafka polling never waits for lifecycle work."""

    def __init__(
        self,
        settings: Settings,
        sessions: async_sessionmaker[AsyncSession],
        repository: SessionRepository,
        provisioner: SessionProvisioner,
        publisher: Publisher,
        tokens: TokenMinter,
        maintenance: Maintenance,
    ) -> None:
        self.settings = settings
        self.sessions = sessions
        self.repository = repository
        self.provisioner = provisioner
        self.publisher = publisher
        self.tokens = tokens
        self.maintenance = maintenance
        self._pending: dict[UUID, VerifiedExec] = {}
        self._requests: dict[UUID, asyncio.Task[None]] = {}
        self._workers: dict[UUID, asyncio.Task[SandboxSession]] = {}

    async def _row(self, session_id: UUID) -> SandboxSession | None:
        async with self.sessions.begin() as db:
            return await self.repository.get(db, session_id)

    async def _send(
        self,
        topic: str,
        key: UUID,
        raw: bytes,
        audience: str,
        subject_token: str,
        *,
        held: VerifiedExec | None = None,
    ) -> None:
        async with asyncio.timeout(self.settings.control_seconds):
            context = await asyncio.to_thread(self.tokens.mint, audience, subject_token)
            if not context.access_token:
                raise RuntimeError("STE returned no token")
            if held is not None and self._pending.get(held.message.execution_id) is not held:
                return
            await self.publisher.send(topic, key, raw, context.access_token)

    async def accept(self, incoming: VerifiedExec) -> None:
        message = incoming.message
        if incoming.session_id != message.session_id:
            log.warning("request_session_key_mismatch")
            return
        if isinstance(message, SandboxRequest):
            if message.execution_id not in self._pending:
                self._pending[message.execution_id] = incoming
                task = asyncio.create_task(self._request(incoming), name="manager-request")
                self._requests[message.execution_id] = task
            return
        if isinstance(message, (SandboxAbort, SandboxAckReset)):
            held = self._pending.get(message.execution_id)
            if (
                held
                and held.message.session_id == message.session_id
                and held.message.message_id == message.message_id
                and held.subject == incoming.subject
            ):
                # Drop only the forwarding buffer. The provisioner is NOT cancelled.
                self._pending.pop(message.execution_id, None)
        async with asyncio.timeout(self.settings.control_seconds):
            row = await self._row(incoming.session_id)
        if row is not None:
            await self._send(
                f"sandbox.req.{row.sandbox_id}",
                incoming.session_id,
                encode_inbound(message),
                IPC,
                incoming.token,
            )

    def _worker(self, session_id: UUID) -> asyncio.Task[SandboxSession]:
        task = self._workers.get(session_id)
        if task is None or task.done():
            task = asyncio.create_task(
                self.provisioner.provision(session_id), name="manager-create"
            )
            self._workers[session_id] = task

            def finished(done: asyncio.Task[SandboxSession]) -> None:
                if self._workers.get(session_id) is done:
                    self._workers.pop(session_id, None)
                if not done.cancelled():
                    done.exception()  # Retrieve detached failures even after all waiters reset.

            task.add_done_callback(finished)
        return task

    async def _request(self, incoming: VerifiedExec) -> None:
        execution = incoming.message.execution_id
        service_transition = None
        try:
            async with asyncio.timeout(self.settings.ready_seconds) as wait:
                while self._pending.get(execution) is incoming:
                    row = await self._row(incoming.session_id)
                    if row is not None and row.status == "service":
                        if row.service_deadline is None:
                            raise RuntimeError("service has no durable deadline")
                        remaining = (row.service_deadline - datetime.now(UTC)).total_seconds()
                        if remaining <= 0:
                            await self.maintenance.service_expired(row)
                            raise TimeoutError("sandbox maintenance expired")
                        transition = (row.sandbox_id, row.status_changed_at)
                        if service_transition != transition:
                            # All callers share the persisted deadline, not a fresh timeout.
                            # Leave one bounded control interval to publish its failure verdict.
                            wait.reschedule(
                                asyncio.get_running_loop().time()
                                + remaining
                                + self.settings.control_seconds
                            )
                            service_transition = transition
                        await asyncio.sleep(min(self.settings.poll_seconds, 0.1))
                        continue
                    if service_transition is not None:
                        wait.reschedule(
                            asyncio.get_running_loop().time() + self.settings.ready_seconds
                        )
                        service_transition = None
                    if row is not None and row.status == "ready":
                        async with self.sessions.begin() as db:
                            row = await self.repository.admit(
                                db, incoming.session_id, datetime.now(UTC)
                            )
                        if row is None:
                            continue
                        # _send rechecks after STE so reset during minting drops this buffer.
                        if self._pending.get(execution) is incoming:
                            await self._send(
                                f"sandbox.req.{row.sandbox_id}",
                                incoming.session_id,
                                encode_inbound(incoming.message),
                                IPC,
                                incoming.token,
                                held=incoming,
                            )
                        return
                    if row is None or row.status == "stopped":
                        if self._pending.get(execution) is not incoming:
                            return
                        # Shield lifecycle from request timeout/reset. Other statuses only wait.
                        await asyncio.shield(self._worker(incoming.session_id))
                    else:
                        await asyncio.sleep(min(self.settings.poll_seconds, 0.1))
        except Exception:
            if self._pending.get(execution) is incoming:
                failure = SandboxResult(
                    execution, -1, "", "", False, 0, True, "sandbox preparation unavailable"
                )
                try:
                    await self._send(
                        REPLY_TOPIC,
                        incoming.session_id,
                        encode_outbound(failure),
                        MCP,
                        incoming.token,
                        held=incoming,
                    )
                except Exception:
                    log.warning("manager preparation error reply unavailable")
        finally:
            if self._pending.get(execution) is incoming:
                self._pending.pop(execution, None)
            if self._requests.get(execution) is asyncio.current_task():
                self._requests.pop(execution, None)

    async def reply(self, sandbox_id: UUID, message: SandboxExecOutbound, token: str) -> None:
        async with asyncio.timeout(self.settings.control_seconds):
            async with self.sessions.begin() as db:
                row = await self.repository.by_sandbox(db, sandbox_id)
        if row is None:
            log.warning("manager reply for unknown sandbox")
            return
        if isinstance(message, SandboxAcknowledge) and message.session_id != row.session_id:
            log.warning("manager acknowledge session mismatch")
            return
        # No status gate, output recapping, or manager execution tracking.
        await self._send(REPLY_TOPIC, row.session_id, encode_outbound(message), MCP, token)
        if isinstance(message, SandboxResult):
            async with asyncio.timeout(self.settings.control_seconds), self.sessions.begin() as db:
                await self.repository.stamp_result(db, sandbox_id, datetime.now(UTC))

    async def ready(self, sandbox_id: UUID) -> None:
        # IPC may emit ready before the Kubernetes create response's UID is committed.
        expected = None
        async with asyncio.timeout(self.settings.ready_seconds):
            while True:
                async with self.sessions.begin() as db:
                    row = await self.repository.by_sandbox(db, sandbox_id)
                    if row is None or row.status != "creating":
                        if row is not None and row.status == "ready":
                            log.warning("manager duplicate IPC ready")
                        return
                    if expected is None:
                        expected = row.status_changed_at
                    if row.status_changed_at != expected:
                        return
                    if await self.repository.mark_ready(
                        db, sandbox_id, datetime.now(UTC), expected
                    ):
                        return
                await asyncio.sleep(min(self.settings.poll_seconds, 0.1))

    async def stop(self) -> None:
        tasks = [*self._requests.values(), *self._workers.values()]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._requests.clear()
        self._workers.clear()
        self._pending.clear()
        await self.provisioner.drain()
