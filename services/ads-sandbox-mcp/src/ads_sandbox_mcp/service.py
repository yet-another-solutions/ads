from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID, uuid4

import anyio
import structlog
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ads_commons.sandbox.handshake import (
    SandboxAbort,
    SandboxAcknowledge,
    SandboxAckReply,
    SandboxAckReset,
    SandboxExecInbound,
    SandboxExecKind,
    SandboxExecOutbound,
    SandboxRequest,
    SandboxResult,
)
from ads_commons.security import SecurityContext, SecurityContextHolder, require_caller
from ads_sandbox_mcp.config import Settings
from ads_sandbox_mcp.store import InFlight, InFlightRepository

log = structlog.get_logger("ads_sandbox_mcp")
MANAGER = "ads-sandbox-manager"


class Publisher(Protocol):
    async def publish(
        self,
        message: SandboxExecInbound,
        headers: Sequence[tuple[str, bytes]],
        *,
        session_id: UUID,
    ) -> None: ...


class TokenMinter(Protocol):
    def mint(self, audience: str, subject_token: str | None = None) -> SecurityContext: ...


@dataclass(frozen=True)
class VerifiedReply:
    """Created only by the authenticated Kafka controller. Never binds the HTTP holder."""

    message: SandboxExecOutbound
    subject_token: str = field(repr=False)


@dataclass
class Waiter:
    result: asyncio.Future[SandboxResult]
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


def failure(execution_id: UUID, text: str) -> SandboxResult:
    return SandboxResult(execution_id, -1, "", "", False, 0, True, text)


class Watchdog:
    """Poll durable deadlines; acknowledgement by another pod must reset the wait."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def wait(
        self,
        execution_id: UUID,
        waiter: Waiter,
        check: Callable[[], Awaitable[bool]],
    ) -> None:
        interval = min(0.1, self._settings.timeout_seconds / 10)
        last_observed = asyncio.get_running_loop().time()
        while True:
            await asyncio.sleep(interval)
            try:
                # Losing the database must not leave a live HTTP waiter forever.
                async with asyncio.timeout(self._settings.timeout_seconds):
                    expired = await check()
                last_observed = asyncio.get_running_loop().time()
            except Exception:
                log.warning("watchdog_store_failed", execution_id=str(execution_id))
                if (
                    asyncio.get_running_loop().time() - last_observed
                    >= self._settings.timeout_seconds
                ):
                    if not waiter.result.done():
                        waiter.result.set_result(
                            failure(execution_id, "sandbox execution state unavailable")
                        )
                    return
                continue
            if expired:
                if not waiter.result.done():
                    waiter.result.set_result(failure(execution_id, "sandbox execution timed out"))
                return


class ExecService:
    """Own the blocking exec and durable ack boundary; no protocol parsing here."""

    def __init__(
        self,
        settings: Settings,
        sessions: async_sessionmaker[AsyncSession],
        repository: InFlightRepository,
        publisher: Publisher,
        tokens: TokenMinter,
        watchdog: Watchdog,
    ) -> None:
        self._settings = settings
        self._sessions = sessions
        self._repository = repository
        self._publisher = publisher
        self._tokens = tokens
        self._watchdog = watchdog
        self._waiters: dict[UUID, Waiter] = {}

    async def _headers(self, subject_token: str | None = None) -> list[tuple[str, bytes]]:
        minted = await asyncio.to_thread(self._tokens.mint, MANAGER, subject_token)
        if not minted.access_token:
            raise RuntimeError("token exchange returned no token")
        return [("authorization", minted.access_token.encode())]

    @require_caller("ads-engine")
    async def execute(self, kind: SandboxExecKind, payload: str) -> SandboxResult:
        context = SecurityContextHolder.require()
        session_id = context.attribute("session_id")
        message_id = context.attribute("message_id")
        if not isinstance(session_id, UUID) or not isinstance(message_id, UUID):
            raise ValueError("security context missing ADS identifiers")
        execution_id = uuid4()
        try:
            async with asyncio.timeout(self._settings.timeout_seconds):
                headers = await self._headers()
            now = datetime.now(UTC)
            async with self._sessions.begin() as session:
                await self._repository.insert(
                    session,
                    InFlight(
                        execution_id=execution_id,
                        session_id=session_id,
                        message_id=message_id,
                        created_at=now,
                        deadline=now + timedelta(seconds=self._settings.timeout_seconds),
                        timed_out=False,
                        ack_replied=False,
                    ),
                )
        except Exception:
            log.warning("exec_setup_failed", execution_id=str(execution_id))
            return failure(execution_id, "sandbox execution setup failed")

        waiter = Waiter(asyncio.get_running_loop().create_future())
        self._waiters[execution_id] = waiter
        watchdog = asyncio.create_task(
            self._watchdog.wait(
                execution_id,
                waiter,
                lambda: self._expire(execution_id, context.access_token, force=False),
            )
        )
        request = SandboxRequest(execution_id, session_id, message_id, kind, payload)
        try:
            # After insert, publication failure is resolved by the watchdog, not an early return.
            try:
                async with asyncio.timeout(self._settings.timeout_seconds):
                    await self._publisher.publish(request, headers, session_id=session_id)
            except Exception:
                log.warning("request_publish_failed", execution_id=str(execution_id))
            return await asyncio.shield(waiter.result)
        except BaseException:
            # SDK disconnect cancellation is level-triggered under AnyIO. Shield cleanup.
            with anyio.CancelScope(shield=True):
                try:
                    await self._expire(execution_id, context.access_token, force=True)
                except Exception:
                    log.warning("cancel_cleanup_failed", execution_id=str(execution_id))
            raise
        finally:
            self._waiters.pop(execution_id, None)
            watchdog.cancel()
            with anyio.CancelScope(shield=True):
                await asyncio.gather(watchdog, return_exceptions=True)

    async def accept_reply(self, reply: VerifiedReply) -> None:
        """Authenticated Kafka entry, intentionally without a user holder bind."""
        message = reply.message
        if isinstance(message, SandboxAcknowledge):
            await self._acknowledge(message, reply.subject_token)
            return
        waiter = self._waiters.get(message.execution_id)
        if waiter is None or waiter.result.done():
            log.warning("result_without_waiter", execution_id=str(message.execution_id))
            return
        # Keep local completion and DB commit atomic with respect to this pod's watchdog.
        async with waiter.lock:
            async with self._sessions.begin() as session:
                row = await self._repository.locked(session, message.execution_id)
                if row is None or row.timed_out or datetime.now(UTC) >= row.deadline:
                    log.warning("result_without_live_row", execution_id=str(message.execution_id))
                    return
                await self._repository.remove(session, row)
            if not waiter.result.done():
                waiter.result.set_result(message)

    async def _acknowledge(self, message: SandboxAcknowledge, subject_token: str) -> None:
        # Serialize across pods with the same row lock used by expiry. The bounded send
        # is inside this transaction so timeout cannot cross a successful ack-reply.
        execution_id = message.execution_id
        async with self._sessions.begin() as session:
            row = await self._repository.locked(session, execution_id)
            if (
                row is None
                or row.session_id != message.session_id
                or row.message_id != message.message_id
            ):
                return
            if row.ack_replied and not row.timed_out:
                # A duplicate must neither extend the deadline nor preempt the
                # watchdog's post-ack abort with a pre-ack reset.
                return
            if datetime.now(UTC) >= row.deadline:
                row.timed_out = True
            if row.timed_out:
                async with asyncio.timeout(self._settings.timeout_seconds):
                    await self._publisher.publish(
                        SandboxAckReset(execution_id, row.session_id, row.message_id),
                        await self._headers(subject_token),
                        session_id=row.session_id,
                    )
                await self._repository.remove(session, row)
                return
            row.deadline = datetime.now(UTC) + timedelta(seconds=self._settings.timeout_seconds)
            async with asyncio.timeout(self._settings.timeout_seconds):
                await self._publisher.publish(
                    SandboxAckReply(execution_id, row.session_id, row.message_id),
                    await self._headers(subject_token),
                    session_id=row.session_id,
                )
            row.ack_replied = True

    async def _expire(self, execution_id: UUID, subject_token: str | None, *, force: bool) -> bool:
        waiter = self._waiters.get(execution_id)
        async with waiter.lock if waiter else asyncio.Lock():
            if waiter is not None and waiter.result.done():
                return True
            return await self._expire_locked(execution_id, subject_token, force=force)

    async def _expire_locked(
        self, execution_id: UUID, subject_token: str | None, *, force: bool
    ) -> bool:
        acknowledged = False
        session_id: UUID
        message_id: UUID
        async with self._sessions.begin() as session:
            row = await self._repository.locked(session, execution_id)
            if row is None:
                return True
            if not force and not row.timed_out and datetime.now(UTC) < row.deadline:
                return False
            acknowledged = row.ack_replied and not row.timed_out
            session_id = row.session_id
            message_id = row.message_id
            row.timed_out = True
        # Tombstone commits before best-effort control publication.
        if acknowledged:
            try:
                async with asyncio.timeout(self._settings.timeout_seconds):
                    await self._publisher.publish(
                        SandboxAbort(execution_id, session_id, message_id),
                        await self._headers(subject_token),
                        session_id=session_id,
                    )
            except Exception:
                log.warning("abort_publish_failed", execution_id=str(execution_id))
        # Before acknowledge there is no recipient to reset. The tombstone answers
        # the eventual acknowledge with ack-reset, never abort.
        return True
