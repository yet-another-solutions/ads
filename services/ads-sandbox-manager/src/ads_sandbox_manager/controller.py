from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from uuid import UUID

import msgspec

from ads_commons.engine import authorization_token
from ads_commons.sandbox import (
    SandboxReady,
    SandboxShutdownAck,
    decode_inbound,
    decode_outbound,
    decode_ping,
    decode_ready,
)
from ads_commons.security import ensure_caller
from ads_commons_beans import JwtVerifier
from ads_sandbox_manager.auth import IPC, MANAGER, MCP
from ads_sandbox_manager.barrier import TOPIC, BarrierMessage, ManagerBarrier
from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.lifecycle import PING_REPLY, TOPICS, LifecycleService, Signal
from ads_sandbox_manager.service import READY_TOPIC, REQUEST_TOPIC, TransitService, VerifiedExec

log = logging.getLogger(__name__)


class KafkaController:
    """Authenticated boundary. No unverified identity, holder binding, or token logging."""

    def __init__(
        self,
        settings: Settings,
        verifier: JwtVerifier,
        service: TransitService,
        barrier: ManagerBarrier,
        lifecycle: LifecycleService,
    ) -> None:
        self.settings = settings
        self.verifier = verifier
        self.service = service
        self.barrier = barrier
        self.lifecycle = lifecycle

    async def admit_lifecycle(
        self,
        topic: str,
        raw: bytes,
        key: bytes | None,
        headers: Sequence[tuple[str | bytes, bytes | None]] | None = None,
    ) -> None:
        # Only malformed/unauthorized messages are classified here. DB admission failures
        # must escape so the durable consumer cannot commit past unfinished work.
        try:
            if topic not in TOPICS:
                return
            token = authorization_token(headers)
            if token is None:
                return
            async with asyncio.timeout(self.settings.control_seconds):
                context = await asyncio.to_thread(self.verifier.authenticate, token)
                ensure_caller(context, MANAGER)
            message = msgspec.json.decode(raw, type=Signal)
            if key != str(message.session_id).encode():
                return
        except Exception:
            log.warning("manager lifecycle signal rejected")
            return
        await self.lifecycle.admit(topic, message)

    async def on_message(
        self,
        topic: str,
        raw: bytes,
        key: bytes | None,
        headers: Sequence[tuple[str | bytes, bytes | None]] | None = None,
    ) -> None:
        try:
            if topic not in (
                REQUEST_TOPIC,
                READY_TOPIC,
                TOPIC,
                PING_REPLY,
            ) and not topic.startswith("sandbox.res."):
                return
            token = authorization_token(headers)
            if token is None:
                log.warning("manager missing authorization")
                return
            async with asyncio.timeout(self.settings.control_seconds):
                context = await asyncio.to_thread(self.verifier.authenticate, token)
                ensure_caller(
                    context, MCP if topic == REQUEST_TOPIC else MANAGER if topic == TOPIC else IPC
                )
            if topic == REQUEST_TOPIC:
                message = decode_inbound(raw)
                if key != str(message.session_id).encode():
                    log.warning("manager request session key mismatch")
                    return
                await self.service.accept(
                    VerifiedExec(message.session_id, message, context.subject, token)
                )
            elif topic == PING_REPLY:
                ping = decode_ping(raw)
                if key == str(ping.sandbox_id).encode():
                    await self.lifecycle.ping_reply(ping)
            elif topic == READY_TOPIC:
                lifecycle = decode_ready(raw)
                if (
                    isinstance(lifecycle, SandboxReady)
                    and key == str(lifecycle.sandbox_id).encode()
                ):
                    await self.service.ready(lifecycle.sandbox_id)
                elif (
                    isinstance(lifecycle, SandboxShutdownAck)
                    and key == str(lifecycle.sandbox_id).encode()
                ):
                    await self.lifecycle.shutdown_ack(lifecycle.sandbox_id, lifecycle.transition)
                # Startup error handling remains outside v1.
            elif topic == TOPIC:
                coordination = msgspec.json.decode(raw, type=BarrierMessage)
                if key == str(coordination.sandbox_id).encode():
                    await self.barrier.accept(coordination)
            else:
                sandbox_id = UUID(topic.removeprefix("sandbox.res."))
                if topic != f"sandbox.res.{sandbox_id}" or key != str(sandbox_id).encode():
                    return
                await self.service.reply(sandbox_id, decode_outbound(raw), token)
        except Exception:
            # Includes decode, authentication, lookup, STE and publish errors; no payloads.
            log.warning("manager message rejected or processing unavailable")
