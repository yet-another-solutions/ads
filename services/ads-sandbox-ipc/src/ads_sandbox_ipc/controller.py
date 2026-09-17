from __future__ import annotations

import asyncio
from collections.abc import Sequence

import structlog

from ads_commons.engine import authorization_token
from ads_commons.sandbox import (
    SandboxExecInbound,
    SandboxPing,
    SandboxReadyMessage,
    SandboxShutdown,
    decode_inbound,
    decode_ping,
    decode_ready,
)
from ads_commons.security import AccessDenied, InvalidAccessToken, ensure_caller
from ads_commons_beans import JwtVerifier
from ads_sandbox_ipc.config import Settings
from ads_sandbox_ipc.service import IpcService, VerifiedMessage

READY_TOPIC = "ads.sandbox.ready"
PING_REQUEST_TOPIC = "ads.sandbox.ping.req"
PING_REPLY_TOPIC = "ads.sandbox.ping.res"
log = structlog.get_logger("ads_sandbox_ipc")


class KafkaController:
    """Decode and authenticate at the boundary. Never bind SecurityContextHolder."""

    def __init__(self, settings: Settings, verifier: JwtVerifier, service: IpcService) -> None:
        self.settings = settings
        self.verifier = verifier
        self.service = service

    async def on_message(
        self,
        topic: str,
        raw: bytes,
        headers: Sequence[tuple[str | bytes, bytes | None]] | None = None,
    ) -> None:
        message: SandboxExecInbound | SandboxReadyMessage | SandboxPing
        try:
            if topic == READY_TOPIC:
                message = decode_ready(raw)
                if not isinstance(message, SandboxShutdown):
                    return
                if message.sandbox_id != self.settings.sandbox_id:
                    return
            elif topic == PING_REQUEST_TOPIC:
                message = decode_ping(raw)
                if message.sandbox_id != self.settings.sandbox_id:
                    return
            elif topic == self.settings.request_topic:
                message = decode_inbound(raw)
            else:
                return
        except (TypeError, ValueError):
            log.warning("ipc_invalid_message")
            return
        token = authorization_token(headers)
        if token is None:
            log.warning("ipc_missing_authorization")
            return
        try:
            context = await asyncio.to_thread(self.verifier.authenticate, token)
            ensure_caller(context, "ads-sandbox-manager")
            # Use only verified claims for TTL. No unverified decode or holder binding.
            claims = await asyncio.to_thread(self.verifier.verified_claims, token)
        except (InvalidAccessToken, AccessDenied):
            log.warning("ipc_invalid_authorization")
            return
        try:
            if isinstance(message, SandboxShutdown):
                await self.service.shutdown(token)
            elif topic == PING_REQUEST_TOPIC:
                await self.service.ping(decode_ping(raw), token)
            else:
                await self.service.accept(
                    VerifiedMessage(
                        decode_inbound(raw), context.subject, token, float(claims["exp"])
                    )
                )
        except Exception:
            # Do not include exception text: it can contain a JWT, command, or kube credentials.
            log.warning("ipc_message_processing_failed")
