from __future__ import annotations

import uuid
from collections.abc import Collection
from typing import Protocol

from ads_commons.engine import EngineRequest, ErrorOutput, decode_request, peek_request_ids
from ads_commons.security import (
    AccessDenied,
    AuthenticationRequired,
    InvalidAccessToken,
    SecurityContext,
    SecurityContextHolder,
    ensure_caller,
)
from ads_engine.service import EngineService, OutputPublisher

SESSION_ID = "session_id"
MESSAGE_ID = "message_id"


class TokenAuthenticator(Protocol):
    def authenticate(self, token: str) -> SecurityContext: ...


class EngineListener:
    """Kafka controller: map the request DTO, bind identity, invoke the service."""

    def __init__(
        self,
        service: EngineService,
        publisher: OutputPublisher,
        authenticator: TokenAuthenticator,
        allowed_callers: Collection[str],
    ) -> None:
        self._service = service
        self._publisher = publisher
        self._authenticator = authenticator
        self._allowed_callers = frozenset(allowed_callers)

    async def on_message(self, raw: bytes) -> None:
        ids = peek_request_ids(raw)
        if ids is None:
            return
        session_id, message_id = ids
        try:
            request = decode_request(raw)
        except Exception as exc:
            await self.emit_error(session_id, message_id, f"invalid request: {exc}")
            return
        await self._bind_and_run(request)

    async def _bind_and_run(self, request: EngineRequest) -> None:
        try:
            context = self._bind_context(request)
        except InvalidAccessToken as exc:
            await self.emit_error(
                request.session_id,
                request.message_id,
                f"invalid authorization: {exc.detail}",
            )
            return
        except AccessDenied as exc:
            await self.emit_error(request.session_id, request.message_id, exc.detail)
            return
        with SecurityContextHolder.bound(context):
            await self._invoke(request)

    def _bind_context(self, request: EngineRequest) -> SecurityContext:
        context = self._authenticator.authenticate(request.authorization.token).with_attributes(
            session_id=request.session_id,
            message_id=request.message_id,
        )
        ensure_caller(context, *self._allowed_callers)
        return context

    async def _invoke(self, request: EngineRequest) -> None:
        try:
            await self._service.handle(request)
        except (AccessDenied, AuthenticationRequired) as exc:
            await self.handle_access_denied(exc)
        except Exception as exc:
            await self.handle_exception(exc)

    async def handle_access_denied(self, exception: AccessDenied | AuthenticationRequired) -> None:
        session_id, message_id = _request_ids(SecurityContextHolder.require())
        await self.emit_error(session_id, message_id, exception.detail)

    async def handle_exception(self, exception: Exception) -> None:
        session_id, message_id = _request_ids(SecurityContextHolder.require())
        await self.emit_error(session_id, message_id, str(exception))

    async def emit_error(self, session_id: uuid.UUID, message_id: uuid.UUID, text: str) -> None:
        await self._publisher.publish(
            session_id,
            ErrorOutput(session_id=session_id, message_id=message_id, text=text),
        )


def _request_ids(context: SecurityContext) -> tuple[uuid.UUID, uuid.UUID]:
    session_id = context.attribute(SESSION_ID)
    message_id = context.attribute(MESSAGE_ID)
    if not isinstance(session_id, uuid.UUID) or not isinstance(message_id, uuid.UUID):
        raise RuntimeError("security context missing request identifiers")
    return session_id, message_id
