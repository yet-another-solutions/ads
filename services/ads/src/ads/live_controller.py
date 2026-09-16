"""Litestar WebSocket for the live channel. Cookie identity, ownership checked before join."""

from __future__ import annotations

import uuid
from typing import Any

import structlog
from litestar import WebSocket, websocket
from litestar.exceptions import WebSocketDisconnect
from sqlalchemy.orm import Session

from ads.live import LiveHub
from ads.repository import SessionRepository
from ads_commons.security import SecurityContextHolder

log = structlog.get_logger("ads.live")


def _owns(session_factory: Any, user_id: uuid.UUID, session_id: uuid.UUID) -> bool:
    session: Session = session_factory()
    try:
        with session.begin():
            row = SessionRepository(session=session).get_any(session_id)
            return row is not None and row.user_id == user_id
    finally:
        session.close()


@websocket("/ws")
async def live_socket(socket: WebSocket[Any, Any, Any]) -> None:
    """Join ``session:{id}`` only after ownership holds. No payload leaves the hub."""
    context = SecurityContextHolder.get()
    await socket.accept()
    if context is None:
        await socket.send_json({"type": "unauthorized"})
        await socket.close()
        return
    hub: LiveHub = socket.app.state.live_hub
    session_factory = socket.app.state.db_session_factory
    try:
        user_id = context.user_id
    except ValueError:
        await socket.close()
        return
    try:
        while True:
            message = await socket.receive_json()
            if not isinstance(message, dict) or message.get("type") != "join":
                continue
            raw = message.get("session_id")
            if not isinstance(raw, str):
                continue
            try:
                session_id = uuid.UUID(raw)
            except ValueError:
                continue
            if not _owns(session_factory, user_id, session_id):
                await socket.send_json({"type": "forbidden", "session_id": raw})
                continue
            hub.leave(socket)
            hub.join(session_id, socket)
            await socket.send_json({"type": "joined", "session_id": raw})
    except WebSocketDisconnect:
        return
    finally:
        hub.leave(socket)
