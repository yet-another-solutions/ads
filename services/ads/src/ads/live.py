"""In-process live channel. Not the source of truth: persist first, then notify."""

from __future__ import annotations

import uuid
from typing import Protocol

import structlog

log = structlog.get_logger("ads.live")


class LiveSocket(Protocol):
    async def send_json(self, data: object) -> None: ...


def room_of(session_id: uuid.UUID) -> str:
    return f"session:{session_id}"


class LiveHub:
    """Rooms of websockets keyed ``session:{session_id}``. No Redis, one process."""

    def __init__(self) -> None:
        self._rooms: dict[str, set[LiveSocket]] = {}

    def join(self, session_id: uuid.UUID, socket: LiveSocket) -> None:
        self._rooms.setdefault(room_of(session_id), set()).add(socket)

    def leave(self, socket: LiveSocket) -> None:
        for room, members in list(self._rooms.items()):
            members.discard(socket)
            if not members:
                self._rooms.pop(room, None)

    def members(self, session_id: uuid.UUID) -> int:
        return len(self._rooms.get(room_of(session_id), ()))

    async def notify(self, session_id: uuid.UUID) -> None:
        payload = {"type": "session-updated", "session_id": str(session_id)}
        for socket in list(self._rooms.get(room_of(session_id), ())):
            try:
                await socket.send_json(payload)
            except Exception:  # a dead socket must not break the unit of work
                log.info("live_socket_dropped", session_id=str(session_id))
                self._rooms.get(room_of(session_id), set()).discard(socket)
