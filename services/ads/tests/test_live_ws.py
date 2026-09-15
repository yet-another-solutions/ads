from __future__ import annotations

import asyncio
import time
import uuid

from litestar import Litestar
from litestar.testing import TestClient

from ads.live import LiveHub
from tests.threadline_fakes import login
from tests.threadline_flows import create_project, create_session


class _Socket:
    def __init__(self) -> None:
        self.sent: list[object] = []

    async def send_json(self, data: object) -> None:
        self.sent.append(data)


def test_hub_notifies_only_the_room() -> None:
    hub = LiveHub()
    first, second = _Socket(), _Socket()
    room = uuid.uuid4()
    other = uuid.uuid4()
    hub.join(room, first)
    hub.join(other, second)
    asyncio.run(hub.notify(room))
    assert first.sent == [{"type": "session-updated", "session_id": str(room)}]
    assert second.sent == []
    hub.leave(first)
    asyncio.run(hub.notify(room))
    assert len(first.sent) == 1


def test_hub_drops_a_dead_socket() -> None:
    class _Dead:
        async def send_json(self, data: object) -> None:
            raise RuntimeError("closed")

    hub = LiveHub()
    room = uuid.uuid4()
    hub.join(room, _Dead())
    asyncio.run(hub.notify(room))
    assert hub.members(room) == 0


def test_websocket_join_requires_ownership(client: TestClient, app: Litestar) -> None:
    login(client)
    project = create_project(client)
    session_id = create_session(client, project)
    with client.websocket_connect("/ws") as socket:
        socket.send_json({"type": "join", "session_id": str(session_id)})
        assert socket.receive_json() == {"type": "joined", "session_id": str(session_id)}
        stranger = str(uuid.uuid4())
        socket.send_json({"type": "join", "session_id": stranger})
        assert socket.receive_json() == {"type": "forbidden", "session_id": stranger}
    for _ in range(50):
        if app.state.live_hub.members(session_id) == 0:
            break
        time.sleep(0.02)
    assert app.state.live_hub.members(session_id) == 0


def test_anonymous_websocket_is_rejected(client: TestClient) -> None:
    with client.websocket_connect("/ws") as socket:
        assert socket.receive_json() == {"type": "unauthorized"}
