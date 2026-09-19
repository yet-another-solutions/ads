from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from ads_sandbox_mcp.http import mcp_endpoint

pytestmark = pytest.mark.anyio


async def test_adapter_forwards_request_frames_and_sdk_response_without_interpretation():
    incoming = asyncio.Queue()
    frames = [
        {"type": "http.request", "body": b"not JSON: first chunk", "more_body": True},
        {"type": "http.request", "body": b"last chunk", "more_body": False},
    ]
    response = [
        {"type": "http.response.start", "status": 400, "headers": [(b"x-sdk", b"owned")]},
        {"type": "http.response.body", "body": b"SDK response", "more_body": False},
    ]
    received, sent = [], []
    receive_finished = asyncio.Event()

    async def handle_request(scope, receive, send):
        assert scope is request_scope
        for frame in frames:
            event = await receive()
            assert event is frame
            received.append(event)
        for event in response:
            await send(event)

    async def receive():
        try:
            return await incoming.get()
        finally:
            receive_finished.set()

    async def send(event):
        sent.append(event)

    runtime = SimpleNamespace(
        sdk=SimpleNamespace(session_manager=SimpleNamespace(handle_request=handle_request))
    )
    request_scope = {"app": SimpleNamespace(state=SimpleNamespace(runtime=runtime))}
    for frame in frames:
        incoming.put_nowait(frame)
    await asyncio.wait_for(mcp_endpoint.fn(request_scope, receive, send), 2)
    assert received == frames
    assert sent == response
    assert all(actual is expected for actual, expected in zip(sent, response, strict=True))
    assert receive_finished.is_set()


async def test_adapter_disconnect_cancels_sdk_and_does_not_forward_disconnect():
    incoming = asyncio.Queue()
    entered, stopped = asyncio.Event(), asyncio.Event()
    sent = []

    async def handle_request(scope, receive, send):
        entered.set()
        try:
            await receive()
            pytest.fail("disconnect must cancel, not become a request body")
        finally:
            stopped.set()

    async def send(event):
        sent.append(event)

    runtime = SimpleNamespace(
        sdk=SimpleNamespace(session_manager=SimpleNamespace(handle_request=handle_request))
    )
    scope = {"app": SimpleNamespace(state=SimpleNamespace(runtime=runtime))}
    task = asyncio.create_task(mcp_endpoint.fn(scope, incoming.get, send))
    await asyncio.wait_for(entered.wait(), 2)
    incoming.put_nowait({"type": "http.disconnect"})
    await asyncio.wait_for(task, 2)
    assert stopped.is_set()
    assert sent == []
