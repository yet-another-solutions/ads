from __future__ import annotations

import asyncio
import json
import uuid

from ads_commons.engine import (
    Acknowledge,
    ErrorOutput,
    Finish,
    PartialResponse,
    Ping,
    encode_request,
)
from ads_engine.chat import StreamDelta
from ads_engine.service import EngineService
from ads_engine.store import ActiveSessionStore
from engine_fakes import RecordingPublisher, ScriptedChat, make_request


def _run(coro: object) -> None:
    asyncio.run(coro)  # type: ignore[arg-type]


def test_missing_ids_are_dropped(store: ActiveSessionStore) -> None:
    publisher = RecordingPublisher()
    service = EngineService(store, publisher, ScriptedChat(), ping_interval_seconds=10)

    async def _body() -> None:
        await service.handle_raw(b"{}")
        await service.handle_raw(b'{"session_id": "11111111-1111-1111-1111-111111111111"}')

    _run(_body())
    assert publisher.messages == []


def test_invalid_request_emits_error_without_ack(store: ActiveSessionStore) -> None:
    publisher = RecordingPublisher()
    service = EngineService(store, publisher, ScriptedChat(), ping_interval_seconds=10)
    raw = json.dumps(
        {
            "session_id": "11111111-1111-1111-1111-111111111111",
            "message_id": "22222222-2222-2222-2222-222222222222",
            "history": [],
            "user_input": "hi",
            "instructions": "",
            "model": {"type": "unknown"},
            "authorization": {"token": "jwt"},
        }
    ).encode()

    _run(service.handle_raw(raw))
    assert len(publisher.messages) == 1
    error = publisher.messages[0]
    assert isinstance(error, ErrorOutput)
    assert error.message_id == uuid.UUID("22222222-2222-2222-2222-222222222222")
    assert "invalid request" in error.text


def test_garbage_authorization_is_accepted(store: ActiveSessionStore) -> None:
    publisher = RecordingPublisher()
    chat = ScriptedChat([StreamDelta(kind="message", text="ok")])
    service = EngineService(store, publisher, chat, ping_interval_seconds=10)
    request = make_request(authorization_token="not-a-jwt")

    _run(service.handle(request))
    types = [type(message).__name__ for message in publisher.messages]
    assert types == ["Acknowledge", "PartialResponse", "Finish"]
    assert chat.requests[0].authorization.token == "not-a-jwt"


def test_duplicate_session_errors_without_stopping_active_run(
    store: ActiveSessionStore,
) -> None:
    publisher = RecordingPublisher()
    started = asyncio.Event()
    release = asyncio.Event()

    class SlowChat:
        def stream(self, request: object) -> object:
            return self._stream(request)

        async def _stream(self, request: object) -> object:
            started.set()
            await release.wait()
            yield StreamDelta(kind="message", text="done")

    service = EngineService(store, publisher, SlowChat(), ping_interval_seconds=10)
    first = make_request(message_id=uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"))
    second = make_request(message_id=uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"))

    async def _body() -> None:
        task = asyncio.create_task(service.handle(first))
        await started.wait()
        await service.handle(second)
        release.set()
        await task

    _run(_body())
    errors = [message for message in publisher.messages if isinstance(message, ErrorOutput)]
    acks = [message for message in publisher.messages if isinstance(message, Acknowledge)]
    finishes = [message for message in publisher.messages if isinstance(message, Finish)]
    assert len(errors) == 1
    assert errors[0].message_id == second.message_id
    assert errors[0].text == "session already active"
    assert len(acks) == 1
    assert acks[0].message_id == first.message_id
    assert len(finishes) == 1


def test_successful_chat_emits_ack_delta_partials_and_finish(
    store: ActiveSessionStore,
) -> None:
    publisher = RecordingPublisher()
    chat = ScriptedChat(
        [
            StreamDelta(kind="reasoning", text="think"),
            StreamDelta(kind="message", text="Hello"),
        ]
    )
    service = EngineService(store, publisher, chat, ping_interval_seconds=10)

    _run(service.handle(make_request()))
    assert isinstance(publisher.messages[0], Acknowledge)
    first = publisher.messages[1]
    second = publisher.messages[2]
    assert isinstance(first, PartialResponse)
    assert first.order == 0
    assert first.reasoning is not None
    assert first.reasoning.text == "think"
    assert isinstance(second, PartialResponse)
    assert second.order == 1
    assert second.message is not None
    assert second.message.text == "Hello"
    assert isinstance(publisher.messages[3], Finish)


def test_openai_retries_before_partial_then_succeeds(store: ActiveSessionStore) -> None:
    publisher = RecordingPublisher()
    chat = ScriptedChat([StreamDelta(kind="message", text="ok")], fail_times=2)
    service = EngineService(store, publisher, chat, ping_interval_seconds=10)

    _run(service.handle(make_request()))
    assert chat.calls == 3
    assert isinstance(publisher.messages[-1], Finish)


def test_openai_gives_up_after_three_failures_before_partial(
    store: ActiveSessionStore,
) -> None:
    publisher = RecordingPublisher()
    chat = ScriptedChat(fail_times=5)
    service = EngineService(store, publisher, chat, ping_interval_seconds=10)

    _run(service.handle(make_request()))
    assert chat.calls == 3
    error = publisher.messages[-1]
    assert isinstance(error, ErrorOutput)
    assert error.message_id == uuid.UUID("22222222-2222-2222-2222-222222222222")
    assert not any(isinstance(message, Finish) for message in publisher.messages)


def test_no_retry_after_partial_was_emitted(store: ActiveSessionStore) -> None:
    publisher = RecordingPublisher()
    chat = ScriptedChat([StreamDelta(kind="message", text="Hel")], fail_after_partial=True)
    service = EngineService(store, publisher, chat, ping_interval_seconds=10)

    _run(service.handle(make_request()))
    assert chat.calls == 1
    assert isinstance(publisher.messages[1], PartialResponse)
    assert isinstance(publisher.messages[-1], ErrorOutput)
    assert not any(isinstance(message, Finish) for message in publisher.messages)


def test_empty_user_input_is_validation_error(store: ActiveSessionStore) -> None:
    publisher = RecordingPublisher()
    service = EngineService(store, publisher, ScriptedChat(), ping_interval_seconds=10)
    raw = encode_request(make_request(user_input=""))

    _run(service.handle_raw(raw))
    error = publisher.messages[0]
    assert isinstance(error, ErrorOutput)
    assert "user_input" in error.text
    assert not any(isinstance(message, Acknowledge) for message in publisher.messages)


def test_ping_is_emitted_for_active_session(store: ActiveSessionStore) -> None:
    pinged = asyncio.Event()

    class Publisher(RecordingPublisher):
        async def publish(self, session_id: uuid.UUID, message: object) -> None:
            await super().publish(session_id, message)
            if isinstance(message, Ping):
                pinged.set()

    class OneDeltaChat:
        def stream(self, request: object) -> object:
            return self._stream(request)

        async def _stream(self, request: object) -> object:
            await pinged.wait()
            yield StreamDelta(kind="message", text="ok")

    publisher = Publisher()
    service = EngineService(
        store,
        publisher,
        OneDeltaChat(),
        ping_interval_seconds=0.01,
        sleep=lambda _seconds: asyncio.sleep(0),
    )
    _run(service.handle(make_request()))
    assert any(isinstance(message, Ping) for message in publisher.messages)
    assert isinstance(publisher.messages[-1], Finish)
