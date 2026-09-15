from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import Callable
from typing import Any

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from ads_commons.engine import (
    Acknowledge,
    ErrorOutput,
    Finish,
    PartialResponse,
    Ping,
    encode_request,
)
from ads_commons.security import JwtVerifier, SecurityContextHolder, require_caller
from ads_engine.chat import StreamDelta
from ads_engine.listener import EngineListener
from ads_engine.service import EngineService
from ads_engine.store import ActiveSessionStore
from engine_fakes import RecordingPublisher, ScriptedChat, encode_access_token, make_request

ALLOWED = frozenset({"ads"})


def _run(coro: object) -> None:
    asyncio.run(coro)  # type: ignore[arg-type]


def _service(
    store: ActiveSessionStore,
    publisher: RecordingPublisher,
    chat: object,
    ping_interval_seconds: float = 10,
    sleep: Callable[[float], Any] | None = None,
) -> EngineService:
    kwargs: dict[str, Any] = {}
    if sleep is not None:
        kwargs["sleep"] = sleep
    return EngineService(
        store,
        publisher,
        chat,  # type: ignore[arg-type]
        ping_interval_seconds=ping_interval_seconds,
        allowed_callers=ALLOWED,
        **kwargs,
    )


def _listener(
    store: ActiveSessionStore,
    publisher: RecordingPublisher,
    chat: object,
    jwt_verifier: JwtVerifier,
    ping_interval_seconds: float = 10,
    sleep: Callable[[float], Any] | None = None,
) -> EngineListener:
    return EngineListener(
        _service(store, publisher, chat, ping_interval_seconds=ping_interval_seconds, sleep=sleep),
        publisher,
        jwt_verifier,
        ALLOWED,
    )


def _handle(listener: EngineListener, request: object) -> None:
    _run(listener.on_message(encode_request(request)))  # type: ignore[arg-type]


def test_missing_ids_are_dropped(store: ActiveSessionStore, jwt_verifier: JwtVerifier) -> None:
    publisher = RecordingPublisher()
    listener = _listener(store, publisher, ScriptedChat(), jwt_verifier)

    async def _body() -> None:
        await listener.on_message(b"{}")
        await listener.on_message(b'{"session_id": "11111111-1111-1111-1111-111111111111"}')

    _run(_body())
    assert publisher.messages == []


def test_invalid_request_emits_error_without_ack(
    store: ActiveSessionStore, jwt_verifier: JwtVerifier
) -> None:
    publisher = RecordingPublisher()
    listener = _listener(store, publisher, ScriptedChat(), jwt_verifier)
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

    _run(listener.on_message(raw))
    assert len(publisher.messages) == 1
    error = publisher.messages[0]
    assert isinstance(error, ErrorOutput)
    assert error.message_id == uuid.UUID("22222222-2222-2222-2222-222222222222")
    assert "invalid request" in error.text


def test_garbage_authorization_is_error_without_ack(
    store: ActiveSessionStore, jwt_verifier: JwtVerifier
) -> None:
    publisher = RecordingPublisher()
    chat = ScriptedChat([StreamDelta(kind="message", text="ok")])
    listener = _listener(store, publisher, chat, jwt_verifier)
    _handle(listener, make_request(authorization_token="not-a-jwt"))
    assert len(publisher.messages) == 1
    error = publisher.messages[0]
    assert isinstance(error, ErrorOutput)
    assert "invalid authorization" in error.text
    assert not any(isinstance(message, Acknowledge) for message in publisher.messages)
    assert chat.calls == 0


def test_disallowed_azp_is_error_without_ack(
    store: ActiveSessionStore,
    jwt_verifier: JwtVerifier,
    jwt_key: RSAPrivateKey,
) -> None:
    publisher = RecordingPublisher()
    chat = ScriptedChat([StreamDelta(kind="message", text="ok")])
    listener = _listener(store, publisher, chat, jwt_verifier)
    token = encode_access_token(jwt_key, azp="other-client")
    _handle(listener, make_request(authorization_token=token))
    error = publisher.messages[0]
    assert isinstance(error, ErrorOutput)
    assert error.text == "caller is not allowed"
    assert not any(isinstance(message, Acknowledge) for message in publisher.messages)
    assert chat.calls == 0


def test_valid_authorization_binds_security_context(
    store: ActiveSessionStore,
    jwt_verifier: JwtVerifier,
    access_token: str,
) -> None:
    seen: list[object] = []

    class HolderChat:
        def stream(self, request: object) -> object:
            return self._stream(request)

        async def _stream(self, request: object) -> object:
            context = SecurityContextHolder.require()
            seen.append(context.subject)
            seen.append(context.attribute("session_id"))
            seen.append(context.attribute("message_id"))
            yield StreamDelta(kind="message", text="ok")

    publisher = RecordingPublisher()
    listener = _listener(store, publisher, HolderChat(), jwt_verifier)
    request = make_request(authorization_token=access_token)
    _handle(listener, request)
    assert seen == ["alice", request.session_id, request.message_id]
    assert SecurityContextHolder.get() is None
    types = [type(message).__name__ for message in publisher.messages]
    assert types == ["Acknowledge", "PartialResponse", "Finish"]


def test_invalid_authorization_does_not_stop_active_run(
    store: ActiveSessionStore,
    jwt_verifier: JwtVerifier,
    access_token: str,
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

    listener = _listener(store, publisher, SlowChat(), jwt_verifier)
    first = make_request(
        message_id=uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        authorization_token=access_token,
    )
    second = make_request(
        message_id=uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
        authorization_token="not-a-jwt",
    )

    async def _body() -> None:
        task = asyncio.create_task(listener.on_message(encode_request(first)))
        await started.wait()
        await listener.on_message(encode_request(second))
        release.set()
        await task

    _run(_body())
    errors = [message for message in publisher.messages if isinstance(message, ErrorOutput)]
    acks = [message for message in publisher.messages if isinstance(message, Acknowledge)]
    finishes = [message for message in publisher.messages if isinstance(message, Finish)]
    assert len(errors) == 1
    assert errors[0].message_id == second.message_id
    assert "invalid authorization" in errors[0].text
    assert len(acks) == 1
    assert acks[0].message_id == first.message_id
    assert len(finishes) == 1


def test_duplicate_session_errors_without_stopping_active_run(
    store: ActiveSessionStore,
    jwt_verifier: JwtVerifier,
    access_token: str,
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

    listener = _listener(store, publisher, SlowChat(), jwt_verifier)
    first = make_request(
        message_id=uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        authorization_token=access_token,
    )
    second = make_request(
        message_id=uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
        authorization_token=access_token,
    )

    async def _body() -> None:
        task = asyncio.create_task(listener.on_message(encode_request(first)))
        await started.wait()
        await listener.on_message(encode_request(second))
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
    jwt_verifier: JwtVerifier,
    access_token: str,
) -> None:
    publisher = RecordingPublisher()
    chat = ScriptedChat(
        [
            StreamDelta(kind="reasoning", text="think"),
            StreamDelta(kind="message", text="Hello"),
        ]
    )
    listener = _listener(store, publisher, chat, jwt_verifier)

    _handle(listener, make_request(authorization_token=access_token))
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


def test_openai_retries_before_partial_then_succeeds(
    store: ActiveSessionStore,
    jwt_verifier: JwtVerifier,
    access_token: str,
) -> None:
    publisher = RecordingPublisher()
    chat = ScriptedChat([StreamDelta(kind="message", text="ok")], fail_times=2)
    listener = _listener(store, publisher, chat, jwt_verifier)

    _handle(listener, make_request(authorization_token=access_token))
    assert chat.calls == 3
    assert isinstance(publisher.messages[-1], Finish)


def test_openai_gives_up_after_three_failures_before_partial(
    store: ActiveSessionStore,
    jwt_verifier: JwtVerifier,
    access_token: str,
) -> None:
    publisher = RecordingPublisher()
    chat = ScriptedChat(fail_times=5)
    listener = _listener(store, publisher, chat, jwt_verifier)

    _handle(listener, make_request(authorization_token=access_token))
    assert chat.calls == 3
    error = publisher.messages[-1]
    assert isinstance(error, ErrorOutput)
    assert error.message_id == uuid.UUID("22222222-2222-2222-2222-222222222222")
    assert not any(isinstance(message, Finish) for message in publisher.messages)


def test_no_retry_after_partial_was_emitted(
    store: ActiveSessionStore,
    jwt_verifier: JwtVerifier,
    access_token: str,
) -> None:
    publisher = RecordingPublisher()
    chat = ScriptedChat([StreamDelta(kind="message", text="Hel")], fail_after_partial=True)
    listener = _listener(store, publisher, chat, jwt_verifier)

    _handle(listener, make_request(authorization_token=access_token))
    assert chat.calls == 1
    assert isinstance(publisher.messages[1], PartialResponse)
    assert isinstance(publisher.messages[-1], ErrorOutput)
    assert not any(isinstance(message, Finish) for message in publisher.messages)


def test_empty_user_input_is_validation_error(
    store: ActiveSessionStore, jwt_verifier: JwtVerifier, access_token: str
) -> None:
    publisher = RecordingPublisher()
    listener = _listener(store, publisher, ScriptedChat(), jwt_verifier)
    _run(
        listener.on_message(
            encode_request(make_request(user_input="", authorization_token=access_token))
        )
    )
    error = publisher.messages[0]
    assert isinstance(error, ErrorOutput)
    assert "user_input" in error.text
    assert not any(isinstance(message, Acknowledge) for message in publisher.messages)


def test_ping_is_emitted_for_active_session(
    store: ActiveSessionStore,
    jwt_verifier: JwtVerifier,
    access_token: str,
) -> None:
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
    listener = _listener(
        store,
        publisher,
        OneDeltaChat(),
        jwt_verifier,
        ping_interval_seconds=0.01,
        sleep=lambda _seconds: asyncio.sleep(0),
    )
    _handle(listener, make_request(authorization_token=access_token))
    assert any(isinstance(message, Ping) for message in publisher.messages)
    assert isinstance(publisher.messages[-1], Finish)


def test_wrong_audience_token_is_rejected(
    store: ActiveSessionStore,
    jwt_verifier: JwtVerifier,
    jwt_key: RSAPrivateKey,
) -> None:
    publisher = RecordingPublisher()
    listener = _listener(store, publisher, ScriptedChat(), jwt_verifier)
    token = encode_access_token(jwt_key, aud="ads")
    _handle(listener, make_request(authorization_token=token))
    error = publisher.messages[0]
    assert isinstance(error, ErrorOutput)
    assert "invalid authorization" in error.text
    assert not any(isinstance(message, Acknowledge) for message in publisher.messages)


def test_access_denied_handler_reads_ids_from_bound_attributes(
    store: ActiveSessionStore,
    jwt_verifier: JwtVerifier,
    access_token: str,
) -> None:
    publisher = RecordingPublisher()

    class DenyService:
        allowed_callers = ALLOWED

        @require_caller("nobody")
        async def handle(self, request: object) -> None:
            raise AssertionError("must not run")

    listener = EngineListener(DenyService(), publisher, jwt_verifier, ALLOWED)  # type: ignore[arg-type]
    request = make_request(authorization_token=access_token)
    _handle(listener, request)
    error = publisher.messages[0]
    assert isinstance(error, ErrorOutput)
    assert error.session_id == request.session_id
    assert error.message_id == request.message_id
    assert error.text == "caller is not allowed"
    assert not any(isinstance(message, Acknowledge) for message in publisher.messages)
