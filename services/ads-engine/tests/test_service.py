from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import AsyncIterator, Callable
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from ads_commons.engine import (
    Acknowledge,
    AckResponse,
    AssistantMessage,
    EngineRequest,
    ErrorOutput,
    Finish,
    PartialResponse,
    Ping,
    Reasoning,
    authorization_headers,
    encode_ack_response,
    encode_request,
)
from ads_commons.security import (
    AccessDenied,
    SecurityContext,
    SecurityContextHolder,
    TokenExchangeError,
)
from ads_engine.chat import StreamDelta
from ads_engine.listener import EngineListener
from ads_engine.service import EngineService
from ads_engine.store import ActiveSessionStore
from engine_fakes import (
    ENGINE_CLIENT_ID,
    EXCHANGED_TOKEN,
    FakeTokenExchange,
    RecordingPublisher,
    ScriptedChat,
    encode_access_token,
    make_request,
)

pytestmark = pytest.mark.usefixtures("store")


class DenyService(EngineService):
    async def handle(self, request: EngineRequest) -> None:
        raise AccessDenied("handler denied")


class SlowChat:
    def __init__(self, started: asyncio.Event, release: asyncio.Event) -> None:
        self.started = started
        self.release = release

    async def stream(self, request: EngineRequest) -> AsyncIterator[StreamDelta]:
        self.started.set()
        await self.release.wait()
        yield StreamDelta(kind="message", text="done")


class OneDeltaChat:
    def __init__(self, pinged: asyncio.Event) -> None:
        self.pinged = pinged

    async def stream(self, request: EngineRequest) -> AsyncIterator[StreamDelta]:
        await self.pinged.wait()
        yield StreamDelta(kind="message", text="ok")


def _run(coro: Any) -> None:
    asyncio.run(coro)


def _ack_bytes(request: EngineRequest) -> bytes:
    return encode_ack_response(
        AckResponse(session_id=request.session_id, message_id=request.message_id)
    )


async def _accept(
    listener: EngineListener,
    publisher: RecordingPublisher,
    request: EngineRequest,
    ack_token: str,
) -> None:
    task = asyncio.create_task(listener.on_message(encode_request(request)))
    await publisher.acknowledged.wait()
    await listener.on_message(
        _ack_bytes(request),
        headers=authorization_headers(ack_token),
    )
    await task


def _handle(listener: EngineListener, request: EngineRequest) -> None:
    _run(listener.on_message(encode_request(request)))


def _handle_accepted(
    listener: EngineListener,
    publisher: RecordingPublisher,
    request: EngineRequest,
    ack_token: str,
) -> None:
    _run(_accept(listener, publisher, request, ack_token))


def _service(
    store: ActiveSessionStore,
    publisher: RecordingPublisher,
    chat: Any,
    ping_interval_seconds: float = 10,
    ack_timeout_seconds: float = 10,
    tokens: FakeTokenExchange | None = None,
    sleep: Callable[[float], Any] = asyncio.sleep,
) -> EngineService:
    return EngineService(
        store=store,
        publisher=publisher,
        chat=chat,
        ping_interval_seconds=ping_interval_seconds,
        allowed_callers=(ENGINE_CLIENT_ID,),
        tokens=tokens or FakeTokenExchange(),
        ack_timeout_seconds=ack_timeout_seconds,
        sleep=sleep,
    )


def _listener(
    store: ActiveSessionStore,
    publisher: RecordingPublisher,
    jwt_verifier: Any,
    chat: Any | None = None,
    service: EngineService | None = None,
    ping_interval_seconds: float = 10,
    ack_timeout_seconds: float = 10,
    tokens: FakeTokenExchange | None = None,
    sleep: Callable[[float], Any] = asyncio.sleep,
) -> EngineListener:
    resolved = service or _service(
        store,
        publisher,
        chat or ScriptedChat(),
        ping_interval_seconds=ping_interval_seconds,
        ack_timeout_seconds=ack_timeout_seconds,
        tokens=tokens,
        sleep=sleep,
    )
    return EngineListener(
        service=resolved,
        publisher=publisher,
        authenticator=jwt_verifier,
        allowed_callers=(ENGINE_CLIENT_ID,),
    )


def test_missing_ids_are_dropped(store: ActiveSessionStore, jwt_verifier: Any) -> None:
    publisher = RecordingPublisher()
    listener = _listener(store, publisher, jwt_verifier)
    _run(listener.on_message(b'{"user_input": "hi"}'))
    assert publisher.messages == []


def test_invalid_request_emits_error_without_ack(
    store: ActiveSessionStore,
    jwt_verifier: Any,
) -> None:
    publisher = RecordingPublisher()
    listener = _listener(store, publisher, jwt_verifier)
    payload = {
        "type": "request",
        "session_id": "11111111-1111-1111-1111-111111111111",
        "message_id": "22222222-2222-2222-2222-222222222222",
        "history": [],
        "user_input": "hi",
        "instructions": "",
        "model": {"type": "unknown"},
        "authorization": {"token": "x"},
    }
    _run(listener.on_message(json.dumps(payload).encode("utf-8")))
    error = publisher.messages[0]
    assert isinstance(error, ErrorOutput)
    assert error.text.startswith("invalid request:")
    assert not any(isinstance(item, Acknowledge) for item in publisher.messages)


def test_garbage_authorization_is_error_without_ack(
    store: ActiveSessionStore,
    jwt_verifier: Any,
) -> None:
    publisher = RecordingPublisher()
    listener = _listener(store, publisher, jwt_verifier)
    _handle(listener, make_request(authorization_token="not-a-jwt"))
    error = publisher.messages[0]
    assert isinstance(error, ErrorOutput)
    assert error.text.startswith("invalid authorization:")
    assert not any(isinstance(item, Acknowledge) for item in publisher.messages)


def test_disallowed_azp_is_error_without_ack(
    store: ActiveSessionStore,
    jwt_verifier: Any,
    jwt_key: RSAPrivateKey,
) -> None:
    publisher = RecordingPublisher()
    listener = _listener(store, publisher, jwt_verifier)
    token = encode_access_token(jwt_key, azp="ads-ui")
    _handle(listener, make_request(authorization_token=token))
    error = publisher.messages[0]
    assert isinstance(error, ErrorOutput)
    assert error.text == "caller is not allowed"
    assert not any(isinstance(item, Acknowledge) for item in publisher.messages)


def test_empty_user_input_is_validation_error(
    store: ActiveSessionStore,
    jwt_verifier: Any,
    access_token: str,
) -> None:
    publisher = RecordingPublisher()
    listener = _listener(store, publisher, jwt_verifier)
    _handle(listener, make_request(user_input="", authorization_token=access_token))
    error = publisher.messages[0]
    assert isinstance(error, ErrorOutput)
    assert error.text == "user_input is required"
    assert not any(isinstance(item, Acknowledge) for item in publisher.messages)


def test_wrong_audience_token_is_rejected(
    store: ActiveSessionStore,
    jwt_verifier: Any,
    jwt_key: RSAPrivateKey,
) -> None:
    publisher = RecordingPublisher()
    listener = _listener(store, publisher, jwt_verifier)
    token = encode_access_token(jwt_key, aud="ads")
    _handle(listener, make_request(authorization_token=token))
    error = publisher.messages[0]
    assert isinstance(error, ErrorOutput)
    assert error.text.startswith("invalid authorization:")


def test_access_denied_handler_reads_ids_from_bound_attributes(
    store: ActiveSessionStore,
    jwt_verifier: Any,
    access_token: str,
) -> None:
    publisher = RecordingPublisher()
    service = DenyService(
        store=store,
        publisher=publisher,
        chat=ScriptedChat(),
        ping_interval_seconds=10,
        allowed_callers=(ENGINE_CLIENT_ID,),
        tokens=FakeTokenExchange(),
    )
    listener = _listener(store, publisher, jwt_verifier, service=service)
    request = make_request(authorization_token=access_token)
    _handle(listener, request)
    error = publisher.messages[0]
    assert isinstance(error, ErrorOutput)
    assert error.session_id == request.session_id
    assert error.message_id == request.message_id
    assert error.text == "handler denied"


def test_valid_authorization_binds_security_context(
    store: ActiveSessionStore,
    jwt_verifier: Any,
    access_token: str,
) -> None:
    publisher = RecordingPublisher()
    captured: dict[str, object] = {}

    class CaptureChat(ScriptedChat):
        async def _stream(self, request: EngineRequest) -> AsyncIterator[StreamDelta]:
            captured["context"] = SecurityContextHolder.get()
            async for delta in super()._stream(request):
                yield delta

    chat = CaptureChat([StreamDelta(kind="message", text="ok")])
    tokens = FakeTokenExchange()
    listener = _listener(store, publisher, jwt_verifier, chat=chat, tokens=tokens)
    request = make_request(authorization_token=access_token)
    _handle_accepted(listener, publisher, request, access_token)
    context = captured["context"]
    assert isinstance(context, SecurityContext)
    assert context.subject == "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    assert context.name == "Alice"
    assert context.roles == frozenset({"user"})
    assert context.authorized_party == "ads-engine"
    assert context.access_token == EXCHANGED_TOKEN
    assert context.attribute("session_id") == request.session_id
    assert context.attribute("message_id") == request.message_id
    assert tokens.audiences == ["ads"]
    assert publisher.headers[0] == authorization_headers(EXCHANGED_TOKEN)


def test_invalid_authorization_does_not_stop_active_run(
    store: ActiveSessionStore,
    jwt_verifier: Any,
    access_token: str,
) -> None:
    publisher = RecordingPublisher()
    started = asyncio.Event()
    release = asyncio.Event()
    listener = _listener(store, publisher, jwt_verifier, chat=SlowChat(started, release))
    first = make_request(authorization_token=access_token)
    second = make_request(
        message_id=uuid.UUID("33333333-3333-3333-3333-333333333333"),
        authorization_token="not-a-jwt",
    )

    async def _body() -> None:
        task = asyncio.create_task(listener.on_message(encode_request(first)))
        await publisher.acknowledged.wait()
        await listener.on_message(_ack_bytes(first), headers=authorization_headers(access_token))
        await started.wait()
        await listener.on_message(encode_request(second))
        release.set()
        await task

    _run(_body())
    assert any(isinstance(item, Finish) for item in publisher.messages)
    errors = [item for item in publisher.messages if isinstance(item, ErrorOutput)]
    assert len(errors) == 1
    assert errors[0].text.startswith("invalid authorization:")


def test_duplicate_session_errors_without_stopping_active_run(
    store: ActiveSessionStore,
    jwt_verifier: Any,
    access_token: str,
) -> None:
    publisher = RecordingPublisher()
    started = asyncio.Event()
    release = asyncio.Event()
    listener = _listener(store, publisher, jwt_verifier, chat=SlowChat(started, release))
    first = make_request(authorization_token=access_token)
    second = make_request(
        message_id=uuid.UUID("33333333-3333-3333-3333-333333333333"),
        authorization_token=access_token,
    )

    async def _body() -> None:
        task = asyncio.create_task(listener.on_message(encode_request(first)))
        await publisher.acknowledged.wait()
        await listener.on_message(_ack_bytes(first), headers=authorization_headers(access_token))
        await started.wait()
        await listener.on_message(encode_request(second))
        release.set()
        await task

    _run(_body())
    errors = [item for item in publisher.messages if isinstance(item, ErrorOutput)]
    assert len(errors) == 1
    assert errors[0].text == "session already active"
    assert errors[0].message_id == second.message_id
    assert any(isinstance(item, Finish) for item in publisher.messages)


def test_successful_chat_emits_ack_delta_partials_and_finish(
    store: ActiveSessionStore,
    jwt_verifier: Any,
    access_token: str,
) -> None:
    publisher = RecordingPublisher()
    chat = ScriptedChat(
        [
            StreamDelta(kind="reasoning", text="think"),
            StreamDelta(kind="message", text="answer"),
        ]
    )
    listener = _listener(store, publisher, jwt_verifier, chat=chat)
    request = make_request(authorization_token=access_token)
    _handle_accepted(listener, publisher, request, access_token)
    assert publisher.messages[0] == Acknowledge(
        session_id=request.session_id,
        message_id=request.message_id,
    )
    assert publisher.messages[1] == PartialResponse(
        session_id=request.session_id,
        order=0,
        reasoning=Reasoning(text="think"),
    )
    assert publisher.messages[2] == PartialResponse(
        session_id=request.session_id,
        order=1,
        message=AssistantMessage(text="answer"),
    )
    assert publisher.messages[3] == Finish(session_id=request.session_id, last_order=1)
    assert chat.calls == 1
    assert chat.requests[0].authorization.token == access_token


def test_openai_retries_before_partial_then_succeeds(
    store: ActiveSessionStore,
    jwt_verifier: Any,
    access_token: str,
) -> None:
    publisher = RecordingPublisher()
    chat = ScriptedChat([StreamDelta(kind="message", text="ok")], fail_times=2)
    listener = _listener(store, publisher, jwt_verifier, chat=chat)
    request = make_request(authorization_token=access_token)
    _handle_accepted(listener, publisher, request, access_token)
    assert chat.calls == 3
    finish = next(item for item in publisher.messages if isinstance(item, Finish))
    assert finish == Finish(session_id=request.session_id, last_order=0)


def test_openai_gives_up_after_three_failures_before_partial(
    store: ActiveSessionStore,
    jwt_verifier: Any,
    access_token: str,
) -> None:
    publisher = RecordingPublisher()
    chat = ScriptedChat(fail_times=3)
    listener = _listener(store, publisher, jwt_verifier, chat=chat)
    request = make_request(authorization_token=access_token)
    _handle_accepted(listener, publisher, request, access_token)
    assert chat.calls == 3
    error = publisher.messages[-1]
    assert isinstance(error, ErrorOutput)
    assert error.text == "openai unavailable"
    assert not any(isinstance(item, Finish) for item in publisher.messages)


def test_empty_stream_is_error_not_finish(
    store: ActiveSessionStore,
    jwt_verifier: Any,
    access_token: str,
) -> None:
    publisher = RecordingPublisher()
    chat = ScriptedChat([])
    listener = _listener(store, publisher, jwt_verifier, chat=chat)
    request = make_request(authorization_token=access_token)
    _handle_accepted(listener, publisher, request, access_token)
    assert chat.calls == 1
    error = publisher.messages[-1]
    assert isinstance(error, ErrorOutput)
    assert error.text == "no partial-response"
    assert error.message_id == request.message_id
    assert not any(isinstance(item, Finish) for item in publisher.messages)
    assert not any(isinstance(item, PartialResponse) for item in publisher.messages)


def test_no_retry_after_partial_was_emitted(
    store: ActiveSessionStore,
    jwt_verifier: Any,
    access_token: str,
) -> None:
    publisher = RecordingPublisher()
    chat = ScriptedChat(
        [StreamDelta(kind="message", text="partial")],
        fail_after_partial=True,
    )
    listener = _listener(store, publisher, jwt_verifier, chat=chat)
    request = make_request(authorization_token=access_token)
    _handle_accepted(listener, publisher, request, access_token)
    assert chat.calls == 1
    error = publisher.messages[-1]
    assert isinstance(error, ErrorOutput)
    assert error.text == "stream dropped"


def test_ping_is_emitted_for_active_session(
    store: ActiveSessionStore,
    jwt_verifier: Any,
    access_token: str,
) -> None:
    publisher = RecordingPublisher()
    pinged = asyncio.Event()

    class Publisher(RecordingPublisher):
        async def publish(
            self,
            session_id: uuid.UUID,
            message: object,
            headers: list[tuple[str, bytes]] | None = None,
        ) -> None:
            await super().publish(session_id, message, headers)
            if isinstance(message, Ping):
                pinged.set()

    publisher = Publisher()
    listener = _listener(
        store,
        publisher,
        jwt_verifier,
        chat=OneDeltaChat(pinged),
        ping_interval_seconds=0.01,
        sleep=lambda _: asyncio.sleep(0),
    )
    request = make_request(authorization_token=access_token)
    _handle_accepted(listener, publisher, request, access_token)
    assert any(isinstance(item, Ping) for item in publisher.messages)
    assert any(isinstance(item, Finish) for item in publisher.messages)


def test_ack_response_timeout_errors_without_starting_chat(
    store: ActiveSessionStore,
    jwt_verifier: Any,
    access_token: str,
) -> None:
    publisher = RecordingPublisher()
    chat = ScriptedChat([StreamDelta(kind="message", text="ok")])
    listener = _listener(
        store,
        publisher,
        jwt_verifier,
        chat=chat,
        ack_timeout_seconds=0.05,
    )
    request = make_request(authorization_token=access_token)
    _handle(listener, request)
    assert chat.calls == 0
    assert publisher.messages[0] == Acknowledge(
        session_id=request.session_id,
        message_id=request.message_id,
    )
    error = publisher.messages[-1]
    assert isinstance(error, ErrorOutput)
    assert error.text == "ack-response timed out"
    assert error.message_id == request.message_id
    assert not any(isinstance(item, Finish) for item in publisher.messages)
    assert not any(isinstance(item, PartialResponse) for item in publisher.messages)
    _run(store.claim(request.session_id, request.message_id))


def test_unmatched_ack_response_is_ignored(
    store: ActiveSessionStore,
    jwt_verifier: Any,
    access_token: str,
) -> None:
    publisher = RecordingPublisher()
    listener = _listener(store, publisher, jwt_verifier)
    ack = AckResponse(
        session_id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
        message_id=uuid.UUID("22222222-2222-2222-2222-222222222222"),
    )
    _run(listener.on_message(encode_ack_response(ack), headers=authorization_headers(access_token)))
    assert publisher.messages == []


def test_wrong_message_id_ack_response_is_ignored_until_timeout(
    store: ActiveSessionStore,
    jwt_verifier: Any,
    access_token: str,
) -> None:
    publisher = RecordingPublisher()
    chat = ScriptedChat([StreamDelta(kind="message", text="ok")])
    listener = _listener(
        store,
        publisher,
        jwt_verifier,
        chat=chat,
        ack_timeout_seconds=0.05,
    )
    request = make_request(authorization_token=access_token)
    wrong = AckResponse(
        session_id=request.session_id,
        message_id=uuid.UUID("33333333-3333-3333-3333-333333333333"),
    )

    async def _body() -> None:
        task = asyncio.create_task(listener.on_message(encode_request(request)))
        await publisher.acknowledged.wait()
        await listener.on_message(
            encode_ack_response(wrong),
            headers=authorization_headers(access_token),
        )
        await task

    _run(_body())
    assert chat.calls == 0
    error = publisher.messages[-1]
    assert isinstance(error, ErrorOutput)
    assert error.text == "ack-response timed out"


def test_duplicate_ack_response_after_start_is_ignored(
    store: ActiveSessionStore,
    jwt_verifier: Any,
    access_token: str,
) -> None:
    publisher = RecordingPublisher()
    chat = ScriptedChat([StreamDelta(kind="message", text="ok")])
    listener = _listener(store, publisher, jwt_verifier, chat=chat)
    request = make_request(authorization_token=access_token)

    async def _body() -> None:
        task = asyncio.create_task(listener.on_message(encode_request(request)))
        await publisher.acknowledged.wait()
        await listener.on_message(_ack_bytes(request), headers=authorization_headers(access_token))
        await listener.on_message(_ack_bytes(request), headers=authorization_headers(access_token))
        await task

    _run(_body())
    assert chat.calls == 1
    finishes = [item for item in publisher.messages if isinstance(item, Finish)]
    assert finishes == [Finish(session_id=request.session_id, last_order=0)]
    assert not any(isinstance(item, ErrorOutput) for item in publisher.messages)


def test_token_exchange_failure_errors_without_acknowledge(
    store: ActiveSessionStore,
    jwt_verifier: Any,
    access_token: str,
) -> None:
    publisher = RecordingPublisher()
    chat = ScriptedChat([StreamDelta(kind="message", text="ok")])
    tokens = FakeTokenExchange(error=TokenExchangeError("ste failed"))
    listener = _listener(store, publisher, jwt_verifier, chat=chat, tokens=tokens)
    request = make_request(authorization_token=access_token)
    _handle(listener, request)
    assert tokens.audiences == ["ads"]
    assert chat.calls == 0
    assert not any(isinstance(item, Acknowledge) for item in publisher.messages)
    error = publisher.messages[-1]
    assert isinstance(error, ErrorOutput)
    assert error.text == "ste failed"
    assert error.message_id == request.message_id
    _run(store.claim(request.session_id, request.message_id))


def test_ack_response_without_authorization_header_times_out(
    store: ActiveSessionStore,
    jwt_verifier: Any,
    access_token: str,
) -> None:
    publisher = RecordingPublisher()
    chat = ScriptedChat([StreamDelta(kind="message", text="ok")])
    listener = _listener(
        store,
        publisher,
        jwt_verifier,
        chat=chat,
        ack_timeout_seconds=0.05,
    )
    request = make_request(authorization_token=access_token)

    async def _body() -> None:
        task = asyncio.create_task(listener.on_message(encode_request(request)))
        await publisher.acknowledged.wait()
        await listener.on_message(_ack_bytes(request))
        await task

    _run(_body())
    assert chat.calls == 0
    error = publisher.messages[-1]
    assert isinstance(error, ErrorOutput)
    assert error.text == "ack-response timed out"


def test_ack_response_with_invalid_authorization_header_times_out(
    store: ActiveSessionStore,
    jwt_verifier: Any,
    access_token: str,
) -> None:
    publisher = RecordingPublisher()
    chat = ScriptedChat([StreamDelta(kind="message", text="ok")])
    listener = _listener(
        store,
        publisher,
        jwt_verifier,
        chat=chat,
        ack_timeout_seconds=0.05,
    )
    request = make_request(authorization_token=access_token)

    async def _body() -> None:
        task = asyncio.create_task(listener.on_message(encode_request(request)))
        await publisher.acknowledged.wait()
        await listener.on_message(
            _ack_bytes(request),
            headers=authorization_headers("not-a-jwt"),
        )
        await task

    _run(_body())
    assert chat.calls == 0
    error = publisher.messages[-1]
    assert isinstance(error, ErrorOutput)
    assert error.text == "ack-response timed out"
