from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest

from ads_commons.sandbox import (
    SandboxAbort,
    SandboxAcknowledge,
    SandboxAckReply,
    SandboxAckReset,
    SandboxIpcError,
    SandboxPing,
    SandboxReady,
    SandboxResult,
    SandboxShutdown,
    SandboxShutdownAck,
    decode_outbound,
    decode_ping,
    decode_ready,
    encode_inbound,
)
from ads_commons.security import InvalidAccessToken, SecurityContextHolder
from ads_commons_beans import TokenExchangeSettings
from ads_sandbox_ipc.auth import ClientCredentials
from ads_sandbox_ipc.controller import PING_REPLY_TOPIC, PING_REQUEST_TOPIC, READY_TOPIC
from ads_sandbox_ipc.kafka import KafkaPublisher
from ipc_support import SUBJECT, eventually


@pytest.mark.anyio
@pytest.mark.parametrize(
    "changes",
    [
        {"aud": "wrong"},
        {"azp": "ads-sandbox-mcp"},
        {"azp": None},
        {"iss": "https://wrong.test"},
        {"sub": "not-a-uuid"},
        {"exp": 1},
        {"iat": 9999999999},
    ],
)
@pytest.mark.parametrize("kind", ["request", "ack-reply", "ack-reset", "abort", "shutdown", "ping"])
async def test_every_inbound_auth_path_fails_closed(ipc, changes, kind, ipc_logs) -> None:
    async with ipc.running():
        request = ipc.request()
        if kind != "request":
            await ipc.send(request)
        message, topic = {
            "request": (request, ipc.settings.request_topic),
            "ack-reply": (SandboxAckReply(request.execution_id), ipc.settings.request_topic),
            "ack-reset": (SandboxAckReset(request.execution_id), ipc.settings.request_topic),
            "abort": (SandboxAbort(request.execution_id), ipc.settings.request_topic),
            "shutdown": (SandboxShutdown(ipc.settings.sandbox_id), READY_TOPIC),
            "ping": (SandboxPing(uuid4(), ipc.settings.sandbox_id), PING_REQUEST_TOPIC),
        }[kind]
        count = len(ipc.publisher.messages)
        token = ipc.keys.token(**changes)
        await ipc.send(message, token, topic)
        assert len(ipc.publisher.messages) == count
        assert len(ipc.kube.calls) == 1
        assert not ipc.service.stopping
        if kind != "request":
            assert ipc.service.current is not None
        assert SecurityContextHolder.get() is None
        assert any(
            entry["event"] == "ipc_invalid_authorization" and entry["log_level"] == "warning"
            for entry in ipc_logs
        )
        assert token not in repr(ipc_logs)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "headers",
    [
        None,
        [],
        [("authorization", None)],
        [("authorization", b"")],
        [("authorization", b"garbage")],
    ],
)
async def test_missing_and_malformed_jwt_warn_every_time(ipc, headers, ipc_logs) -> None:
    async with ipc.running():
        for _ in range(2):
            await ipc.controller.on_message(
                ipc.settings.request_topic, encode_inbound(ipc.request()), headers
            )
        assert len(ipc.publisher.messages) == 1
        assert len(ipc.kube.calls) == 1
        assert len(ipc_logs) == 2
        assert all(
            entry["event"].startswith("ipc_") and entry["log_level"] == "warning"
            for entry in ipc_logs
        )


@pytest.mark.anyio
async def test_invalid_abort_does_not_abort_active_exec_and_subject_cannot_switch(ipc) -> None:
    async with ipc.running():
        request = ipc.request()
        await ipc.send(request)
        other = ipc.keys.token(sub=str(uuid4()))
        await ipc.send(SandboxAckReply(request.execution_id), other)
        assert len(ipc.kube.calls) == 1
        await ipc.send(SandboxAckReply(request.execution_id))
        await eventually(lambda: bool(ipc.store.entries()))
        await ipc.send(SandboxAbort(request.execution_id), "garbage")
        await ipc.send(SandboxAbort(request.execution_id), other)
        assert not ipc.kube.killed
        ipc.finish()
        await eventually(lambda: ipc.service.last_result is not None)
        count = len(ipc.publisher.messages)
        await ipc.send(request, other)
        assert len(ipc.publisher.messages) == count
        assert not ipc.service.last_result.is_error


@pytest.mark.anyio
async def test_unmatched_sandbox_and_unexpected_topics_are_ignored(ipc) -> None:
    async with ipc.running():
        await ipc.send(SandboxShutdown(uuid4()), topic=READY_TOPIC)
        await ipc.send(SandboxPing(uuid4(), uuid4()), topic=PING_REQUEST_TOPIC)
        await ipc.send(SandboxReady(ipc.settings.sandbox_id), topic=READY_TOPIC)
        await ipc.controller.on_message("sandbox.req.other", encode_inbound(ipc.request()))
        await ipc.controller.on_message(ipc.settings.request_topic, b"{broken")
        assert len(ipc.publisher.messages) == 1
        assert not ipc.service.stopping


@pytest.mark.anyio
async def test_publisher_mints_at_produce_time_for_each_message_and_routes_commons_types(
    ipc,
) -> None:
    producer = SimpleNamespace(send_and_wait=AsyncMock())
    tokens = Mock()
    client_credentials = Mock()
    tokens.mint.side_effect = lambda *a, **k: SimpleNamespace(access_token=str(uuid4()))
    client_credentials.mint.side_effect = lambda: str(uuid4())
    publisher = KafkaPublisher(ipc.settings, producer, tokens, client_credentials)
    execution_id = uuid4()
    messages = [
        SandboxReady(ipc.settings.sandbox_id),
        SandboxIpcError(ipc.settings.sandbox_id, "failed"),
        SandboxAcknowledge(execution_id),
        SandboxResult(execution_id, 0, "", "", False, 0, False),
        SandboxShutdownAck(ipc.settings.sandbox_id),
        SandboxPing(uuid4(), ipc.settings.sandbox_id),
    ]
    subjects = [None, None, "request-jwt", "ack-reply-jwt", "shutdown-jwt", "ping-req-jwt"]
    headers = []
    for message, subject in zip(messages, subjects, strict=True):
        await publisher.publish(message, subject)
        args, kwargs = producer.send_and_wait.call_args
        topic = args[0]
        decode = (
            decode_outbound
            if topic == ipc.settings.reply_topic
            else decode_ping
            if topic == PING_REPLY_TOPIC
            else decode_ready
        )
        assert decode(kwargs["value"]) == message
        assert kwargs["key"] == str(ipc.settings.sandbox_id).encode()
        assert kwargs["headers"][0][0] == "authorization"
        assert kwargs["headers"][0][1] != (subject or "").encode()
        headers.append(kwargs["headers"][0][1])
    assert len(set(headers)) == 6
    assert client_credentials.mint.call_count == 2
    assert tokens.mint.call_count == 4
    assert [call.kwargs["subject_token"] for call in tokens.mint.call_args_list] == subjects[2:]
    assert all(call.args == ("ads-sandbox-manager",) for call in tokens.mint.call_args_list)
    assert SecurityContextHolder.get() is None
    with pytest.raises(ValueError, match="subject token"):
        await publisher.publish(messages[2])
    tokens.mint.side_effect = RuntimeError("outage")
    before = producer.send_and_wait.call_count
    with pytest.raises(RuntimeError):
        await publisher.publish(messages[3], "ack-reply-jwt")
    assert producer.send_and_wait.call_count == before


def test_client_credentials_uses_normal_uuid_sub_verifier_and_no_refresh(ipc, monkeypatch) -> None:
    settings = TokenExchangeSettings(
        "https://identity.test/token", "ads-sandbox-ipc", "local-test-secret", None
    )
    client = ClientCredentials(settings, ipc.keys.verifier)
    response = Mock()
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    token = ipc.keys.token(aud="ads-sandbox-manager", azp="ads-sandbox-ipc")
    response.read.return_value = ('{"access_token":"' + token + '"}').encode()
    urlopen = Mock(return_value=response)
    monkeypatch.setattr("ads_sandbox_ipc.auth.urlopen", urlopen)
    assert client.mint() == token
    request = urlopen.call_args.args[0]
    assert b"grant_type=client_credentials" in request.data
    assert b"subject_token" not in request.data and b"refresh_token" not in request.data
    assert ipc.keys.verifier.authenticate(token, audience="ads-sandbox-manager").subject == SUBJECT
    bad = ipc.keys.token(aud="ads-sandbox-manager", azp="ads-sandbox-ipc", sub="service-name")
    response.read.return_value = ('{"access_token":"' + bad + '"}').encode()
    with pytest.raises(InvalidAccessToken):
        client.mint()
    response.read.return_value = b"{}"
    with pytest.raises(InvalidAccessToken):
        client.mint()
