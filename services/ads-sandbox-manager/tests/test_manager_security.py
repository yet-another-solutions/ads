import time
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import jwt
import msgspec
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from ads_commons.sandbox import (
    SandboxAbort,
    SandboxAcknowledge,
    SandboxAckReply,
    SandboxAckReset,
    SandboxPing,
    SandboxReady,
    SandboxRequest,
    SandboxResult,
    SandboxShutdownAck,
    encode_inbound,
    encode_outbound,
    encode_ping,
    encode_ready,
)
from ads_commons.security import InvalidAccessToken, SecurityContextHolder
from ads_commons_beans import JwtVerifier, JwtVerifierSettings, TokenExchangeSettings
from ads_sandbox_manager.auth import IPC, MANAGER, MCP, ClientCredentials
from ads_sandbox_manager.barrier import TOPIC, BarrierAck, BarrierRequest
from ads_sandbox_manager.controller import KafkaController
from ads_sandbox_manager.lifecycle import PING_REPLY, TOPICS, Signal
from ads_sandbox_manager.service import READY_TOPIC, REQUEST_TOPIC


class Keys:
    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.subject = str(uuid4())
        self.verifier = JwtVerifier(
            JwtVerifierSettings(
                "https://identity.test", MANAGER, MANAGER, "https://identity.test/jwks", None
            ),
            self,
        )

    def get_signing_key_from_jwt(self, token):
        return SimpleNamespace(key=self.key.public_key())

    def token(self, **changes):
        claims = {
            "sub": self.subject,
            "iss": "https://identity.test",
            "aud": MANAGER,
            "azp": MCP,
            "iat": int(time.time()),
            "exp": int(time.time()) + 600,
            "jti": str(uuid4()),
        }
        claims.update(changes)
        return jwt.encode(claims, self.key, algorithm="RS256")


@pytest.fixture
def keys():
    return Keys()


def wire(kind):
    execution, session, message, sandbox, replica = (uuid4() for _ in range(5))
    controls = {
        "request": SandboxRequest(execution, session, message, "shell", "secret-command"),
        "ack-reply": SandboxAckReply(execution, session, message),
        "ack-reset": SandboxAckReset(execution, session, message),
        "abort": SandboxAbort(execution, session, message),
    }
    if kind in controls:
        return REQUEST_TOPIC, encode_inbound(controls[kind]), str(session).encode(), MCP
    if kind == "ping":
        return PING_REPLY, encode_ping(SandboxPing(uuid4(), sandbox)), str(sandbox).encode(), IPC
    if kind in ("ready", "shutdown-ack"):
        value = (
            SandboxReady(sandbox)
            if kind == "ready"
            else SandboxShutdownAck(sandbox, datetime.now(UTC))
        )
        return READY_TOPIC, encode_ready(value), str(sandbox).encode(), IPC
    if kind.startswith("barrier"):
        value = (
            BarrierRequest(uuid4(), sandbox, replica, (replica,))
            if kind == "barrier-request"
            else BarrierAck(uuid4(), sandbox, replica, replica)
        )
        return TOPIC, msgspec.json.encode(value), str(sandbox).encode(), MANAGER
    value = (
        SandboxAcknowledge(execution, session, message)
        if kind == "acknowledge"
        else SandboxResult(execution, 0, "secret-output", "", False, 1, False)
    )
    return f"sandbox.res.{sandbox}", encode_outbound(value), str(sandbox).encode(), IPC


KINDS = [
    "ping",
    "request",
    "ack-reply",
    "ack-reset",
    "abort",
    "acknowledge",
    "result",
    "ready",
    "shutdown-ack",
    "barrier-request",
    "barrier-ack",
]


@pytest.mark.anyio
@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize(
    "changes",
    [
        {"aud": "wrong"},
        {"azp": "wrong"},
        {"azp": None},
        {"iss": "https://wrong.test"},
        {"sub": "not-a-uuid"},
        {"exp": 1},
        {"iat": 9999999999},
    ],
)
async def test_all_transit_auth_paths_fail_closed(manager_settings, keys, kind, changes, caplog):
    service, barrier, lifecycle = AsyncMock(), AsyncMock(), AsyncMock()
    controller = KafkaController(manager_settings, keys.verifier, service, barrier, lifecycle)
    topic, raw, key, caller = wire(kind)
    claims = {"azp": caller, **changes}
    token = keys.token(**claims)
    await controller.on_message(topic, raw, key, [("authorization", token.encode())])
    assert not service.mock_calls and not barrier.mock_calls and not lifecycle.mock_calls
    assert SecurityContextHolder.get() is None
    assert "rejected" in caplog.text
    assert all(secret not in caplog.text for secret in (token, "secret-command", "secret-output"))


@pytest.mark.anyio
@pytest.mark.parametrize("kind", KINDS)
async def test_valid_authenticated_delivery_without_holder(manager_settings, keys, kind):
    service, barrier, lifecycle = AsyncMock(), AsyncMock(), AsyncMock()
    controller = KafkaController(manager_settings, keys.verifier, service, barrier, lifecycle)
    topic, raw, key, caller = wire(kind)
    await controller.on_message(
        topic, raw, key, [("authorization", keys.token(azp=caller).encode())]
    )
    assert service.mock_calls or barrier.mock_calls or lifecycle.mock_calls
    assert SecurityContextHolder.get() is None


@pytest.mark.anyio
@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("bad", ["missing-auth", "invalid-auth", "key", "payload"])
async def test_missing_auth_and_malformed_wire_have_no_effect(manager_settings, keys, kind, bad):
    service, barrier, lifecycle = AsyncMock(), AsyncMock(), AsyncMock()
    controller = KafkaController(manager_settings, keys.verifier, service, barrier, lifecycle)
    topic, raw, key, caller = wire(kind)
    headers = [("authorization", keys.token(azp=caller).encode())]
    if bad == "missing-auth":
        headers = None
    elif bad == "invalid-auth":
        headers = [("authorization", b"garbage")]
    elif bad == "key":
        key = str(uuid4()).encode()
    else:
        raw = b"{broken"
    await controller.on_message(topic, raw, key, headers)
    assert not service.mock_calls and not barrier.mock_calls and not lifecycle.mock_calls


def test_manager_client_credentials_verifies_uuid_subject_and_caller(keys, monkeypatch):
    settings = TokenExchangeSettings("https://identity.test/token", MANAGER, "fixture", None)
    client = ClientCredentials(settings, keys.verifier)
    response = Mock()
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    token = keys.token(azp=MANAGER)
    response.read.return_value = msgspec.json.encode({"access_token": token})
    urlopen = Mock(return_value=response)
    monkeypatch.setattr("ads_sandbox_manager.auth.urlopen", urlopen)
    assert client.mint() == token
    body = urlopen.call_args.args[0].data
    assert b"grant_type=client_credentials" in body
    assert b"subject_token" not in body and b"refresh_token" not in body
    for invalid in (
        {},
        {"access_token": keys.token(azp=MANAGER, sub="client-name")},
        {"access_token": keys.token(azp=MANAGER, aud="wrong")},
    ):
        response.read.return_value = msgspec.json.encode(invalid)
        with pytest.raises(InvalidAccessToken):
            client.mint()


@pytest.mark.anyio
@pytest.mark.parametrize("topic", TOPICS)
@pytest.mark.parametrize(
    "changes",
    [
        {"aud": "wrong"},
        {"azp": MCP},
        {"azp": IPC},
        {"azp": None},
        {"sub": "client-name"},
        {"exp": 1},
        {"iss": "https://wrong.test"},
        {"iat": 9999999999},
    ],
)
async def test_lifecycle_manager_only_verified_auth(manager_settings, keys, topic, changes):
    lifecycle = AsyncMock()
    controller = KafkaController(
        manager_settings, keys.verifier, AsyncMock(), AsyncMock(), lifecycle
    )
    message = Signal(uuid4(), uuid4())
    await controller.admit_lifecycle(
        topic,
        msgspec.json.encode(message),
        str(message.session_id).encode(),
        [("authorization", keys.token(**{"azp": MANAGER, **changes}).encode())],
    )
    assert not lifecycle.mock_calls
    assert SecurityContextHolder.get() is None


@pytest.mark.anyio
@pytest.mark.parametrize("topic", TOPICS)
async def test_lifecycle_database_error_escapes_for_durable_retry(manager_settings, keys, topic):
    lifecycle = AsyncMock()
    controller = KafkaController(
        manager_settings, keys.verifier, AsyncMock(), AsyncMock(), lifecycle
    )
    message = Signal(uuid4(), uuid4())
    args = (
        topic,
        msgspec.json.encode(message),
        str(message.session_id).encode(),
        [("authorization", keys.token(azp=MANAGER).encode())],
    )
    await controller.admit_lifecycle(*args)
    lifecycle.admit.assert_awaited_once_with(topic, message)
    lifecycle.admit.side_effect = RuntimeError("database unavailable")
    with pytest.raises(RuntimeError, match="database"):
        await controller.admit_lifecycle(*args)
    assert SecurityContextHolder.get() is None


@pytest.mark.anyio
@pytest.mark.parametrize("bad", ["no-auth", "signature", "key", "payload"])
async def test_lifecycle_malformed_signals_are_classified_without_database(
    manager_settings, keys, bad
):
    lifecycle = AsyncMock()
    controller = KafkaController(
        manager_settings, keys.verifier, AsyncMock(), AsyncMock(), lifecycle
    )
    message = Signal(uuid4(), uuid4())
    raw, key = msgspec.json.encode(message), str(message.session_id).encode()
    token = Keys().token(azp=MANAGER) if bad == "signature" else keys.token(azp=MANAGER)
    headers = [] if bad == "no-auth" else [("authorization", token.encode())]
    if bad == "key":
        key = b"wrong"
    if bad == "payload":
        raw = b"{broken"
    await controller.admit_lifecycle(TOPICS[0], raw, key, headers)
    assert not lifecycle.mock_calls
