import time
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
    SandboxReady,
    SandboxRequest,
    SandboxResult,
    encode_inbound,
    encode_outbound,
    encode_ready,
)
from ads_commons.security import InvalidAccessToken, SecurityContextHolder
from ads_commons_beans import JwtVerifier, JwtVerifierSettings, TokenExchangeSettings
from ads_sandbox_manager.auth import IPC, MANAGER, MCP, ClientCredentials
from ads_sandbox_manager.barrier import TOPIC, BarrierAck, BarrierRequest
from ads_sandbox_manager.controller import KafkaController
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
    if kind == "ready":
        return READY_TOPIC, encode_ready(SandboxReady(sandbox)), str(sandbox).encode(), IPC
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
    "request",
    "ack-reply",
    "ack-reset",
    "abort",
    "acknowledge",
    "result",
    "ready",
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
    service, barrier = AsyncMock(), AsyncMock()
    controller = KafkaController(manager_settings, keys.verifier, service, barrier)
    topic, raw, key, caller = wire(kind)
    claims = {"azp": caller, **changes}
    token = keys.token(**claims)
    await controller.on_message(topic, raw, key, [("authorization", token.encode())])
    assert not service.mock_calls and not barrier.mock_calls
    assert SecurityContextHolder.get() is None
    assert "rejected" in caplog.text
    assert all(secret not in caplog.text for secret in (token, "secret-command", "secret-output"))


@pytest.mark.anyio
@pytest.mark.parametrize("kind", KINDS)
async def test_valid_authenticated_delivery_without_holder(manager_settings, keys, kind):
    service, barrier = AsyncMock(), AsyncMock()
    controller = KafkaController(manager_settings, keys.verifier, service, barrier)
    topic, raw, key, caller = wire(kind)
    await controller.on_message(
        topic, raw, key, [("authorization", keys.token(azp=caller).encode())]
    )
    assert service.mock_calls or barrier.mock_calls
    assert SecurityContextHolder.get() is None


@pytest.mark.anyio
@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("bad", ["missing-auth", "invalid-auth", "key", "payload"])
async def test_missing_auth_and_malformed_wire_have_no_effect(manager_settings, keys, kind, bad):
    service, barrier = AsyncMock(), AsyncMock()
    controller = KafkaController(manager_settings, keys.verifier, service, barrier)
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
    assert not service.mock_calls and not barrier.mock_calls


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
