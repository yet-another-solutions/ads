import asyncio
import time
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from litestar.testing import TestClient

from ads_commons.context_meter import ContextMeterApi, MeterRequest, MeterResponse
from ads_commons.security import AccessDenied, AuthenticationRequired, SecurityContextHolder
from ads_commons_beans import JwtVerifier, JwtVerifierSettings
from ads_context_meter.app import create_app
from ads_context_meter.config import Settings
from ads_context_meter.service import ContextMeterService
from ads_context_meter.worker import TokenCounter

ISSUER = "https://keycloak.test/realms/ads"
BODY = {"model_name": "glm-5.3", "messages": [{"type": "user", "text": "hello"}]}


class CountingStub(TokenCounter):
    def __init__(self):
        self.calls = []
        self.closed = False

    async def count(self, body):
        self.calls.append((body, SecurityContextHolder.require()))
        return 17

    def close(self):
        self.closed = True


@pytest.fixture
def setup(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    class Keys:
        def get_signing_key_from_jwt(self, token):
            return SimpleNamespace(key=key.public_key())

    verifier = JwtVerifier(
        JwtVerifierSettings(ISSUER, "ads-context-meter", "ads-engine", "https://unused", None),
        Keys(),
    )
    settings = Settings(
        ISSUER + "/.well-known/openid-configuration",
        ISSUER,
        "ads-context-meter",
        "ads-engine",
        tmp_path,
        Path("unused"),
        Path("unused"),
        None,
        "127.0.0.1",
        8080,
    )
    counter = CountingStub()

    def token(**claims):
        payload = {
            "iss": ISSUER,
            "aud": "ads-context-meter",
            "sub": str(uuid4()),
            "azp": "ads-engine",
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
            # Deliberately no realm or resource roles.
        }
        payload.update(claims)
        return jwt.encode(payload, key, algorithm="RS256")

    with TestClient(create_app(settings, jwt_verifier=verifier, counter=counter)) as client:
        yield client, token, counter, verifier
    assert counter.closed


def auth(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.parametrize("model", ["glm-5.2", "glm-5.3"])
def test_allowed_engine_without_roles(setup, model):
    client, token, counter, _ = setup
    response = client.post("/meter", json={**BODY, "model_name": model}, headers=auth(token()))
    assert response.status_code == 200
    assert response.json() == {"estimated_tokens": 17}
    assert counter.calls[0][0].model_name == model
    assert counter.calls[0][1].authorized_party == "ads-engine"
    assert not counter.calls[0][1].roles
    assert SecurityContextHolder.get() is None


def test_allowed_compactor_without_roles(setup):
    client, token, counter, _ = setup
    result = client.post("/meter", json=BODY, headers=auth(token(azp="ads-context-compactor")))
    assert result.status_code == 200
    assert counter.calls[-1][1].authorized_party == "ads-context-compactor"


@pytest.mark.parametrize("header", [None, "Bearer ", "Basic bad", "Bearer garbage"])
def test_missing_or_invalid_bearer_never_counts(setup, header):
    client, _, counter, _ = setup
    response = client.post(
        "/meter",
        json=BODY,
        headers={"Authorization": header} if header is not None else {},
    )
    assert response.status_code == 401
    assert not counter.calls


@pytest.mark.parametrize(
    "claims,status",
    [
        ({"aud": "ads-engine"}, 401),
        ({"iss": "https://wrong"}, 401),
        ({"exp": 1}, 401),
        ({"sub": "not-a-uuid"}, 401),
        ({"azp": ""}, 403),
        ({"azp": "ads"}, 403),
        ({"azp": "ads-sandbox-mcp", "realm_access": {"roles": ["user", "admin"]}}, 403),
    ],
)
def test_jwt_and_caller_rejection_never_counts(setup, claims, status):
    client, token, counter, _ = setup
    response = client.post("/meter", json=BODY, headers=auth(token(**claims)))
    assert response.status_code == status
    assert not counter.calls
    assert SecurityContextHolder.get() is None


def test_wrong_signature_and_absent_azp(setup):
    client, token, counter, _ = setup
    claims = jwt.decode(token(), options={"verify_signature": False})
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert (
        client.post(
            "/meter", json=BODY, headers=auth(jwt.encode(claims, other, algorithm="RS256"))
        ).status_code
        == 401
    )
    assert client.post("/meter", json=BODY, headers=auth(token(azp=None))).status_code == 403
    assert not counter.calls


@pytest.mark.parametrize(
    "body",
    [
        {"messages": []},
        {"model_name": "glm-5.3"},
        {"model_name": "unknown", "messages": []},
        {"model_name": "GLM-5.3", "messages": []},
        {"model_name": "../tokenizer", "messages": []},
        {"model_name": "glm-5.3", "messages": [{"type": "future", "text": "x"}]},
        {"model_name": "glm-5.3", "messages": [{"type": "user", "text": 42}]},
        {**BODY, "tokenizer_url": "https://forbidden"},
    ],
)
def test_invalid_contract_is_400(setup, body):
    client, token, counter, _ = setup
    assert client.post("/meter", json=body, headers=auth(token())).status_code == 400
    assert not counter.calls


def test_all_primitives_are_shared_ads_types(setup):
    client, token, counter, _ = setup
    messages = [
        {"type": "system", "text": "Be helpful"},
        {"type": "user", "text": "Question"},
        {"type": "reasoning", "text": "Think"},
        {"type": "assistant", "text": "Answer"},
        {"type": "tool_call", "id": "a", "name": "exec", "arguments": {"cmd": "true"}},
        {
            "type": "tool_result",
            "tool_call_id": "a",
            "name": "exec",
            "status": "success",
            "content": {"stdout": "ok"},
        },
    ]
    response = client.post("/meter", json={**BODY, "messages": messages}, headers=auth(token()))
    assert response.status_code == 200
    assert len(counter.calls[0][0].messages) == 6


def test_health_only_is_public_and_rest_only(setup):
    client, token, counter, _ = setup
    for path in ("/health/live", "/health/ready"):
        assert client.get(path).status_code == 200
    assert client.post("/meter", json=BODY).status_code == 401
    assert client.get("/health/other").status_code == 404
    assert client.get("/meter", headers=auth(token())).status_code == 405
    assert client.post("/measure", json=BODY, headers=auth(token())).status_code == 404
    assert not counter.calls


def test_service_guard_applies_without_http(setup):
    _, token, counter, verifier = setup
    service = ContextMeterService(counter)
    assert isinstance(service, ContextMeterApi)
    request = MeterRequest("glm-5.2", [])
    with pytest.raises(AuthenticationRequired):
        asyncio.run(service.meter(request))
    with SecurityContextHolder.bound(verifier.authenticate(token(azp="ads"))):
        with pytest.raises(AccessDenied):
            asyncio.run(service.meter(request))
    assert not counter.calls
    with SecurityContextHolder.bound(verifier.authenticate(token())):
        assert asyncio.run(service.meter(request)) == MeterResponse(17)


def test_security_context_cleared_after_failure(setup, monkeypatch):
    client, token, counter, _ = setup

    async def fail(body):
        raise AccessDenied()

    monkeypatch.setattr(counter, "count", fail)
    assert client.post("/meter", json=BODY, headers=auth(token())).status_code == 403
    assert SecurityContextHolder.get() is None
