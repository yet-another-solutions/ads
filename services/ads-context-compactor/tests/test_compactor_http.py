import time
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import jwt
import msgspec
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from dishka import Provider, Scope, provide
from litestar.testing import TestClient

from ads_commons.context_compactor import CompactRequest
from ads_commons.engine import Tombstone, UserHistoryTurn
from ads_commons.security import SecurityContextHolder
from ads_commons_beans import JwtVerifier, JwtVerifierSettings
from ads_context_compactor.app import create_app
from ads_context_compactor.config import Settings
from ads_context_compactor.service import ContextCompactorService
from ads_context_runtime.frames import ContextFailure
from context_fakes import Meter, Model, model_settings


@pytest.fixture
def setup():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = "https://identity.test"

    class Keys:
        def get_signing_key_from_jwt(self, token):
            return SimpleNamespace(key=key.public_key())

    verifier = JwtVerifier(
        JwtVerifierSettings(issuer, "ads-context-compactor", "ads-engine", "https://unused", None),
        Keys(),
    )
    model = Model('<ads-compaction-result>{"summary":"summary"}</ads-compaction-result>')

    class Overrides(Provider):
        @provide(scope=Scope.APP, override=True)
        def jwt(self) -> JwtVerifier:
            return verifier

        @provide(scope=Scope.REQUEST, override=True)
        def service(self) -> ContextCompactorService:
            return ContextCompactorService(Meter(), model=model, reserve=100)

    def token(**extra):
        return jwt.encode(
            {
                "iss": issuer,
                "aud": "ads-context-compactor",
                "sub": str(uuid4()),
                "azp": "ads-engine",
                "iat": int(time.time()),
                "exp": int(time.time()) + 300,
                **extra,
            },
            key,
            algorithm="RS256",
        )

    settings = Settings(
        issuer + "/discovery", issuer, "private-client-secret", Path("unused"), Path("unused")
    )
    body = msgspec.to_builtins(
        CompactRequest(
            [UserHistoryTurn("old" * 1000), UserHistoryTurn("current")], model_settings(), 50
        )
    )
    with TestClient(create_app(settings, overrides=[Overrides()])) as client:
        yield client, token, model, body
    assert SecurityContextHolder.get() is None


def test_authenticated_rest_returns_only_tombstone(setup):
    client, token, model, body = setup
    result = client.post("/compact", json=body, headers={"Authorization": "Bearer " + token()})
    assert result.status_code == 200
    memory = msgspec.json.decode(result.content, type=Tombstone)
    assert memory.summarization == "summary"
    assert memory.messages[0].text == "old" * 1000
    assert "model-secret" not in result.text and "private-client-secret" not in str(model.calls)


@pytest.mark.parametrize(
    "claims,status",
    [
        ({"azp": "ads"}, 403),
        ({"aud": "ads-engine"}, 401),
        ({"exp": 1}, 401),
        ({"iss": "https://wrong"}, 401),
    ],
)
def test_invalid_identity_cannot_invoke_model(setup, claims, status):
    client, token, model, body = setup
    result = client.post(
        "/compact", json=body, headers={"Authorization": "Bearer " + token(**claims)}
    )
    assert result.status_code == status and not model.calls


def test_missing_auth_bad_request_and_model_failure_are_non_success(setup):
    client, token, model, body = setup
    assert client.get("/health/live").status_code == 200
    assert client.post("/compact", json=body).status_code == 401
    auth = {"Authorization": "Bearer " + token()}
    assert client.post("/compact", json={}, headers=auth).status_code == 400
    model.answers = [ContextFailure("private-provider-failure")]
    response = client.post("/compact", json=body, headers=auth)
    assert response.status_code == 422 and "private-provider" not in response.text
    assert SecurityContextHolder.get() is None
