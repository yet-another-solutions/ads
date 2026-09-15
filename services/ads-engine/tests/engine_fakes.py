from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import AsyncIterator
from types import SimpleNamespace
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from ads_commons.engine import (
    Acknowledge,
    Authorization,
    EngineRequest,
    OpenAiBearerToken,
    OpenAiStreamAuthentication,
    OpenAiStreamModel,
    OpenAiStreamOptions,
)
from ads_commons.security import SecurityContext
from ads_commons_beans import JwtVerifier
from ads_engine.chat import StreamDelta

ENGINE_ISSUER = "https://keycloak.test/realms/ads"
ENGINE_AUDIENCE = "ads-engine"
ENGINE_CLIENT_ID = "ads"
ENGINE_SUBJECT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
EXCHANGED_TOKEN = "exchanged-token"


def make_request(
    *,
    session_id: uuid.UUID | None = None,
    message_id: uuid.UUID | None = None,
    user_input: str = "hello",
    authorization_token: str = "jwt-not-verified",
) -> EngineRequest:
    return EngineRequest(
        session_id=session_id or uuid.UUID("11111111-1111-1111-1111-111111111111"),
        message_id=message_id or uuid.UUID("22222222-2222-2222-2222-222222222222"),
        history=[],
        user_input=user_input,
        instructions="be brief",
        model=OpenAiStreamModel(
            url="https://llm.example/v1",
            authentication=OpenAiStreamAuthentication(
                openai_bearer=OpenAiBearerToken(token="sk-test"),
            ),
            options=OpenAiStreamOptions(model_name="test-model"),
        ),
        authorization=Authorization(token=authorization_token),
    )


def new_rsa_key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class StaticJwks:
    def __init__(self, private_key: RSAPrivateKey) -> None:
        self._key = private_key

    def get_signing_key_from_jwt(self, token: str) -> SimpleNamespace:
        return SimpleNamespace(key=self._key.public_key())


def encode_access_token(private_key: RSAPrivateKey, **claims: Any) -> str:
    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": ENGINE_SUBJECT,
        "name": "Alice",
        "iss": ENGINE_ISSUER,
        "aud": ENGINE_AUDIENCE,
        "azp": ENGINE_CLIENT_ID,
        "exp": now + 3600,
        "iat": now,
        "realm_access": {"roles": ["user"]},
    }
    payload.update(claims)
    return jwt.encode(payload, private_key, algorithm="RS256")


def make_verifier(private_key: RSAPrivateKey) -> JwtVerifier:
    return JwtVerifier(
        issuer=ENGINE_ISSUER,
        audience=ENGINE_AUDIENCE,
        client_id=ENGINE_CLIENT_ID,
        jwks_client=StaticJwks(private_key),
    )


def exchanged_context() -> SecurityContext:
    return SecurityContext(
        subject=ENGINE_SUBJECT,
        name="Alice",
        roles=frozenset({"user"}),
        authorized_party="ads-engine",
        access_token=EXCHANGED_TOKEN,
    )


class FakeTokenExchange:
    def __init__(
        self,
        context: SecurityContext | None = None,
        error: Exception | None = None,
    ) -> None:
        self.audiences: list[str] = []
        self._context = context if context is not None else exchanged_context()
        self._error = error

    def mint(self, audience: str) -> SecurityContext:
        self.audiences.append(audience)
        if self._error is not None:
            raise self._error
        return self._context


class RecordingPublisher:
    def __init__(self) -> None:
        self.messages: list[object] = []
        self.headers: list[list[tuple[str, bytes]] | None] = []
        self.acknowledged = asyncio.Event()

    async def publish(
        self,
        session_id: uuid.UUID,
        message: object,
        headers: list[tuple[str, bytes]] | None = None,
    ) -> None:
        self.messages.append(message)
        self.headers.append(list(headers) if headers is not None else None)
        if isinstance(message, Acknowledge):
            self.acknowledged.set()


class ScriptedChat:
    def __init__(
        self,
        deltas: list[StreamDelta] | None = None,
        fail_times: int = 0,
        fail_after_partial: bool = False,
    ) -> None:
        self.deltas = list(deltas or [])
        self.fail_times = fail_times
        self.fail_after_partial = fail_after_partial
        self.calls = 0
        self.requests: list[EngineRequest] = []

    def stream(self, request: EngineRequest) -> AsyncIterator[StreamDelta]:
        return self._stream(request)

    async def _stream(self, request: EngineRequest) -> AsyncIterator[StreamDelta]:
        self.calls += 1
        self.requests.append(request)
        if self.calls <= self.fail_times:
            raise RuntimeError("openai unavailable")
        for delta in self.deltas:
            yield delta
            if self.fail_after_partial:
                raise RuntimeError("stream dropped")
