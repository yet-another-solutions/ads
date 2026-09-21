from __future__ import annotations

import time
import uuid
from typing import Any

from litestar.testing import TestClient

from ads_commons.engine import (
    Abort,
    AckResponse,
    EngineRequest,
    OpenAiBearerToken,
    OpenAiStreamAuthentication,
    OpenAiStreamOptions,
)
from ads_commons.model_catalog import SUPPORTED_MODEL_TYPES
from ads_commons.preferences import (
    ModelInfo,
    ModelList,
    ModelPatch,
    ModelSummary,
    ModelTypeList,
    ModelWrite,
)
from ads_commons.security import InvalidAccessToken, SecurityContext
from ads_commons_web.identity import (
    ACCESS_TOKEN_SESSION_KEY,
    identity_from_claims,
    security_context_from_identity,
)
from ads_commons_web.session_binder import SessionBinder

USER_ID = uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
USER_ACCESS_TOKEN = "user-access-token"
OTHER_USER_ID = uuid.UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
ENGINE_TOKEN = "engine-acknowledge-jwt"
STORED_BEARER = "sk-stored-secret"
AUDITOR_ID = uuid.UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
AUDITOR_TOKEN = "auditor-exchanged-jwt"
NOT_AN_AUDITOR_TOKEN = "no-auditor-role-exchanged-jwt"
AUDIT_TOKENS = {
    AUDITOR_TOKEN: frozenset({"auditor"}),
    NOT_AN_AUDITOR_TOKEN: frozenset({"user"}),
}


class ProduceFailed(Exception):
    pass


class RecordingKafka:
    """Records what would go on ``ads.engine.request``. No broker in tests."""

    def __init__(self, fail_request: bool = False) -> None:
        self.requests: list[EngineRequest] = []
        self.ack_responses: list[tuple[AckResponse, str]] = []
        self.aborts: list[tuple[Abort, str]] = []
        self.fail_request = fail_request

    async def produce_request(self, request: EngineRequest) -> None:
        if self.fail_request:
            raise ProduceFailed("kafka is down")
        self.requests.append(request)

    async def produce_ack_response(self, message: AckResponse, token: str) -> None:
        self.ack_responses.append((message, token))

    async def produce_abort(self, message: Abort, token: str) -> None:
        self.aborts.append((message, token))


class FakePreferences:
    """In-memory ads-preferences. ``get_model`` is the only caller that sees a bearer."""

    def __init__(self) -> None:
        self.models: dict[uuid.UUID, ModelInfo] = {}
        self.patches: list[tuple[uuid.UUID, ModelPatch]] = []
        self.writes: list[ModelWrite] = []

    def seed(self, description: str = "Work chat", bearer: str = STORED_BEARER) -> ModelInfo:
        model_id = uuid.uuid4()
        info = ModelInfo(
            id=model_id,
            description=description,
            name="gpt-test",
            type="openai-stream",
            url="https://llm.example/v1",
            authentication=OpenAiStreamAuthentication(
                openai_bearer=OpenAiBearerToken(token=bearer),
            ),
            options=OpenAiStreamOptions(model_name="glm-5.3", max_context_tokens=32768),
        )
        self.models[model_id] = info
        return info

    async def list_model_types(self) -> ModelTypeList:
        return ModelTypeList(types=list(SUPPORTED_MODEL_TYPES))

    async def list_models(self) -> ModelList:
        return ModelList(
            models=[
                ModelSummary(id=info.id, description=info.description)
                for info in self.models.values()
            ]
        )

    async def get_model(self, model_id: uuid.UUID) -> ModelInfo:
        info = self.models.get(model_id)
        if info is None:
            from ads.exceptions import NotFound

            raise NotFound("no such model")
        return info

    async def add_model(self, body: ModelWrite) -> ModelInfo:
        self.writes.append(body)
        model_id = uuid.uuid4()
        info = ModelInfo(
            id=model_id,
            description=body.description,
            name=body.name,
            type=body.type,
            url=body.url,
            authentication=body.authentication,
            options=body.options,
        )
        self.models[model_id] = info
        return info

    async def edit_model(self, model_id: uuid.UUID, body: ModelPatch) -> ModelInfo:
        current = await self.get_model(model_id)
        self.patches.append((model_id, body))
        info = ModelInfo(
            id=model_id,
            description=body.description if body.description is not None else current.description,
            name=body.name if body.name is not None else current.name,
            type=body.type if body.type is not None else current.type,
            url=body.url if body.url is not None else current.url,
            authentication=(
                body.authentication if body.authentication is not None else current.authentication
            ),
            options=body.options if body.options is not None else current.options,
        )
        self.models[model_id] = info
        return info

    async def delete_model(self, model_id: uuid.UUID) -> None:
        await self.get_model(model_id)
        self.models.pop(model_id, None)


class FakeTokens:
    """STE V2 stand-in. Records audience and the subject token actually exchanged."""

    def __init__(self, error: Exception | None = None) -> None:
        self.calls: list[tuple[str, str | None]] = []
        self.error = error

    def exchange(self, audience: str, subject_token: str | None = None) -> str:
        self.calls.append((audience, subject_token))
        if self.error is not None:
            raise self.error
        return f"ste-{audience}"

    def mint(self, audience: str, subject_token: str | None = None) -> SecurityContext:
        return SecurityContext(
            subject=str(USER_ID),
            name="ads",
            roles=frozenset({"user"}),
            authorized_party="ads",
            access_token=self.exchange(audience, subject_token),
        )


class FakeAuthenticator:
    """``ENGINE_TOKEN`` verifies as ``ads-engine``, the ``AUDIT_TOKENS`` as ``ads-audit``."""

    def __init__(self, azp: str = "ads-engine") -> None:
        self.azp = azp
        self.audiences: list[str | None] = []

    def authenticate(self, token: str, *, audience: str | None = None) -> SecurityContext:
        self.audiences.append(audience)
        if token in AUDIT_TOKENS:
            return SecurityContext(
                subject=str(AUDITOR_ID),
                name="Ada Auditor",
                roles=AUDIT_TOKENS[token],
                authorized_party="ads-audit",
                access_token=token,
            )
        if token != ENGINE_TOKEN:
            raise InvalidAccessToken("token is not the engine token")
        return SecurityContext(
            subject=str(USER_ID),
            name="ads-engine",
            roles=frozenset({"user"}),
            authorized_party=self.azp,
            access_token=token,
        )


class FakeOidcVerifier:
    def __init__(self) -> None:
        self.extra_claims: dict[str, dict[str, Any]] = {}

    def verified_claims(
        self,
        token: str,
        *,
        nonce: str | None = None,
        audience: str | None = None,
        verify_exp: bool = True,
    ) -> dict[str, Any]:
        del audience
        if not token.strip():
            raise InvalidAccessToken("token is required")
        claims = self._claims_for(token)
        if nonce is not None and claims.get("nonce") != nonce:
            raise InvalidAccessToken("nonce mismatch")
        exp = claims.get("exp")
        if verify_exp and isinstance(exp, int | float) and float(exp) < time.time():
            raise InvalidAccessToken("expired")
        return claims

    def decode(
        self,
        token: str,
        *,
        nonce: str | None = None,
        audience: str | None = None,
    ) -> Any:
        try:
            return identity_from_claims(
                self.verified_claims(token, nonce=nonce, audience=audience),
                "ads",
            )
        except ValueError as exc:
            raise InvalidAccessToken(str(exc)) from exc

    def authenticate(self, token: str, *, audience: str | None = None) -> SecurityContext:
        return security_context_from_identity(
            self.decode(token, audience=audience)
        ).with_access_token(token)

    def _claims_for(self, token: str) -> dict[str, Any]:
        if token in self.extra_claims:
            return dict(self.extra_claims[token])
        now = int(time.time())
        sub = str(USER_ID)
        roles = ["user"]
        if token.startswith("user:"):
            parts = token.split(":", 2)
            if len(parts) == 3:
                sub = parts[1]
                roles = [item for item in parts[2].split(",") if item]
        elif token not in {USER_ACCESS_TOKEN, "id-token"}:
            raise InvalidAccessToken("unknown token")
        return {
            "sub": sub,
            "name": "Alice Operator",
            "email": "alice@example.com",
            "azp": "ads",
            "sid": f"sid-{sub}",
            "exp": now + 3600,
            "iat": now,
            "iss": "http://keycloak.test/realms/ads",
            "aud": "ads",
            "realm_access": {"roles": roles},
        }


class FakeTokenRefresher:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.response: dict[str, Any] = {
            "access_token": "user-access-token-rotated",
            "refresh_token": "refresh-2",
        }
        self.error: Exception | None = None

    async def refresh_tokens(self, refresh_token: str) -> dict[str, Any]:
        self.calls.append(refresh_token)
        if self.error is not None:
            raise self.error
        return self.response


class _NoRefresh:
    async def refresh_tokens(self, refresh_token: str) -> dict[str, Any]:
        del refresh_token
        raise AssertionError("OIDC refresh should not run")


class _UnusedRefreshTokens:
    async def load(self, sid: str) -> str | None:
        raise AssertionError("refresh token store should not open")

    async def save(self, sid: str, user_id: uuid.UUID, refresh_token: str) -> None:
        raise AssertionError("refresh token store should not open")

    async def delete(self, sid: str) -> None:
        raise AssertionError("refresh token store should not open")


def attach_fake_session_binder(
    app: Any, verifier: FakeOidcVerifier | None = None
) -> FakeOidcVerifier:
    oidc_verifier = verifier or FakeOidcVerifier()
    app.state.session_binder = SessionBinder(
        oidc_verifier,  # type: ignore[arg-type]
        _NoRefresh(),
        _UnusedRefreshTokens(),
        "ads",
    )
    return oidc_verifier


def login(client: TestClient, sub: uuid.UUID = USER_ID, roles: list[str] | None = None) -> None:
    if sub == USER_ID and (roles is None or roles == ["user"]):
        token = USER_ACCESS_TOKEN
    else:
        token = f"user:{sub}:{','.join(roles or [])}"
    client.set_session_data({ACCESS_TOKEN_SESSION_KEY: token})


def headers(token: str = ENGINE_TOKEN) -> list[tuple[str, bytes]]:
    return [("authorization", token.encode("utf-8"))]


def project_id_of(payload: dict[str, Any]) -> uuid.UUID:
    return uuid.UUID(str(payload["id"]))
