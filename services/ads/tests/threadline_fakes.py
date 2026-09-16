from __future__ import annotations

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
from ads_commons.preferences import ModelInfo, ModelList, ModelPatch, ModelSummary, ModelWrite
from ads_commons.security import InvalidAccessToken, SecurityContext

USER_ID = uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
OTHER_USER_ID = uuid.UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
ENGINE_TOKEN = "engine-acknowledge-jwt"
STORED_BEARER = "sk-stored-secret"


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
            options=OpenAiStreamOptions(model_name="gpt-test"),
        )
        self.models[model_id] = info
        return info

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
    """Only ``ENGINE_TOKEN`` verifies, with ``azp=ads-engine`` and ``aud=ads``."""

    def __init__(self, azp: str = "ads-engine") -> None:
        self.azp = azp
        self.audiences: list[str | None] = []

    def authenticate(self, token: str, *, audience: str | None = None) -> SecurityContext:
        self.audiences.append(audience)
        if token != ENGINE_TOKEN:
            raise InvalidAccessToken("token is not the engine token")
        return SecurityContext(
            subject=str(USER_ID),
            name="ads-engine",
            roles=frozenset({"user"}),
            authorized_party=self.azp,
            access_token=token,
        )


def login(client: TestClient, sub: uuid.UUID = USER_ID, roles: list[str] | None = None) -> None:
    client.set_session_data(
        {
            "identity": {
                "sub": str(sub),
                "name": "Alice Operator",
                "roles": roles if roles is not None else ["user"],
                "email": "alice@example.com",
            },
            "access_token": "user-access-token",
        }
    )


def headers(token: str = ENGINE_TOKEN) -> list[tuple[str, bytes]]:
    return [("authorization", token.encode("utf-8"))]


def project_id_of(payload: dict[str, Any]) -> uuid.UUID:
    return uuid.UUID(str(payload["id"]))
