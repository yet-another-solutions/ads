from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import msgspec
from sqlalchemy.orm import Session

from ads_commons.engine import OpenAiStreamAuthentication, OpenAiStreamOptions
from ads_commons.model_catalog import SUPPORTED_MODEL_TYPES
from ads_commons.preferences import (
    ModelInfo,
    ModelList,
    ModelPatch,
    ModelSummary,
    ModelTypeList,
    ModelWrite,
)
from ads_commons.security import SecurityContextHolder, require_role
from ads_preferences.exceptions import InvalidModel, ModelNotFound
from ads_preferences.models import UserModel
from ads_preferences.repository import UserModelRepository


def _require_text(value: str, field: str) -> str:
    if not value.strip():
        raise InvalidModel(f"{field} must be non-empty")
    return value


def _authentication_payload(authentication: OpenAiStreamAuthentication) -> dict[str, Any]:
    token = authentication.openai_bearer.token
    if not token.strip():
        raise InvalidModel("authentication token must be non-empty")
    payload = json.loads(msgspec.json.encode(authentication))
    if not isinstance(payload, dict):
        raise InvalidModel("authentication is invalid")
    return payload


def _authentication_from_row(payload: dict[str, Any]) -> OpenAiStreamAuthentication:
    return msgspec.convert(payload, type=OpenAiStreamAuthentication)


def _options_payload(options: OpenAiStreamOptions) -> dict[str, Any]:
    model_name = _require_text(options.model_name, "options.model-name")
    payload = json.loads(
        msgspec.json.encode(
            OpenAiStreamOptions(
                model_name=model_name,
                max_context_tokens=options.max_context_tokens,
            )
        )
    )
    if not isinstance(payload, dict):
        raise InvalidModel("options is invalid")
    return payload


def _options_from_row(payload: dict[str, Any]) -> OpenAiStreamOptions:
    return msgspec.convert(payload, type=OpenAiStreamOptions)


class PreferencesService:
    def __init__(self, session: Session, repository: UserModelRepository) -> None:
        self._session = session
        self._repository = repository

    def _to_info(self, row: UserModel) -> ModelInfo:
        if row.type != "openai-stream":
            raise RuntimeError("stored model type is not openai-stream")
        return ModelInfo(
            id=row.id,
            description=row.description,
            name=row.name,
            type="openai-stream",
            url=row.url,
            authentication=_authentication_from_row(row.authentication),
            options=_options_from_row(row.options),
        )

    @require_role("user")
    async def list_model_types(self) -> ModelTypeList:
        return ModelTypeList(types=list(SUPPORTED_MODEL_TYPES))

    @require_role("user")
    async def list_models(self) -> ModelList:
        user_id = SecurityContextHolder.require().user_id
        with self._session.begin():
            rows = self._repository.list_for_user(user_id)
            return ModelList(
                models=[ModelSummary(id=row.id, description=row.description) for row in rows]
            )

    @require_role("user")
    async def get_model(self, model_id: uuid.UUID) -> ModelInfo:
        user_id = SecurityContextHolder.require().user_id
        with self._session.begin():
            row = self._repository.get_for_user(user_id, model_id)
            if row is None:
                raise ModelNotFound()
            return self._to_info(row)

    @require_role("user")
    async def add_model(self, body: ModelWrite) -> ModelInfo:
        user_id = SecurityContextHolder.require().user_id
        now = datetime.now(UTC)
        row = UserModel(
            id=uuid.uuid4(),
            user_id=user_id,
            description=_require_text(body.description, "description"),
            name=_require_text(body.name, "name"),
            type=body.type,
            url=_require_text(body.url, "url"),
            authentication=_authentication_payload(body.authentication),
            options=_options_payload(body.options),
            created_at=now,
            updated_at=now,
        )
        with self._session.begin():
            stored = self._repository.insert_for_user(row)
            return self._to_info(stored)

    @require_role("user")
    async def edit_model(self, model_id: uuid.UUID, body: ModelPatch) -> ModelInfo:
        user_id = SecurityContextHolder.require().user_id
        if (
            body.description is None
            and body.name is None
            and body.type is None
            and body.url is None
            and body.authentication is None
            and body.options is None
        ):
            raise InvalidModel("patch must include at least one field")
        with self._session.begin():
            row = self._repository.get_for_user(user_id, model_id)
            if row is None:
                raise ModelNotFound()
            if body.description is not None:
                row.description = _require_text(body.description, "description")
            if body.name is not None:
                row.name = _require_text(body.name, "name")
            if body.type is not None:
                row.type = body.type
            if body.url is not None:
                row.url = _require_text(body.url, "url")
            if body.authentication is not None:
                row.authentication = _authentication_payload(body.authentication)
            if body.options is not None:
                row.options = _options_payload(body.options)
            row.updated_at = datetime.now(UTC)
            stored = self._repository.update_for_user(row)
            return self._to_info(stored)

    @require_role("user")
    async def delete_model(self, model_id: uuid.UUID) -> None:
        user_id = SecurityContextHolder.require().user_id
        with self._session.begin():
            deleted = self._repository.delete_for_user(user_id, model_id)
            if not deleted:
                raise ModelNotFound()
