"""Preferences catalog wire types."""

from __future__ import annotations

from typing import Literal, Protocol, runtime_checkable
from uuid import UUID

import msgspec

from ads_commons.engine import OpenAiStreamAuthentication

OpenAiStreamType = Literal["openai-stream"]


class ModelSummary(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    id: UUID
    description: str


class ModelList(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    models: list[ModelSummary]


class ModelInfo(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    id: UUID
    description: str
    name: str
    type: OpenAiStreamType
    url: str
    authentication: OpenAiStreamAuthentication


class ModelWrite(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    description: str
    name: str
    type: OpenAiStreamType
    url: str
    authentication: OpenAiStreamAuthentication


class ModelPatch(msgspec.Struct, frozen=True, forbid_unknown_fields=True, omit_defaults=True):
    description: str | None = None
    name: str | None = None
    type: OpenAiStreamType | None = None
    url: str | None = None
    authentication: OpenAiStreamAuthentication | None = None


@runtime_checkable
class PreferencesApi(Protocol):
    async def list_models(self) -> ModelList: ...

    async def get_model(self, model_id: UUID) -> ModelInfo: ...

    async def add_model(self, body: ModelWrite) -> ModelInfo: ...

    async def edit_model(self, model_id: UUID, body: ModelPatch) -> ModelInfo: ...

    async def delete_model(self, model_id: UUID) -> None: ...
