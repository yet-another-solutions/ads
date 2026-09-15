"""Models facade. Catalog logic stays in ads-preferences; this strips secrets for the browser."""

from __future__ import annotations

import uuid

from ads.exceptions import InvalidInput, NotFound
from ads.method_security import require_role
from ads.views import ModelOption, ModelView
from ads_commons.engine import OpenAiBearerToken, OpenAiStreamAuthentication
from ads_commons.preferences import (
    ModelInfo,
    ModelPatch,
    ModelWrite,
    OpenAiStreamType,
    PreferencesApi,
)

OPENAI_STREAM: OpenAiStreamType = "openai-stream"


def _view(info: ModelInfo) -> ModelView:
    """Drop ``authentication`` before anything reaches a template or the browser."""
    return ModelView(
        id=info.id,
        description=info.description,
        name=info.name,
        type=info.type,
        url=info.url,
    )


def _require_text(value: str, field: str) -> str:
    if not value.strip():
        raise InvalidInput(f"{field} must be non-empty")
    return value.strip()


class CatalogService:
    """Reads and writes the per-user model catalog over S2S HTTPS."""

    def __init__(self, preferences: PreferencesApi) -> None:
        self._preferences = preferences

    async def options(self) -> list[ModelOption]:
        """Composer options: id and description only."""
        listing = await self._preferences.list_models()
        return [ModelOption(id=row.id, description=row.description) for row in listing.models]

    async def list_models(self) -> list[ModelView]:
        listing = await self._preferences.list_models()
        views: list[ModelView] = []
        for summary in listing.models:
            try:
                views.append(_view(await self._preferences.get_model(summary.id)))
            except NotFound:
                continue
        return views

    @require_role("user")
    async def add_model(
        self,
        description: str,
        name: str,
        url: str,
        bearer: str,
    ) -> ModelView:
        """The typed bearer is forwarded once and never echoed back."""
        info = await self._preferences.add_model(
            ModelWrite(
                description=_require_text(description, "Description"),
                name=_require_text(name, "Name"),
                type=OPENAI_STREAM,
                url=_require_text(url, "URL"),
                authentication=OpenAiStreamAuthentication(
                    openai_bearer=OpenAiBearerToken(token=_require_text(bearer, "Bearer token")),
                ),
            )
        )
        return _view(info)

    @require_role("user")
    async def edit_model(
        self,
        model_id: uuid.UUID,
        description: str | None,
        name: str | None,
        url: str | None,
        bearer: str | None,
    ) -> ModelView:
        """An omitted or blank bearer patches without ``authentication``: the stored one stays."""
        authentication = None
        if bearer is not None and bearer.strip():
            authentication = OpenAiStreamAuthentication(
                openai_bearer=OpenAiBearerToken(token=bearer.strip()),
            )
        patch = ModelPatch(
            description=description.strip() if description is not None else None,
            name=name.strip() if name is not None else None,
            url=url.strip() if url is not None else None,
            authentication=authentication,
        )
        if (
            patch.description is None
            and patch.name is None
            and patch.url is None
            and patch.authentication is None
        ):
            raise InvalidInput("nothing to change")
        return _view(await self._preferences.edit_model(model_id, patch))

    @require_role("user")
    async def delete_model(self, model_id: uuid.UUID) -> None:
        await self._preferences.delete_model(model_id)
