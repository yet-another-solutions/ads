"""Models facade. Catalog logic stays in ads-preferences; this strips secrets for the browser."""

from __future__ import annotations

import uuid

from ads.exceptions import InvalidInput, NotFound
from ads.views import ModelOption, ModelView
from ads_commons.engine import OpenAiBearerToken, OpenAiStreamAuthentication, OpenAiStreamOptions
from ads_commons.preferences import (
    ModelInfo,
    ModelPatch,
    ModelWrite,
    OpenAiStreamType,
    PreferencesApi,
)
from ads_commons.security import require_role

OPENAI_STREAM: OpenAiStreamType = "openai-stream"


def _view(info: ModelInfo) -> ModelView:
    """Drop ``authentication`` before anything reaches a template or the browser."""
    return ModelView(
        id=info.id,
        description=info.description,
        name=info.name,
        type=info.type,
        url=info.url,
        model_name=info.options.model_name,
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
        model_name: str,
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
                options=OpenAiStreamOptions(
                    model_name=_require_text(model_name, "Model name"),
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
        model_name: str | None,
    ) -> ModelView:
        """An omitted or blank bearer patches without ``authentication``: the stored one stays."""
        authentication = None
        if bearer is not None and bearer.strip():
            authentication = OpenAiStreamAuthentication(
                openai_bearer=OpenAiBearerToken(token=bearer.strip()),
            )
        options = None
        if model_name is not None:
            options = OpenAiStreamOptions(model_name=model_name.strip())
        patch = ModelPatch(
            description=description.strip() if description is not None else None,
            name=name.strip() if name is not None else None,
            url=url.strip() if url is not None else None,
            authentication=authentication,
            options=options,
        )
        if (
            patch.description is None
            and patch.name is None
            and patch.url is None
            and patch.authentication is None
            and patch.options is None
        ):
            raise InvalidInput("nothing to change")
        return _view(await self._preferences.edit_model(model_id, patch))

    @require_role("user")
    async def delete_model(self, model_id: uuid.UUID) -> None:
        await self._preferences.delete_model(model_id)
