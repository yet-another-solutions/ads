"""Models facade: catalog logic stays in ads-preferences. Bearers never come back out."""

from __future__ import annotations

import uuid
from typing import Annotated

from dishka.integrations.litestar import FromDishka
from litestar import delete, get, patch, post
from litestar.enums import RequestEncodingType
from litestar.params import Body
from litestar.response import Template

from ads.authenticated import AuthenticatedController
from ads.catalog_service import CatalogService
from ads.inject import inject
from ads.views import ModelView
from ads_commons.preferences import ModelTypeList

Form = Annotated[dict[str, str], Body(media_type=RequestEncodingType.URL_ENCODED)]


async def _dialog(catalog: CatalogService, selected: ModelView | None) -> Template:
    models = await catalog.list_models()
    types = await catalog.list_model_types()
    keep = None
    if selected is not None:
        keep = next((row for row in models if row.id == selected.id), None)
    return Template(
        template_name="partials/settings.html",
        context={"models": models, "selected": keep, "types": types},
    )


@inject
class ModelsController(AuthenticatedController):
    path = "/settings/models"
    catalog: FromDishka[CatalogService]

    @post("/")
    async def add_model(self, data: Form) -> Template:
        created = await self.catalog.add_model(
            data.get("description", ""),
            data.get("name", ""),
            data.get("url", ""),
            data.get("bearer", ""),
            data.get("model-name", ""),
            data.get("type", ""),
            data.get("max_context_tokens", ""),
        )
        return await _dialog(self.catalog, created)

    @patch("/{model_id:uuid}")
    async def edit_model(
        self,
        model_id: uuid.UUID,
        data: Form,
    ) -> Template:
        edited = await self.catalog.edit_model(
            model_id,
            data.get("description"),
            data.get("name"),
            data.get("url"),
            data.get("bearer"),
            data.get("model-name"),
            data.get("type"),
            data.get("max_context_tokens"),
        )
        return await _dialog(self.catalog, edited)

    @delete("/{model_id:uuid}", status_code=200)
    async def delete_model(
        self,
        model_id: uuid.UUID,
    ) -> Template:
        await self.catalog.delete_model(model_id)
        return await _dialog(self.catalog, None)


@inject
class ModelTypesController(AuthenticatedController):
    path = "/settings/model-types"
    catalog: FromDishka[CatalogService]

    @get("/")
    async def list_types(self) -> ModelTypeList:
        return ModelTypeList(types=await self.catalog.list_model_types())
