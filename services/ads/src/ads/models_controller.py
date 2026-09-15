"""Models facade: catalog logic stays in ads-preferences. Bearers never come back out."""

from __future__ import annotations

import uuid
from typing import Annotated

from dishka.integrations.litestar import FromDishka, inject
from litestar import delete, patch, post
from litestar.enums import RequestEncodingType
from litestar.params import Body
from litestar.response import Template

from ads.authenticated import AuthenticatedController
from ads.catalog_service import CatalogService
from ads.views import ModelView

Form = Annotated[dict[str, str], Body(media_type=RequestEncodingType.URL_ENCODED)]


async def _dialog(catalog: CatalogService, selected: ModelView | None) -> Template:
    models = await catalog.list_models()
    keep = None
    if selected is not None:
        keep = next((row for row in models if row.id == selected.id), None)
    return Template(
        template_name="partials/settings.html",
        context={"models": models, "selected": keep},
    )


class ModelsController(AuthenticatedController):
    path = "/settings/models"

    @post("/")
    @inject
    async def add_model(self, data: Form, catalog: FromDishka[CatalogService]) -> Template:
        created = await catalog.add_model(
            data.get("description", ""),
            data.get("name", ""),
            data.get("url", ""),
            data.get("bearer", ""),
        )
        return await _dialog(catalog, created)

    @patch("/{model_id:uuid}")
    @inject
    async def edit_model(
        self,
        model_id: uuid.UUID,
        data: Form,
        catalog: FromDishka[CatalogService],
    ) -> Template:
        edited = await catalog.edit_model(
            model_id,
            data.get("description"),
            data.get("name"),
            data.get("url"),
            data.get("bearer"),
        )
        return await _dialog(catalog, edited)

    @delete("/{model_id:uuid}", status_code=200)
    @inject
    async def delete_model(
        self,
        model_id: uuid.UUID,
        catalog: FromDishka[CatalogService],
    ) -> Template:
        await catalog.delete_model(model_id)
        return await _dialog(catalog, None)
