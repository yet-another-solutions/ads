from __future__ import annotations

from uuid import UUID

from dishka.integrations.litestar import FromDishka
from litestar import Controller, Response, delete, get, patch, post
from litestar.status_codes import HTTP_201_CREATED, HTTP_204_NO_CONTENT

from ads_commons.preferences import ModelInfo, ModelList, ModelPatch, ModelWrite
from ads_preferences.inject import inject
from ads_preferences.service import PreferencesService


@inject
class ModelsController(Controller):
    path = "/v1"
    service: FromDishka[PreferencesService]

    @get("/models")
    async def list_models(self) -> ModelList:
        return await self.service.list_models()

    @get("/models/{model_id:str}")
    async def get_model(self, model_id: UUID) -> ModelInfo:
        return await self.service.get_model(model_id)

    @post("/models", status_code=HTTP_201_CREATED)
    async def add_model(self, data: ModelWrite) -> Response[ModelInfo]:
        info = await self.service.add_model(data)
        return Response(
            info,
            status_code=HTTP_201_CREATED,
            headers={"location": f"/v1/models/{info.id}"},
        )

    @patch("/models/{model_id:str}")
    async def edit_model(
        self,
        model_id: UUID,
        data: ModelPatch,
    ) -> ModelInfo:
        return await self.service.edit_model(model_id, data)

    @delete("/models/{model_id:str}", status_code=HTTP_204_NO_CONTENT)
    async def delete_model(self, model_id: UUID) -> None:
        await self.service.delete_model(model_id)
