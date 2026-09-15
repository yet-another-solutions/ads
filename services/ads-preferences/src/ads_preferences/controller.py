from __future__ import annotations

from uuid import UUID

from dishka.integrations.litestar import FromDishka, inject
from litestar import Controller, Response, delete, get, patch, post
from litestar.status_codes import HTTP_201_CREATED, HTTP_204_NO_CONTENT

from ads_commons.preferences import ModelInfo, ModelList, ModelPatch, ModelWrite
from ads_preferences.service import PreferencesService


class ModelsController(Controller):
    path = "/v1"

    @get("/models")
    @inject
    async def list_models(self, service: FromDishka[PreferencesService]) -> ModelList:
        return await service.list_models()

    @get("/models/{model_id:str}")
    @inject
    async def get_model(self, model_id: UUID, service: FromDishka[PreferencesService]) -> ModelInfo:
        return await service.get_model(model_id)

    @post("/models", status_code=HTTP_201_CREATED)
    @inject
    async def add_model(
        self, data: ModelWrite, service: FromDishka[PreferencesService]
    ) -> Response[ModelInfo]:
        info = await service.add_model(data)
        return Response(
            info,
            status_code=HTTP_201_CREATED,
            headers={"location": f"/v1/models/{info.id}"},
        )

    @patch("/models/{model_id:str}")
    @inject
    async def edit_model(
        self,
        model_id: UUID,
        data: ModelPatch,
        service: FromDishka[PreferencesService],
    ) -> ModelInfo:
        return await service.edit_model(model_id, data)

    @delete("/models/{model_id:str}", status_code=HTTP_204_NO_CONTENT)
    @inject
    async def delete_model(self, model_id: UUID, service: FromDishka[PreferencesService]) -> None:
        await service.delete_model(model_id)
