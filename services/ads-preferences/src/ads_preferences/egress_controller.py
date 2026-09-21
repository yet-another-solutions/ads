from __future__ import annotations

from uuid import UUID

from dishka.integrations.litestar import FromDishka
from litestar import Controller, delete, get, put

from ads_commons.egress import ProjectEgressSettings, ProjectEgressSnapshot
from ads_preferences.egress_service import ProjectEgressService
from ads_preferences.inject import inject


@inject
class ProjectEgressController(Controller):
    path = "/v1/projects/{project_id:str}/egress-settings"
    service: FromDishka[ProjectEgressService]

    @get()
    async def get_egress(self, project_id: UUID) -> ProjectEgressSnapshot:
        return await self.service.get_egress(project_id)

    @put()
    async def save_egress(
        self, project_id: UUID, data: ProjectEgressSettings
    ) -> ProjectEgressSnapshot:
        return await self.service.save_egress(project_id, data)

    @delete(status_code=204)
    async def delete_egress(self, project_id: UUID) -> None:
        await self.service.delete_egress(project_id)
