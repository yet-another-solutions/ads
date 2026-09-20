from dishka.integrations.litestar import FromDishka
from litestar import Controller, post

from ads_commons.context_compactor import CompactRequest
from ads_commons.engine import Tombstone
from ads_context_compactor.inject import inject
from ads_context_compactor.service import ContextCompactorService


@inject
class CompactorController(Controller):
    path = "/compact"
    service: FromDishka[ContextCompactorService]

    @post(status_code=200)
    async def compact(self, data: CompactRequest) -> Tombstone:
        return await self.service.compact(data)
