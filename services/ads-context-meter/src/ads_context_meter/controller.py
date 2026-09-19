from dishka.integrations.litestar import FromDishka
from litestar import Controller, post

from ads_commons.context_meter import MeterRequest, MeterResponse
from ads_context_meter.inject import inject
from ads_context_meter.service import ContextMeterService


@inject
class MeterController(Controller):
    path = "/meter"
    service: FromDishka[ContextMeterService]

    @post(status_code=200)
    async def meter(self, data: MeterRequest) -> MeterResponse:
        return await self.service.meter(data)
