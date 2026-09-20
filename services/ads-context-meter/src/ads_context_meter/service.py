from ads_commons.context_meter import MeterRequest, MeterResponse
from ads_commons.security import require_caller
from ads_context_meter.worker import TokenCounter


class ContextMeterService:
    def __init__(self, counter: TokenCounter) -> None:
        self._counter = counter

    @require_caller("ads-engine", "ads-context-compactor")
    async def meter(self, body: MeterRequest) -> MeterResponse:
        return MeterResponse(estimated_tokens=await self._counter.count(body))
