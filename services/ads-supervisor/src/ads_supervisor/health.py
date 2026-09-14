from __future__ import annotations

from dishka.integrations.litestar import FromDishka, inject
from litestar import get
from litestar.exceptions import ServiceUnavailableException

from ads_supervisor.supervisor import Supervisor


@get("/health/live", sync_to_thread=False)
def live() -> dict[str, str]:
    return {"status": "ok"}


@get("/health/ready")
@inject
async def ready(supervisor: FromDishka[Supervisor]) -> dict[str, str]:
    """Not ready until a run is open: without one nothing may be permitted."""
    if supervisor.run is None:
        raise ServiceUnavailableException(detail="no run has been opened")
    return {"status": "ok"}
