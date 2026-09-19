from __future__ import annotations

from dishka.integrations.litestar import FromDishka, inject
from litestar import get
from litestar.exceptions import ServiceUnavailableException

from ads_policy.audit import BufferedAuditSink


@get("/health/live", sync_to_thread=False)
def live() -> dict[str, str]:
    return {"status": "ok"}


@get("/health/ready")
@inject
async def ready(audit: FromDishka[BufferedAuditSink]) -> dict[str, str]:
    if audit.saturated:
        raise ServiceUnavailableException(detail="audit backlog full: calls are being refused")
    return {"status": "ok"}
