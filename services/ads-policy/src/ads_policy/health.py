from __future__ import annotations

from dishka.integrations.litestar import FromDishka, inject
from litestar import get
from litestar.exceptions import ServiceUnavailableException
from redis.asyncio import Redis
from redis.exceptions import RedisError

from ads_policy.audit import BufferedAuditSink


@get("/health/live", sync_to_thread=False)
def live() -> dict[str, str]:
    return {"status": "ok"}


@get("/health/ready")
@inject
async def ready(redis: FromDishka[Redis], audit: FromDishka[BufferedAuditSink]) -> dict[str, str]:
    try:
        await redis.ping()
    except RedisError as exc:
        raise ServiceUnavailableException(detail="run store unreachable") from exc
    if audit.saturated:
        raise ServiceUnavailableException(detail="audit backlog full: decisions are being refused")
    return {"status": "ok"}
