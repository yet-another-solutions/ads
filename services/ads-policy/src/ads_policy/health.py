from __future__ import annotations

from dishka.integrations.litestar import FromDishka, inject
from litestar import get
from litestar.exceptions import ServiceUnavailableException
from redis.asyncio import Redis
from redis.exceptions import RedisError


@get("/health/live", sync_to_thread=False)
def live() -> dict[str, str]:
    return {"status": "ok"}


@get("/health/ready")
@inject
async def ready(redis: FromDishka[Redis]) -> dict[str, str]:
    """Not ready without the run store: every decision would be a denial."""
    try:
        await redis.ping()
    except RedisError as exc:
        raise ServiceUnavailableException(detail="run store unreachable") from exc
    return {"status": "ok"}
