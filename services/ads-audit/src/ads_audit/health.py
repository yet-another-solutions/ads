from __future__ import annotations

from dishka.integrations.litestar import FromDishka, inject
from litestar import get
from litestar.exceptions import ServiceUnavailableException
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine


@get("/health/live", sync_to_thread=False)
def live() -> dict[str, str]:
    return {"status": "ok"}


@get("/health/ready")
@inject
async def ready(engine: FromDishka[AsyncEngine]) -> dict[str, str]:
    """Not ready without the journal: accepted events would have nowhere to land."""
    try:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        raise ServiceUnavailableException(detail="journal unreachable") from exc
    return {"status": "ok"}
