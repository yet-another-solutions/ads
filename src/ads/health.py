from __future__ import annotations

from litestar import get


@get("/health/live", sync_to_thread=False)
def live() -> dict[str, str]:
    return {"status": "ok"}


@get("/health/ready", sync_to_thread=False)
def ready() -> dict[str, str]:
    return {"status": "ok"}
