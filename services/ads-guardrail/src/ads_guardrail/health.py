from __future__ import annotations

from litestar import get


@get("/health/live", sync_to_thread=False)
def live() -> dict[str, str]:
    return {"status": "ok"}


@get("/health/ready", sync_to_thread=False)
def ready() -> dict[str, str]:
    """Up is ready. The process holds no run of its own — each call brings its own."""
    return {"status": "ok"}
