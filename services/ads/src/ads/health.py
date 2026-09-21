from __future__ import annotations

from typing import Any

from litestar import Request, get
from litestar.response import Response

from ads.egress_kafka import EgressKafka


@get("/health/live", sync_to_thread=False)
def live() -> dict[str, str]:
    return {"status": "ok"}


@get("/health/ready", sync_to_thread=False)
def ready(request: Request[Any, Any, Any]) -> Response[dict[str, str]]:
    updates = getattr(request.app.state, "egress_updates", None)
    healthy = updates is not None and (
        not isinstance(updates, EgressKafka) or (updates.started and not updates.failed)
    )
    return Response(
        {"status": "ok" if healthy else "not-ready"}, status_code=200 if healthy else 503
    )
