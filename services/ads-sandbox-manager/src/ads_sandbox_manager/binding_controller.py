from __future__ import annotations

import asyncio
from typing import Any
from uuid import UUID

import msgspec
from litestar import Request, get
from litestar.response import Response

from ads_commons.security import (
    AccessDenied,
    AuthenticationRequired,
    InvalidAccessToken,
    SecurityContextHolder,
)
from ads_commons_beans import JwtVerifier
from ads_sandbox_manager.binding import BindingService


@get("/v1/sandboxes/{sandbox_id:uuid}/binding")
async def binding(request: Request[Any, Any, Any], sandbox_id: UUID) -> Response[Any]:
    # Do not gate this endpoint on readiness: IPC startup needs the creating binding.
    container = request.app.state.container
    verifier = await container.get(JwtVerifier)
    service = await container.get(BindingService)
    authorization = request.headers.get("authorization", "")
    if not authorization.startswith("Bearer ") or not authorization[7:].strip():
        return Response({"error": "authentication required"}, status_code=401)
    try:
        context = await asyncio.to_thread(verifier.authenticate, authorization[7:])
        with SecurityContextHolder.bound(context):
            result = await service.get(sandbox_id)
    except (AuthenticationRequired, InvalidAccessToken):
        return Response({"error": "authentication required"}, status_code=401)
    except AccessDenied:
        return Response({"error": "access denied"}, status_code=403)
    if result is None:
        return Response({"error": "binding not found"}, status_code=404)
    return Response(msgspec.to_builtins(result))
