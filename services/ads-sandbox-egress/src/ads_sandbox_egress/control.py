from __future__ import annotations

import asyncio
from typing import Any

import msgspec
from dishka.integrations.litestar import FromDishka, inject
from litestar import Request, get, put
from litestar.response import Response

from ads_commons.egress import EgressApply, EgressStale, EgressStaleResponse
from ads_commons.security import (
    AccessDenied,
    AuthenticationRequired,
    InvalidAccessToken,
    SecurityContextHolder,
)
from ads_commons_beans import JwtVerifier
from ads_sandbox_egress.anchor import AnchorService
from ads_sandbox_egress.configuration import (
    ConfigurationService,
    ConfigurationUnavailable,
    RevisionConflict,
    StaleConfiguration,
)


def error(code: str, status: int) -> Response[Any]:
    return Response({"error": {"code": code}}, status_code=status)


@put("/configuration", status_code=200)
@inject
async def configure(
    request: Request[Any, Any, Any],
    verifier: FromDishka[JwtVerifier],
    service: FromDishka[ConfigurationService],
) -> Response[Any]:
    authorization = request.headers.get("authorization", "")
    if not authorization.startswith("Bearer ") or not authorization[7:].strip():
        return error("authentication_required", 401)
    try:
        context = await asyncio.to_thread(verifier.authenticate, authorization[7:])
        body = msgspec.json.decode(await request.body(), type=EgressApply)
        with SecurityContextHolder.bound(context):
            applied = await service.apply(body)
        return Response(msgspec.to_builtins(applied), status_code=200)
    except (AuthenticationRequired, InvalidAccessToken):
        return error("authentication_required", 401)
    except AccessDenied:
        return error("access_denied", 403)
    except msgspec.DecodeError:
        return error("invalid_configuration", 400)
    except StaleConfiguration as exc:
        return Response(
            msgspec.to_builtins(
                EgressStaleResponse(EgressStale("stale_revision", exc.received, exc.applied))
            ),
            status_code=409,
        )
    except RevisionConflict:
        return error("revision_conflict", 409)
    except ConfigurationUnavailable:
        return error("configuration_unavailable", 503)


@get("/ping")
@inject
async def ping(service: FromDishka[ConfigurationService]) -> Response[Any]:
    result = await service.ping()
    return Response(msgspec.to_builtins(result), status_code=200 if result.healthy else 503)


@get("/dnssec-anchor")
@inject
async def anchor(
    request: Request[Any, Any, Any],
    verifier: FromDishka[JwtVerifier],
    service: FromDishka[AnchorService],
) -> Response[Any]:
    authorization = request.headers.get("authorization", "")
    if not authorization.startswith("Bearer ") or not authorization[7:].strip():
        return error("authentication_required", 401)
    try:
        context = await asyncio.to_thread(verifier.authenticate, authorization[7:])
        with SecurityContextHolder.bound(context):
            result = service.get()
        return Response(msgspec.to_builtins(result), status_code=200)
    except (AuthenticationRequired, InvalidAccessToken):
        return error("authentication_required", 401)
    except AccessDenied:
        return error("access_denied", 403)
    except ConfigurationUnavailable:
        return error("configuration_unavailable", 503)
