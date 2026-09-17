from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from typing import Any

import msgspec
import structlog
from litestar import Litestar, Request, Response, delete, get, post
from litestar.response import Stream

from ads_mcp_probe.protocol import (
    INITIALIZE_METHOD,
    JSON_RPC_PARSE_ERROR,
    answer,
    error,
    is_request,
    is_streaming_tool_call,
    progress_notification,
)

logger = structlog.get_logger("ads.mcp_probe")

MCP_PATH = "/mcp"
SESSION_HEADER = "mcp-session-id"
JSON_MEDIA_TYPE = "application/json"
SSE_MEDIA_TYPE = "text/event-stream"


@post(MCP_PATH, status_code=200)
async def receive(request: Request[Any, Any, Any]) -> Response[Any]:
    try:
        message = msgspec.json.decode(await request.body())
    except msgspec.DecodeError:
        return _json(error(None, JSON_RPC_PARSE_ERROR, "body is not JSON"), status=400)
    if isinstance(message, list):
        answers = [reply for item in message if (reply := answer(item)) is not None]
        return _json(answers) if answers else Response(content=b"", status_code=202)
    if is_streaming_tool_call(message) and SSE_MEDIA_TYPE in request.headers.get("accept", ""):
        return Stream(
            _events_answering(message),
            media_type=SSE_MEDIA_TYPE,
            headers={"cache-control": "no-cache"},
        )
    reply = answer(message)
    if reply is None:
        return Response(content=b"", status_code=202)
    headers = {}
    if is_request(message) and message.get("method") == INITIALIZE_METHOD:
        headers[SESSION_HEADER] = uuid.uuid4().hex
        logger.info(
            "session started",
            session=headers[SESSION_HEADER],
            carries_authorization="authorization" in request.headers,
        )
    return _json(reply, headers=headers)


@get(MCP_PATH)
async def listen() -> Response[Any]:
    return Response(content=b"", status_code=405, headers={"allow": "POST, DELETE"})


@delete(MCP_PATH, status_code=200)
async def end_session() -> None:
    return None


@get("/health/live", sync_to_thread=False)
def live() -> dict[str, str]:
    return {"status": "ok"}


@get("/health/ready", sync_to_thread=False)
def ready() -> dict[str, str]:
    return {"status": "ok"}


async def _events_answering(message: Any) -> AsyncIterator[bytes]:
    yield _event(progress_notification(message["id"], "probe: streaming"))
    reply = answer(message)
    if reply is not None:
        yield _event(reply, event_id="1")


def _event(payload: Any, event_id: str | None = None) -> bytes:
    lines = [] if event_id is None else [f"id: {event_id}"]
    lines += ["event: message", f"data: {msgspec.json.encode(payload).decode()}"]
    return ("\n".join(lines) + "\n\n").encode()


def _json(payload: Any, status: int = 200, headers: dict[str, str] | None = None) -> Response[Any]:
    return Response(
        content=msgspec.json.encode(payload),
        status_code=status,
        media_type=JSON_MEDIA_TYPE,
        headers=headers or {},
    )


def create_app() -> Litestar:
    return Litestar(route_handlers=[receive, listen, end_session, live, ready])
