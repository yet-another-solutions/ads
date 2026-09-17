from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ads_mcp_probe import __version__
from ads_mcp_probe.tools import TOOLS, ToolArgumentError, tool_named

LATEST_PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_PROTOCOL_VERSIONS = frozenset({"2025-06-18", "2025-03-26"})
SERVER_NAME = "ads-mcp-probe"

JSON_RPC_PARSE_ERROR = -32700
JSON_RPC_INVALID_REQUEST = -32600
JSON_RPC_METHOD_NOT_FOUND = -32601
JSON_RPC_INVALID_PARAMS = -32602

INITIALIZE_METHOD = "initialize"
TOOL_CALL_METHOD = "tools/call"


def is_request(message: object) -> bool:
    return isinstance(message, Mapping) and "method" in message and "id" in message


def is_streaming_tool_call(message: object) -> bool:
    if not isinstance(message, Mapping) or not is_request(message):
        return False
    if message.get("method") != TOOL_CALL_METHOD:
        return False
    params = message.get("params")
    name = params.get("name") if isinstance(params, Mapping) else None
    tool = tool_named(name) if isinstance(name, str) else None
    return tool is not None and tool.streams


def answer(message: object) -> dict[str, Any] | None:
    if not isinstance(message, Mapping) or message.get("jsonrpc") != "2.0":
        return error(None, JSON_RPC_INVALID_REQUEST, "not a JSON-RPC 2.0 message")
    if not is_request(message):
        return None
    request_id = message["id"]
    method = message.get("method")
    params = message.get("params")
    arguments = params if isinstance(params, Mapping) else {}
    if method == INITIALIZE_METHOD:
        return result(request_id, _initialized(arguments))
    if method == "ping":
        return result(request_id, {})
    if method == "tools/list":
        return result(request_id, {"tools": [tool.listing() for tool in TOOLS]})
    if method == TOOL_CALL_METHOD:
        return _tool_call(request_id, arguments)
    return error(request_id, JSON_RPC_METHOD_NOT_FOUND, f"no method {method!r}")


def progress_notification(token: object, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "method": "notifications/progress",
        "params": {"progressToken": token, "progress": 0, "message": message},
    }


def result(request_id: object, value: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": value}


def error(request_id: object, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _initialized(params: Mapping[str, Any]) -> dict[str, Any]:
    asked = params.get("protocolVersion")
    version = asked if asked in SUPPORTED_PROTOCOL_VERSIONS else LATEST_PROTOCOL_VERSION
    return {
        "protocolVersion": version,
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": {"name": SERVER_NAME, "version": __version__},
    }


def _tool_call(request_id: object, params: Mapping[str, Any]) -> dict[str, Any]:
    name = params.get("name")
    tool = tool_named(name) if isinstance(name, str) else None
    if tool is None:
        return error(request_id, JSON_RPC_INVALID_PARAMS, f"no tool {name!r}")
    arguments = params.get("arguments") or {}
    if not isinstance(arguments, Mapping):
        return error(request_id, JSON_RPC_INVALID_PARAMS, "arguments must be an object")
    try:
        text = tool.answer(arguments)
    except ToolArgumentError as exc:
        return result(request_id, _text_content(str(exc), is_error=True))
    return result(request_id, _text_content(text, is_error=False))


def _text_content(text: str, *, is_error: bool) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": is_error}
