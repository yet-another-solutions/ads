from __future__ import annotations

from typing import Annotated, Any

import msgspec
from mcp import types
from mcp.server.context import ServerRequestContext
from mcp.shared.exceptions import MCPError

from ads_commons.sandbox.handshake import SandboxExecKind
from ads_commons.security import require_caller
from ads_sandbox_mcp.config import Settings
from ads_sandbox_mcp.service import ExecService

NonEmpty = Annotated[str, msgspec.Meta(min_length=1)]


class ShellArgs(msgspec.Struct, forbid_unknown_fields=True):
    command: NonEmpty


class PythonArgs(msgspec.Struct, forbid_unknown_fields=True):
    code: NonEmpty


def _tool(name: str, argument: str, description: str) -> types.Tool:
    return types.Tool(
        name=name,
        description=description,
        input_schema={
            "type": "object",
            "properties": {argument: {"type": "string", "minLength": 1}},
            "required": [argument],
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "properties": {
                "exit_code": {"type": "integer"},
                "stdout": {"type": "string"},
                "stderr": {"type": "string"},
                "truncated": {"type": "boolean"},
                "duration_ms": {"type": "integer"},
            },
            "required": ["exit_code", "stdout", "stderr", "truncated", "duration_ms"],
            "additionalProperties": False,
        },
    )


TOOLS = [
    _tool("exec_shell", "command", "Run a verbatim bash command in the session workspace."),
    _tool("exec_python", "code", "Run Python code on stdin in the session workspace."),
]


def _cap(text: str, limit: int) -> tuple[str, bool]:
    raw = text.encode("utf-8")
    return raw[:limit].decode("utf-8", errors="ignore"), len(raw) > limit


class ToolController:
    """Official SDK callbacks, not another JSON-RPC dispatcher."""

    def __init__(self, service: ExecService, settings: Settings) -> None:
        self._service = service
        self._settings = settings

    @require_caller("ads-engine")
    async def list_tools(
        self, ctx: ServerRequestContext[Any], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        return types.ListToolsResult(tools=TOOLS)

    @require_caller("ads-engine")
    async def call_tool(
        self, ctx: ServerRequestContext[Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        kind: SandboxExecKind
        try:
            if params.name == "exec_shell":
                payload = msgspec.convert(params.arguments, type=ShellArgs).command
                kind = "shell"
            elif params.name == "exec_python":
                payload = msgspec.convert(params.arguments, type=PythonArgs).code
                kind = "python"
            else:
                raise ValueError("unknown tool")
            if len(payload.encode("utf-8")) > self._settings.input_bytes:
                raise ValueError("tool input exceeds configured byte cap")
        except (msgspec.ValidationError, ValueError, TypeError) as exc:
            raise MCPError(-32602, "invalid tool arguments") from exc
        result = await self._service.execute(kind, payload)
        stdout, out_cut = _cap(result.stdout, self._settings.stdout_bytes)
        stderr, err_cut = _cap(result.stderr, self._settings.stderr_bytes)
        structured = {
            "exit_code": result.exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "truncated": result.truncated or out_cut or err_cut,
            "duration_ms": result.duration_ms,
        }
        # Text mirrors the bounded structured result; never leak uncapped output in content.
        text = msgspec.json.encode(structured).decode()
        if result.is_error:
            detail, _ = _cap(result.text, self._settings.stderr_bytes)
            text = f"{detail or 'sandbox execution failed'}\n{text}"
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=text)],
            structured_content=structured,
            is_error=result.is_error,
        )
