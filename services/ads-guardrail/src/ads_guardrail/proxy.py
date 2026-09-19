from __future__ import annotations

import re
import ssl
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from typing import Any

import aiohttp
import anyio.to_thread
import msgspec
import structlog

from ads_guardrail.config import Settings
from ads_guardrail.contract import McpServer
from ads_guardrail.guardrail import Guardrail, Reading, RunNotOpen
from ads_guardrail.scanner import InjectionScan, InjectionScanner
from ads_policy.contract import (
    CheckKind,
    InterceptionPoint,
    PolicyDecision,
    Run,
    Switch,
    string_values,
)
from ads_policy.output import PROMPT_INJECTION_RULE

logger = structlog.get_logger("ads.guardrail")

TOOL_CALL_METHOD = "tools/call"
REFUSED_BY = "ads-guardrail"
REFUSED_BY_POLICY = "policy"
REFUSED_FOR_PROMPT_INJECTION = "prompt-injection"
JSON_RPC_INVALID_REQUEST = -32600
MESSAGE_CONTENT_KEYS = ("result", "error", "params")
SSE_EVENT_END = re.compile(rb"\r\n\r\n|\n\n|\r\r")
MAX_EVENT_BYTES = 16 * 1024 * 1024
SSE_MEDIA_TYPE = "text/event-stream"
HEADERS_NOT_FORWARDED = frozenset(
    {
        "host",
        "connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "proxy-authorization",
        "proxy-connection",
        "content-length",
        "content-encoding",
        "accept-encoding",
    }
)


class UnknownServer(LookupError):
    pass


class UpstreamUnavailable(ConnectionError):
    pass


@dataclass(frozen=True, slots=True)
class Relayed:
    status: int
    headers: dict[str, str]
    body: bytes | AsyncIterator[bytes]

    @property
    def media_type(self) -> str:
        return self.headers.get("content-type", "application/json")


class Proxy:
    def __init__(
        self, settings: Settings, guardrail: Guardrail, injection_scanner: InjectionScanner
    ) -> None:
        self._settings = settings
        self._servers_by_name = {server.name: server for server in settings.mcp_servers}
        self._guardrail = guardrail
        self._injection_scanner = injection_scanner
        silence_limit = settings.mcp_timeout_seconds
        self._session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=_upstream_tls(settings)),
            timeout=aiohttp.ClientTimeout(
                total=None, sock_connect=silence_limit, sock_read=silence_limit
            ),
        )
        self._listening_stream_timeout = aiohttp.ClientTimeout(
            total=None, sock_connect=silence_limit, sock_read=None
        )

    async def handle(
        self, method: str, server_name: str, body: bytes, headers: dict[str, str]
    ) -> Relayed:
        server = self._servers_by_name.get(server_name)
        if server is None:
            raise UnknownServer(server_name)
        if method != "POST":
            return await self._relay_unchanged(method, server, b"", headers)
        message = _json_or_none(body)
        if isinstance(message, list):
            if any(_is_tool_call(item) for item in message):
                logger.info("batched tool call refused", server=server.name)
                denied = self._guardrail.inspection.denied_message
                return _json_response(_refusals_for_batch(message, denied))
            return await self._relay_unchanged(method, server, body, headers)
        call = _tool_call_parts(message)
        if call is None:
            return await self._relay_unchanged(method, server, body, headers)
        tool, arguments, request_id = call
        try:
            run, decision = await anyio.to_thread.run_sync(
                self._find_run_and_decide,
                _bearer_of(headers),
                headers.get(self._settings.run_header, ""),
                server,
                tool,
                arguments,
            )
        except RunNotOpen as exc:
            logger.info(
                "tool call belongs to no run", server=server.name, tool=tool, reason=str(exc)
            )
            return _json_response(_refusal(request_id, self._guardrail.inspection.denied_message))
        if not decision.permitted:
            logger.info(
                "tool call refused", server=server.name, tool=tool, rule_id=decision.rule_id
            )
            return _json_response(
                _refusal(
                    request_id,
                    decision.message,
                    alternative=self._alternative_in(decision.message),
                )
            )
        response = await self._send_upstream(method, server, body, headers)
        response_headers = _forwarded_response_headers(response)
        if response.content_type == SSE_MEDIA_TYPE:
            events = self._inspected_event_stream(response, run, decision)
            return Relayed(response.status, response_headers, events)
        try:
            answer = await response.read()
        except aiohttp.ClientError as exc:
            raise UpstreamUnavailable(str(exc)) from exc
        finally:
            response.release()
        if not answer:
            return Relayed(response.status, response_headers, answer)
        inspected = await self._inspected_message(run, decision, answer)
        return Relayed(response.status, response_headers, inspected)

    async def close(self) -> None:
        await self._session.close()

    def _alternative_in(self, message: str) -> str:
        return "" if message == self._guardrail.inspection.denied_message else message

    def _find_run_and_decide(
        self,
        bearer: str,
        named_run_id: str,
        server: McpServer,
        tool: str,
        arguments: dict[str, Any],
    ) -> tuple[Run, PolicyDecision]:
        run = self._guardrail.find_run_of_caller(bearer, named_run_id)
        decision = self._guardrail.decide_tool_call(
            run, f"mcp:{server.name}", tool, arguments, site=server.site
        )
        return run, decision

    async def _relay_unchanged(
        self, method: str, server: McpServer, body: bytes, headers: dict[str, str]
    ) -> Relayed:
        response = await self._send_upstream(method, server, body, headers)
        return Relayed(
            response.status, _forwarded_response_headers(response), _passed_through(response)
        )

    async def _send_upstream(
        self, method: str, server: McpServer, body: bytes, headers: dict[str, str]
    ) -> aiohttp.ClientResponse:
        timeout = self._listening_stream_timeout if method == "GET" else None
        try:
            return await self._session.request(
                method,
                server.url,
                data=body or None,
                headers=self._forwarded_request_headers(headers),
                timeout=timeout,
            )
        except aiohttp.ClientError as exc:
            raise UpstreamUnavailable(str(exc)) from exc

    def _forwarded_request_headers(self, headers: dict[str, str]) -> dict[str, str]:
        run_header = self._settings.run_header
        return {
            name: value
            for name, value in headers.items()
            if name.lower() not in HEADERS_NOT_FORWARDED and name.lower() != run_header
        }

    async def _inspected_event_stream(
        self, response: aiohttp.ClientResponse, run: Run, decision: PolicyDecision
    ) -> AsyncIterator[bytes]:
        unfinished = b""
        try:
            async for chunk in response.content.iter_any():
                events, unfinished = _complete_events_and_rest(unfinished + chunk)
                for event in events:
                    if inspected := await self._inspected_event(event, run, decision):
                        yield inspected
                if len(unfinished) > MAX_EVENT_BYTES:
                    logger.warning("stream cut: an event outgrew the limit", size=len(unfinished))
                    return
            if unfinished and (inspected := await self._inspected_event(unfinished, run, decision)):
                yield inspected
        except aiohttp.ClientError as exc:
            logger.warning("stream from the MCP server broke off", error=str(exc))
        finally:
            response.release()

    async def _inspected_event(self, event: bytes, run: Run, decision: PolicyDecision) -> bytes:
        lines = event.splitlines()
        data = [_sse_field_value(line) for line in lines if line.startswith(b"data:")]
        if not data:
            return event
        payload = b"\n".join(data)
        inspected = await self._inspected_message(run, decision, payload)
        if inspected is payload:
            return event
        if not inspected:
            return b""
        other_fields = [line for line in lines if not line.startswith(b"data:")]
        return b"\n".join([*other_fields, b"data: " + inspected]) + b"\n\n"

    async def _inspected_message(self, run: Run, decision: PolicyDecision, payload: bytes) -> bytes:
        message = _json_or_none(payload)
        if message is None:
            text = payload.decode("utf-8", errors="replace")
            reading = await self._read_tool_result(run, decision, [text])
            if reading.withheld:
                return _refusal(None, reading.decision.message, _refusal_reason(reading))
            return payload if reading.texts == (text,) else reading.texts[0].encode("utf-8")
        messages = message if isinstance(message, list) else [message]
        texts = [
            text
            for item in messages
            if isinstance(item, dict)
            for key in MESSAGE_CONTENT_KEYS
            if key in item
            for text in string_values(item[key])
        ]
        if not texts:
            return payload
        reading = await self._read_tool_result(run, decision, texts)
        if reading.withheld:
            return _withheld(message, reading)
        if reading.texts == tuple(texts):
            return payload
        replacements = iter(reading.texts)
        for item in messages:
            if isinstance(item, dict):
                for key in MESSAGE_CONTENT_KEYS:
                    if key in item:
                        item[key] = _with_string_values_replaced(item[key], replacements)
        return msgspec.json.encode(message)

    async def _read_tool_result(
        self, run: Run, decision: PolicyDecision, texts: list[str]
    ) -> Reading:
        injection_scan = await self._injection_scan_if_asked(decision, texts)
        reading = await anyio.to_thread.run_sync(
            self._guardrail.inspect_tool_result, run, decision, texts, injection_scan
        )
        found = reading.decision
        if reading.withheld:
            logger.warning("tool result withheld", rule_id=found.rule_id, reason=found.reason)
        elif found.transform is not None and reading.texts != tuple(texts):
            logger.info("tool result redacted", redactions=list(found.transform.redactions))
        return reading

    async def _injection_scan_if_asked(
        self, decision: PolicyDecision, texts: list[str]
    ) -> InjectionScan | None:
        inbound = decision.interception.side(InterceptionPoint.RESPONSE)
        if inbound.switch_for(CheckKind.INJECTION) is Switch.OFF:
            return None
        return await self._injection_scanner.scan(texts)


async def _passed_through(response: aiohttp.ClientResponse) -> AsyncIterator[bytes]:
    try:
        async for chunk in response.content.iter_any():
            yield chunk
    except aiohttp.ClientError as exc:
        logger.warning("stream from the MCP server broke off", error=str(exc))
    finally:
        response.release()


def _complete_events_and_rest(buffer: bytes) -> tuple[list[bytes], bytes]:
    events: list[bytes] = []
    while match := SSE_EVENT_END.search(buffer):
        events.append(buffer[: match.end()])
        buffer = buffer[match.end() :]
    return events, buffer


def _sse_field_value(line: bytes) -> bytes:
    value = line.split(b":", 1)[1]
    return value[1:] if value.startswith(b" ") else value


def _upstream_tls(settings: Settings) -> ssl.SSLContext | bool:
    if settings.tls_ca_bundle is None:
        return True
    return ssl.create_default_context(cafile=str(settings.tls_ca_bundle))


def _bearer_of(headers: dict[str, str]) -> str:
    scheme, _, credential = headers.get("authorization", "").partition(" ")
    return credential.strip() if scheme.lower() == "bearer" else ""


def _forwarded_response_headers(response: aiohttp.ClientResponse) -> dict[str, str]:
    return {
        name.lower(): value
        for name, value in response.headers.items()
        if name.lower() not in HEADERS_NOT_FORWARDED
    }


def _json_or_none(body: bytes) -> Any:
    try:
        return msgspec.json.decode(body)
    except msgspec.DecodeError:
        return None


def _is_tool_call(message: Any) -> bool:
    return isinstance(message, dict) and message.get("method") == TOOL_CALL_METHOD


def _tool_call_parts(message: Any) -> tuple[str, dict[str, Any], Any] | None:
    if not _is_tool_call(message):
        return None
    params = message.get("params")
    if not isinstance(params, dict):
        return None
    name = params.get("name")
    if not isinstance(name, str) or not name:
        return None
    raw = params.get("arguments")
    arguments = {str(key): value for key, value in raw.items()} if isinstance(raw, dict) else {}
    return name, arguments, message.get("id")


def _with_string_values_replaced(node: Any, replacements: Iterator[str]) -> Any:
    if isinstance(node, str):
        return next(replacements)
    if isinstance(node, dict):
        return {
            key: _with_string_values_replaced(value, replacements) for key, value in node.items()
        }
    if isinstance(node, list):
        return [_with_string_values_replaced(value, replacements) for value in node]
    return node


def _json_response(body: bytes) -> Relayed:
    return Relayed(200, {"content-type": "application/json"}, body)


def _refusal(
    request_id: Any, message: str, reason: str = REFUSED_BY_POLICY, alternative: str = ""
) -> bytes:
    return msgspec.json.encode(_json_rpc_error(request_id, message, reason, alternative))


def _refusals_for_batch(messages: list[Any], message: str) -> bytes:
    return msgspec.json.encode(
        [
            _json_rpc_error(item["id"], message, REFUSED_BY_POLICY)
            for item in messages
            if isinstance(item, dict) and "id" in item and "method" in item
        ]
    )


def _json_rpc_error(
    request_id: Any, message: str, reason: str, alternative: str = ""
) -> dict[str, Any]:
    data = {"refused_by": REFUSED_BY, "reason": reason}
    if alternative:
        data["alternative"] = alternative
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": JSON_RPC_INVALID_REQUEST, "message": message, "data": data},
    }


def _refusal_reason(reading: Reading) -> str:
    if reading.decision.rule_id == PROMPT_INJECTION_RULE:
        return REFUSED_FOR_PROMPT_INJECTION
    return REFUSED_BY_POLICY


def _withheld(message: Any, reading: Reading) -> bytes:
    items = message if isinstance(message, list) else [message]
    answers = [
        _json_rpc_error(item.get("id"), reading.decision.message, _refusal_reason(reading))
        for item in items
        if isinstance(item, dict) and ("result" in item or "error" in item)
    ]
    if not answers:
        return b""
    return msgspec.json.encode(answers if isinstance(message, list) else answers[0])
