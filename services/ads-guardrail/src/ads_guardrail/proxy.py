from __future__ import annotations

import re
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from typing import Any

import aiohttp
import anyio.to_thread
import msgspec
import structlog

from ads_guardrail.config import Settings
from ads_guardrail.guardrail import Guardrail, Reading, RunNotOpen
from ads_policy.contract import PolicyDecision, Run

logger = structlog.get_logger("ads.guardrail")

#: The one method that is an action. Everything else — initialize, ping, tools/list,
#: resources, prompts — passes through unread: the less of the protocol this
#: understands, the less of it can break underneath us.
TOOL_CALL = "tools/call"

#: JSON-RPC's own code for a request the server refuses to act on.
INVALID_REQUEST = -32600

#: Where a message carries content: a response's result or error, a notification's or
#: a server request's params. The envelope around them — jsonrpc, id, method — is not
#: read and not rewritten.
CONTENT = ("result", "error", "params")

#: An event in a stream ends at a blank line, however the server spells its newlines.
EVENT_END = re.compile(rb"\r\n\r\n|\n\n|\r\r")

#: One event is one message, and a message has to be held whole to be read. A server
#: that never ends one would otherwise grow this without bound; the stream is cut
#: instead, because passing the rest unread would be a way around the check.
MAX_EVENT_BYTES = 16 * 1024 * 1024

SSE = "text/event-stream"

#: Belong to a connection, not to a message, so they do not cross the proxy either way.
#: ``accept-encoding`` too: the client library negotiates and undoes compression for
#: this hop itself, and the agent's own preference would leave bodies it cannot read.
HOP_BY_HOP = frozenset(
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
    """The path names an MCP server nobody put in the table."""


class UpstreamUnavailable(ConnectionError):
    """The MCP server could not be reached, or stopped answering."""


@dataclass(frozen=True, slots=True)
class Relayed:
    """What goes back to the agent. A stream is passed on as it arrives."""

    status: int
    headers: dict[str, str]
    body: bytes | AsyncIterator[bytes]

    @property
    def media_type(self) -> str:
        return self.headers.get("content-type", "application/json")


class Proxy:
    """Stands where the MCP servers used to be, in front of the real ones.

    Speaks MCP's Streamable HTTP transport: every message is a POST, answered with
    one JSON body or with an event stream; a GET opens a stream for what the server
    sends unasked; a DELETE ends a session. The session id and every other header go
    through untouched, so the agent and the server see each other as if nothing stood
    between them.

    An agent is pointed at ``/mcp/<name>`` instead of a server's own address, which is
    the entire installation: one URL per server in its configuration and nothing at all
    in its code. Remove the override and the guardrail is gone.
    """

    def __init__(self, settings: Settings, guardrail: Guardrail) -> None:
        self._settings = settings
        self._servers = dict(settings.mcp_servers or {})
        self._guardrail = guardrail
        wait = settings.mcp_timeout_seconds
        # No total: a tool may take long and say so in progress events. What is
        # bounded is silence — between bytes, and before the connection is made.
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=None, sock_connect=wait, sock_read=wait)
        )
        # A stream the agent opened to hear from the server may stay quiet for as long
        # as the server has nothing to say.
        self._listening = aiohttp.ClientTimeout(total=None, sock_connect=wait, sock_read=None)

    async def handle(
        self, method: str, server: str, body: bytes, headers: dict[str, str]
    ) -> Relayed:
        """What the agent should receive for one HTTP request to ``/mcp/<server>``."""
        upstream = self._servers.get(server)
        if upstream is None:
            raise UnknownServer(server)
        if method != "POST":
            # A GET listens, a DELETE hangs up: neither is an action to decide.
            return await self._relay(method, upstream, b"", headers)
        message = _decode(body)
        if isinstance(message, list):
            if any(_is_tool_call(item) for item in message):
                # A batch is a way to carry a call past the check inside something that
                # is not a call. The current protocol has dropped batches anyway.
                logger.info("batched tool call refused", server=server)
                return _json(_refuse_batch(message, self._guardrail.governance.denied_message))
            return await self._relay(method, upstream, body, headers)
        call = _tool_call(message)
        if call is None:
            return await self._relay(method, upstream, body, headers)
        tool, arguments, request_id = call
        try:
            # The policy client is synchronous and goes over the network; the event
            # loop carries every other agent's traffic meanwhile.
            run, decision = await anyio.to_thread.run_sync(
                self._decide,
                _bearer(headers),
                headers.get(self._settings.run_header, ""),
                # The server's name is the source bindings know it by: two servers may
                # both offer `search`, and they need not mean the same thing by it.
                f"mcp:{server}",
                tool,
                arguments,
            )
        except RunNotOpen as exc:
            logger.info("tool call belongs to no run", server=server, tool=tool, reason=str(exc))
            return _json(_refuse(request_id, self._guardrail.governance.denied_message))
        if not decision.permitted:
            logger.info("tool call refused", server=server, tool=tool, rule_id=decision.rule_id)
            # The agent is told what it may do instead, never where the wall is.
            return _json(_refuse(request_id, decision.message))
        response = await self._open(method, upstream, body, headers)
        relayed = _headers(response)
        if response.content_type == SSE:
            events = self._read_stream(response, run, decision)
            return Relayed(response.status, relayed, events)
        try:
            answer = await response.read()
        except aiohttp.ClientError as exc:
            raise UpstreamUnavailable(str(exc)) from exc
        finally:
            response.release()
        if not answer:
            return Relayed(response.status, relayed, answer)
        return Relayed(response.status, relayed, self._read_message(run, decision, answer))

    def _decide(
        self, bearer: str, named: str, source: str, tool: str, arguments: dict[str, str]
    ) -> tuple[Run, PolicyDecision]:
        run = self._guardrail.find(bearer, named)
        return run, self._guardrail.permit(run, source, tool, arguments)

    async def close(self) -> None:
        await self._session.close()

    async def _relay(
        self, method: str, upstream: str, body: bytes, headers: dict[str, str]
    ) -> Relayed:
        """Carry a request that decides nothing, and its answer, through as they are."""
        response = await self._open(method, upstream, body, headers)
        return Relayed(response.status, _headers(response), _passed_on(response))

    async def _open(
        self, method: str, upstream: str, body: bytes, headers: dict[str, str]
    ) -> aiohttp.ClientResponse:
        timeout = self._listening if method == "GET" else None
        try:
            return await self._session.request(
                method,
                upstream,
                data=body or None,
                headers=self._forwardable(headers),
                timeout=timeout,
            )
        except aiohttp.ClientError as exc:
            raise UpstreamUnavailable(str(exc)) from exc

    def _forwardable(self, headers: dict[str, str]) -> dict[str, str]:
        """The agent's headers, less the connection's and less our own run header."""
        ours = self._settings.run_header
        return {
            name: value
            for name, value in headers.items()
            if name.lower() not in HOP_BY_HOP and name.lower() != ours
        }

    async def _read_stream(
        self, response: aiohttp.ClientResponse, run: Run, decision: PolicyDecision
    ) -> AsyncIterator[bytes]:
        """Each event as it completes, read. Progress reaches the agent as it happens.

        An event is a whole message, so its end is a natural place to read: nothing is
        split across two reads and no window has to be carried between them.
        """
        pending = b""
        try:
            async for chunk in response.content.iter_any():
                events, pending = _split_events(pending + chunk)
                for event in events:
                    yield self._read_event(event, run, decision)
                if len(pending) > MAX_EVENT_BYTES:
                    logger.warning("stream cut: an event outgrew the limit", size=len(pending))
                    return
            if pending:
                yield self._read_event(pending, run, decision)
        except aiohttp.ClientError as exc:
            logger.warning("stream from the MCP server broke off", error=str(exc))
        finally:
            response.release()

    def _read_event(self, event: bytes, run: Run, decision: PolicyDecision) -> bytes:
        """One event, with its data read as a message and every other field kept."""
        lines = event.splitlines()
        data = [_field_value(line) for line in lines if line.startswith(b"data:")]
        if not data:
            return event
        payload = b"\n".join(data)
        read = self._read_message(run, decision, payload)
        if read is payload:
            return event
        kept = [line for line in lines if not line.startswith(b"data:")]
        return b"\n".join([*kept, b"data: " + read]) + b"\n\n"

    def _read_message(self, run: Run, decision: PolicyDecision, payload: bytes) -> bytes:
        """A message as the agent should get it; ``payload`` itself when nothing changed.

        The strings inside are read, not the JSON text: an escaped secret is found, and
        cutting one out cannot break the document around it. Something that is not JSON
        at all is still read — as one text, since there is nothing to take apart.
        """
        message = _decode(payload)
        if message is None:
            text = payload.decode("utf-8", errors="replace")
            reading = self._inspect(run, decision, [text])
            return payload if reading.texts == (text,) else reading.texts[0].encode("utf-8")
        messages = message if isinstance(message, list) else [message]
        texts = [
            text
            for item in messages
            if isinstance(item, dict)
            for key in CONTENT
            if key in item
            for text in _strings(item[key])
        ]
        if not texts:
            return payload
        reading = self._inspect(run, decision, texts)
        if reading.texts == tuple(texts):
            return payload
        replacements = iter(reading.texts)
        for item in messages:
            if isinstance(item, dict):
                for key in CONTENT:
                    if key in item:
                        item[key] = _replaced(item[key], replacements)
        return msgspec.json.encode(message)

    def _inspect(self, run: Run, decision: PolicyDecision, texts: list[str]) -> Reading:
        reading = self._guardrail.inspect_result(run, decision, texts)
        found = reading.decision
        if found.warnings:
            logger.warning("tool result carries a signal", warnings=list(found.warnings))
        if found.transform is not None and reading.texts != tuple(texts):
            logger.info("tool result redacted", redactions=list(found.transform.redactions))
        return reading


async def _passed_on(response: aiohttp.ClientResponse) -> AsyncIterator[bytes]:
    try:
        async for chunk in response.content.iter_any():
            yield chunk
    except aiohttp.ClientError as exc:
        logger.warning("stream from the MCP server broke off", error=str(exc))
    finally:
        response.release()


def _split_events(buffer: bytes) -> tuple[list[bytes], bytes]:
    """The finished events in ``buffer``, and the unfinished rest."""
    events: list[bytes] = []
    while match := EVENT_END.search(buffer):
        events.append(buffer[: match.end()])
        buffer = buffer[match.end() :]
    return events, buffer


def _field_value(line: bytes) -> bytes:
    """The value of an SSE field: after the colon, less one space if there is one."""
    value = line.split(b":", 1)[1]
    return value[1:] if value.startswith(b" ") else value


def _bearer(headers: dict[str, str]) -> str:
    """The credential the call arrived with, as its run was bound to it."""
    scheme, _, credential = headers.get("authorization", "").partition(" ")
    return credential.strip() if scheme.lower() == "bearer" else ""


def _headers(response: aiohttp.ClientResponse) -> dict[str, str]:
    """The server's headers — the session id among them — less the connection's."""
    return {
        name.lower(): value
        for name, value in response.headers.items()
        if name.lower() not in HOP_BY_HOP
    }


def _decode(body: bytes) -> Any:
    """The JSON in ``body``, or None. Unparseable is the real server's to answer for."""
    try:
        return msgspec.json.decode(body)
    except msgspec.DecodeError:
        return None


def _is_tool_call(message: Any) -> bool:
    return isinstance(message, dict) and message.get("method") == TOOL_CALL


def _tool_call(message: Any) -> tuple[str, dict[str, str], Any] | None:
    """The tool, its arguments and the id to answer with — or nothing to act on."""
    if not _is_tool_call(message):
        return None
    params = message.get("params")
    if not isinstance(params, dict):
        return None
    name = params.get("name")
    if not isinstance(name, str) or not name:
        return None
    raw = params.get("arguments")
    arguments = {str(k): _flatten(v) for k, v in raw.items()} if isinstance(raw, dict) else {}
    return name, arguments, message.get("id")


def _flatten(value: Any) -> str:
    """Arguments are read as text, so a nested one is read as the JSON it is."""
    if isinstance(value, str):
        return value
    return msgspec.json.encode(value).decode("utf-8")


def _strings(node: Any) -> Iterator[str]:
    """Every string value under ``node``, depth first. Keys are names, not content."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from _strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from _strings(value)


def _replaced(node: Any, replacements: Iterator[str]) -> Any:
    """``node`` with its strings taken from ``replacements``, in ``_strings`` order."""
    if isinstance(node, str):
        return next(replacements)
    if isinstance(node, dict):
        return {key: _replaced(value, replacements) for key, value in node.items()}
    if isinstance(node, list):
        return [_replaced(value, replacements) for value in node]
    return node


def _json(body: bytes) -> Relayed:
    return Relayed(200, {"content-type": "application/json"}, body)


def _refuse(request_id: Any, message: str) -> bytes:
    """A refusal the agent can act on: its own protocol, not a transport error.

    A 403 would read to the agent as the server being broken, and it would retry. An
    error in the JSON-RPC envelope reads as "this call is not available", which is
    what happened.
    """
    return msgspec.json.encode(_error(request_id, message))


def _refuse_batch(messages: list[Any], message: str) -> bytes:
    """One error for every request in the batch; notifications are answered by nobody."""
    return msgspec.json.encode(
        [
            _error(item["id"], message)
            for item in messages
            if isinstance(item, dict) and "id" in item and "method" in item
        ]
    )


def _error(request_id: Any, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": INVALID_REQUEST, "message": message},
    }
