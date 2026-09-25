"""Authorized WebSocket transition, not a general CONNECT/tunnel dispatcher.

The original endpoints own frame encoding, masking, extension semantics and
Close frames. This intermediary never refragments, decompresses or interprets
application payloads. It can relay only after the request owner has checked
policy and both opening handshakes, and only on the same two owned legs.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import re

from ads_sandbox_egress.framing import Headers, forwarding_headers, validate_headers
from ads_sandbox_egress.http1 import HTTP1Channel
from ads_sandbox_egress.policy import RequestDenied

_TOKEN = rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+"
_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _one(headers: Headers, name: bytes) -> bytes:
    values = [v for n, v in headers if n == name]
    if len(values) != 1:
        raise RequestDenied("websocket_singleton_header")
    return values[0]


def _protocols(headers: Headers) -> tuple[bytes, ...]:
    values = tuple(
        item.strip()
        for name, value in headers
        if name == b"sec-websocket-protocol"
        for item in value.split(b",")
    )
    if any(re.fullmatch(_TOKEN, value) is None for value in values) or len(set(values)) != len(
        values
    ):
        raise RequestDenied("websocket_subprotocol")
    return values


def _extensions(headers: Headers) -> tuple[bytes, ...]:
    result = []
    for name, value in headers:
        if name != b"sec-websocket-extensions":
            continue
        # Quoted parameter values must unescape to tokens, so neither comma
        # nor semicolon is legal even inside their quoted representation.
        for part in value.split(b","):
            token, *parameters = (item.strip() for item in part.split(b";"))
            if re.fullmatch(_TOKEN, token) is None:
                raise RequestDenied("websocket_extension_syntax")
            for parameter in parameters:
                name, separator, value = parameter.partition(b"=")
                if re.fullmatch(_TOKEN, name.strip()) is None:
                    raise RequestDenied("websocket_extension_parameter")
                if separator:
                    value = value.strip()
                    if value.startswith(b'"'):
                        if re.fullmatch(rb'"(?:[^"\\\r\n]|\\.)*"', value) is None:
                            raise RequestDenied("websocket_extension_parameter")
                        value = re.sub(rb"\\(.)", rb"\1", value[1:-1])
                    if re.fullmatch(_TOKEN, value) is None:
                        raise RequestDenied("websocket_extension_parameter")
            result.append(token)
    return tuple(result)


def transition_headers(headers: Headers) -> Headers:
    fields = validate_headers(headers)
    tokens = tuple(
        item.strip().lower()
        for name, value in fields
        if name == b"connection"
        for item in value.split(b",")
    )
    if (
        _one(fields, b"upgrade").lower() != b"websocket"
        or b"upgrade" not in tokens
        or b"close" in tokens
        or any(token.startswith(b"sec-websocket-") for token in tokens)
    ):
        raise RequestDenied("websocket_upgrade_fields")
    return forwarding_headers(fields) + ((b"connection", b"Upgrade"), (b"upgrade", b"websocket"))


def request_headers(method: bytes, headers: Headers) -> Headers:
    fields = transition_headers(headers)
    if (
        method != b"GET"
        or _one(fields, b"sec-websocket-version") != b"13"
        or any(
            n == b"transfer-encoding" or n == b"content-length" and int(v) != 0 for n, v in headers
        )
        or any(n in (b"sec-websocket-accept", b"expect") for n, _ in headers)
    ):
        raise RequestDenied("websocket_opening_request")
    key = _one(fields, b"sec-websocket-key")
    try:
        nonce = base64.b64decode(key, validate=True)
    except (ValueError, binascii.Error):
        raise RequestDenied("websocket_key") from None
    if len(nonce) != 16 or base64.b64encode(nonce) != key:
        raise RequestDenied("websocket_key")
    _protocols(fields)
    _extensions(fields)
    return fields


def response_headers(request: Headers, response: Headers) -> Headers:
    fields = transition_headers(response)
    if any(
        n in (b"content-length", b"transfer-encoding", b"sec-websocket-key") for n, _ in response
    ):
        raise RequestDenied("websocket_opening_response")
    expected = base64.b64encode(hashlib.sha1(_one(request, b"sec-websocket-key") + _GUID).digest())
    if _one(fields, b"sec-websocket-accept") != expected:
        raise RequestDenied("websocket_accept")
    selected = _protocols(fields)
    if (
        len(selected) > 1
        or sum(n == b"sec-websocket-protocol" for n, _ in fields) > 1
        or any(value not in _protocols(request) for value in selected)
        or any(value not in _extensions(request) for value in _extensions(fields))
    ):
        raise RequestDenied("websocket_unoffered_negotiation")
    return fields


async def relay(front: HTTP1Channel, origin: HTTP1Channel, *, idle_timeout: float) -> None:
    """Bounded duplex byte preservation after a checked WebSocket handshake.

    No new destination, HTTP request, policy decision or extension transform is
    possible here. EOF ends both directions; errors/cancellation return to the
    request owner's reset-only custody. Progress in either direction keeps an
    otherwise idle receiving direction alive, but stalled writes stay bounded.
    """
    initial = (front.take_switched_data(), origin.take_switched_data())
    activity = asyncio.get_running_loop().time()

    async def copy(source: HTTP1Channel, target: HTTP1Channel, pending: bytes) -> None:
        nonlocal activity
        while True:
            data = pending or await source.reader.read(16384)
            pending = b""
            if not data:
                return
            # Parser leftovers are bounded, but can exceed a streaming chunk.
            for offset in range(0, len(data), 16384):
                target.writer.write(data[offset : offset + 16384])
                async with asyncio.timeout(idle_timeout):
                    await target.writer.drain()
                activity = asyncio.get_running_loop().time()

    async def idle() -> None:
        while True:
            remaining = activity + idle_timeout - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise RequestDenied("websocket_idle")
            await asyncio.sleep(remaining)

    tasks = {
        asyncio.create_task(copy(front, origin, initial[0])),
        asyncio.create_task(copy(origin, front, initial[1])),
        asyncio.create_task(idle()),
    }
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
