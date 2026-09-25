"""Independently terminated HTTP/1-to-H2 upgrade handshake state."""

from __future__ import annotations

from dataclasses import dataclass

from ads_sandbox_egress.framing import Headers, forwarding_headers
from ads_sandbox_egress.http2 import HTTP2Connection
from ads_sandbox_egress.policy import RequestDenied
from ads_sandbox_egress.request_authorization import RequestHead


@dataclass(frozen=True)
class Upgrade:
    frontend: HTTP2Connection
    origin: HTTP2Connection
    headers: Headers


def prepare(head: RequestHead, serialized: Headers) -> Upgrade:
    if head.upgrade != "http/2" or head.sub_protocol != "http/1.1":
        raise RequestDenied("h2c_request_required")
    settings = [v for n, v in head.headers if n == b"http2-settings"]
    if len(settings) != 1:
        raise RequestDenied("h2c_settings_required")
    frontend = HTTP2Connection(client=False)
    frontend.upgraded(head.method, settings[0])
    origin = HTTP2Connection(client=True)
    offered = origin.upgraded(head.method)
    assert offered is not None
    # The client's SETTINGS describe the frontend leg, not the separately
    # terminated origin leg. Never misadvertise them as the proxy's settings.
    headers = tuple((n, v) for n, v in serialized if n != b"http2-settings") + (
        (b"connection", b"Upgrade, HTTP2-Settings"),
        (b"upgrade", b"h2c"),
        (b"http2-settings", offered),
    )
    return Upgrade(frontend, origin, headers)


def response_headers(headers: Headers) -> Headers:
    upgrades = [v.lower() for n, v in headers if n == b"upgrade"]
    tokens = {
        item.strip().lower()
        for name, value in headers
        if name == b"connection"
        for item in value.split(b",")
    }
    if (
        upgrades != [b"h2c"]
        or b"upgrade" not in tokens
        or b"close" in tokens
        or any(
            n in (b"content-length", b"transfer-encoding", b"http2-settings") for n, _ in headers
        )
    ):
        raise RequestDenied("h2c_response_transition")
    return forwarding_headers(headers) + ((b"connection", b"Upgrade"), (b"upgrade", b"h2c"))
