"""Strict framing gates applied BEFORE a protocol parser normalizes headers."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from ads_sandbox_egress.policy import RequestDenied

Headers = tuple[tuple[bytes, bytes], ...]
_TOKEN = re.compile(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_FORBIDDEN_TRAILERS = frozenset(
    (
        b"host",
        b"authorization",
        b"proxy-authorization",
        b"content-length",
        b"transfer-encoding",
        b"connection",
        b"te",
        b"trailer",
        b"upgrade",
        b"expect",
        b"content-encoding",
        b"content-type",
        b"content-range",
        b"cookie",
        b"set-cookie",
        b"proxy-authenticate",
        b"www-authenticate",
    )
)
_HOP_BY_HOP = frozenset(
    (b"connection", b"keep-alive", b"proxy-connection", b"transfer-encoding", b"upgrade")
)


def validate_headers(headers: Iterable[tuple[bytes, bytes]], *, h2: bool = False) -> Headers:
    result: list[tuple[bytes, bytes]] = []
    total = 0
    regular_seen = False
    pseudo: set[bytes] = set()
    for name, value in headers:
        total += len(name) + len(value) + 4
        if len(result) >= 128 or total > 65536 or len(name) > 256 or len(value) > 16384:
            raise RequestDenied("header_limit")
        if not name or any(char < 32 and char != 9 or char == 127 for char in value):
            raise RequestDenied("invalid_header")
        if h2 and name != name.lower():
            raise RequestDenied("uppercase_h2_header")
        name = name.lower()
        if name.startswith(b":"):
            if (
                not h2
                or regular_seen
                or name in pseudo
                or name
                not in (b":method", b":scheme", b":authority", b":path", b":status", b":protocol")
            ):
                raise RequestDenied("invalid_pseudo_header")
            pseudo.add(name)
        else:
            regular_seen = True
            if not _TOKEN.fullmatch(name):
                raise RequestDenied("invalid_header_name")
        if h2 and (name in _HOP_BY_HOP or name == b"te" and value.lower() != b"trailers"):
            raise RequestDenied("h2_connection_header")
        result.append((name, value))
    lengths = [value for name, value in result if name == b"content-length"]
    transfers = [value for name, value in result if name == b"transfer-encoding"]
    if len(lengths) > 1 or lengths and transfers:
        raise RequestDenied("ambiguous_framing")
    if lengths and (not re.fullmatch(rb"[0-9]{1,19}", lengths[0]) or int(lengths[0]) > 2**63 - 1):
        raise RequestDenied("invalid_content_length")
    if transfers and (len(transfers) != 1 or transfers[0].lower() != b"chunked"):
        raise RequestDenied("unsupported_transfer_coding")
    return tuple(result)


def raw_http1_headers(block: bytes) -> tuple[bytes, Headers]:
    """Inspect duplicates before h11's permitted identical-length normalization."""
    if len(block) > 65536 or not block.endswith(b"\r\n\r\n"):
        raise RequestDenied("invalid_header_block")
    lines = block[:-4].split(b"\r\n")
    start = lines[0]
    if not start or b"\n" in start or b"\r" in start or len(start) > 16384:
        raise RequestDenied("invalid_start_line")
    headers = []
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        if not colon or not _TOKEN.fullmatch(name):
            raise RequestDenied("invalid_header_line")
        headers.append((name, value.strip(b" \t")))
    return start, validate_headers(headers)


def validate_trailers(headers: Iterable[tuple[bytes, bytes]], *, h2: bool = False) -> Headers:
    values = validate_headers(headers, h2=h2)
    if len(values) > 32 or sum(len(n) + len(v) for n, v in values) > 16384:
        raise RequestDenied("trailer_limit")
    if any(name.startswith(b":") or name in _FORBIDDEN_TRAILERS for name, _ in values):
        raise RequestDenied("forbidden_trailer")
    return values


def forwarding_headers(headers: Headers) -> Headers:
    """Remove connection-specific metadata; parser/serializer owns framing.

    Upgrade handlers must construct their own validated transition fields, not
    use this ordinary-message serializer for an Upgrade/CONNECT exchange.
    """
    nominated = set()
    for name, value in headers:
        if name == b"connection":
            for item in value.split(b","):
                item = item.strip().lower()
                if not _TOKEN.fullmatch(item) or item in (
                    b"host",
                    b"content-length",
                    b"authorization",
                    b"proxy-authorization",
                ):
                    raise RequestDenied("unsafe_connection_nomination")
                nominated.add(item)
    return tuple((n, v) for n, v in headers if n not in _HOP_BY_HOP | nominated)


@dataclass(slots=True)
class BodyLength:
    expected: int | None
    received: int = 0

    def add(self, count: int) -> None:
        if count < 0 or self.received + count > 2**63 - 1:
            raise RequestDenied("body_length_limit")
        self.received += count
        if self.expected is not None and self.received > self.expected:
            raise RequestDenied("body_length_exceeded")

    def finish(self) -> None:
        if self.expected is not None and self.received != self.expected:
            raise RequestDenied("body_truncated")
