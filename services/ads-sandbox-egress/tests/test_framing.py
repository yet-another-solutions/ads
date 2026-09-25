import pytest

from ads_sandbox_egress.framing import (
    BodyLength,
    forwarding_headers,
    raw_http1_headers,
    validate_headers,
    validate_trailers,
)
from ads_sandbox_egress.policy import RequestDenied


@pytest.mark.parametrize("start", [b"GET / HTTP/1.1", b"HTTP/1.1 200 OK"])
@pytest.mark.parametrize(
    "lines",
    [
        b"Content-Length: 1\r\nContent-Length: 1",
        b"Content-Length: 1, 1",
        b"Content-Length: +1",
        b"Content-Length: -1",
        b"Content-Length: 1\r\nTransfer-Encoding: chunked",
        b"Transfer-Encoding: gzip, chunked",
        b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked",
        b"Bad : name",
        b"Folded: a\r\n b",
        b"Injected: a\nb",
    ],
)
def test_strict_raw_profile_both_directions(start, lines):
    with pytest.raises(RequestDenied):
        raw_http1_headers(start + b"\r\n" + lines + b"\r\n\r\n")


@pytest.mark.parametrize(
    "name",
    [b"host", b"authorization", b"content-length", b"transfer-encoding", b":authority", b"cookie"],
)
def test_trailers_cannot_change_authorization(name):
    with pytest.raises(RequestDenied):
        validate_trailers(((name, b"1"),), h2=True)


def test_valid_metadata_and_truncation():
    assert validate_trailers(((b"digest", b"sha-256=abcd"),)) == ((b"digest", b"sha-256=abcd"),)
    length = BodyLength(5)
    length.add(3)
    with pytest.raises(RequestDenied, match="truncated"):
        length.finish()
    length.add(2)
    length.finish()
    with pytest.raises(RequestDenied, match="exceeded"):
        length.add(1)


@pytest.mark.parametrize(
    "headers",
    [
        ((b":method", b"GET"), (b":method", b"POST")),
        ((b"host", b"a"), (b":path", b"/")),
        ((b"Host", b"a"),),
        ((b"transfer-encoding", b"chunked"),),
        ((b"te", b"gzip"),),
        ((b":unknown", b"x"),),
    ],
)
def test_h2_strict_fields(headers):
    with pytest.raises(RequestDenied):
        validate_headers(headers, h2=True)


def test_connection_nominations():
    assert forwarding_headers(
        ((b"connection", b"close, x-hop"), (b"x-hop", b"v"), (b"x-end", b"v"))
    ) == ((b"x-end", b"v"),)
    with pytest.raises(RequestDenied):
        forwarding_headers(((b"connection", b"Host"), (b"host", b"a")))
