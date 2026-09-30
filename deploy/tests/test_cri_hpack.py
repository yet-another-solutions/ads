"""HPACK decode regression: real captured server bytes must parse.

Failure under fix: containerd 2.3.5 huffman-encodes response header values
and names, and emits indexed static-table fields. The previous hand-rolled
parser required literal-without-huffman encoding everywhere and rejected
the very first response header block from containerd. These tests pin the
exact captured byte streams (CRI Version rpc, unix socket, 2026-09-30 lab)
so any decoder regression fails loudly.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[2] / "services/ads-ptp-tools/ads-cri"

# Captured from containerd 2.3.5, HTTP/2 HEADERS on the Version rpc stream.
CONTAINERD_INITIAL = bytes.fromhex("885f8b1d75d0620d263d4c4d6564")
# Captured trailer block: grpc-status "0", empty huffman grpc-message.
CONTAINERD_TRAILERS = bytes.fromhex("40889acac8b21234da8f013040899acac8b5254207317f00")
# CRI-O 1.36.4 parity: literal, no-huffman trailers (previous parser passed).
CRIO_TRAILERS = b"\x00\x0bgrpc-status\x01\x30"


@pytest.fixture
def cri():
    loader = importlib.machinery.SourceFileLoader("ads_cri", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_containerd_initial_headers_decode(cri):
    decoder = cri.hpack.Decoder()
    headers = cri.decode_headers(CONTAINERD_INITIAL, decoder)
    assert [tuple(pair) for pair in headers] == [
        (":status", "200"),
        ("content-type", "application/grpc"),
    ]


def test_containerd_trailers_decode(cri):
    decoder = cri.hpack.Decoder()
    headers = cri.decode_headers(CONTAINERD_TRAILERS, decoder)
    decoded = dict(headers)
    assert decoded["grpc-status"] == "0"
    assert decoded["grpc-message"] == ""


def test_crio_trailers_still_decode(cri):
    decoder = cri.hpack.Decoder()
    headers = cri.decode_headers(CRIO_TRAILERS, decoder)
    assert dict(headers) == {"grpc-status": "0"}


def test_truncated_block_fails_closed(cri):
    with pytest.raises(Exception) as excinfo:
        cri.decode_headers(CONTAINERD_INITIAL[:-2], cri.hpack.Decoder())
    assert "truncated" in str(excinfo.value).lower()


def test_wire_encoding_unchanged(cri):
    # Request encoding must remain the deterministic no-huffman literal form.
    block = cri.hpack_headers([(":path", "/runtime.v1.RuntimeService/Version")])
    assert block == b'\x00\x05:path"/runtime.v1.RuntimeService/Version'


def test_response_state_machine_accepts_containerd_shape(cri, monkeypatch):
    """Full _response() walk with the exact captured containerd frames."""
    frames = [
        # HEADERS: initial response, END_HEADERS, no END_STREAM
        bytes.fromhex("00000e010400000003") + CONTAINERD_INITIAL,
        # DATA: 5-byte gRPC prefix (empty VersionResponse body)
        bytes.fromhex("000005000100000003") + b"\x00\x00\x00\x00\x00",
        # HEADERS: trailers with END_HEADERS|END_STREAM
        bytes.fromhex("000018010500000003") + CONTAINERD_TRAILERS,
    ]
    connection = cri.Connection.__new__(cri.Connection)
    connection.decoder = cri.hpack.Decoder()
    connection.stream_id = 3
    connection.buffer = b""
    connection.deadline = cri.time.monotonic() + 8

    index = {"i": 0}

    def header_seq():
        head = frames[index["i"]]
        index["i"] += 1
        return (
            int.from_bytes(head[:3], "big"),
            head[3],
            head[4],
            int.from_bytes(head[5:9], "big"),
        )

    def payload_seq(length):
        head = frames[index["i"] - 1]
        assert length == len(head) - 9
        return head[9:]

    monkeypatch.setattr(connection, "_frame_header", header_seq)
    monkeypatch.setattr(connection, "_read_exact", payload_seq)
    body = connection._response(3)
    assert body == b""
