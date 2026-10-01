"""grpcio transport contract for the CRI client.

The hand-rolled HTTP/2 + HPACK layer was replaced by grpcio with the
vendored cri-api 1.36 stubs. The old failure mode this file pinned
(containerd huffman-encoded response headers the previous parser
rejected) cannot recur: HPACK is handled entirely inside grpcio. These
tests pin the behavior that must hold at the ads-cri surface instead.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import sys
import time
from concurrent import futures
from pathlib import Path

import grpc
import pytest

SCRIPT = Path(__file__).parents[2] / "services/ads-ptp-tools/ads-cri"
TOOLS = SCRIPT.parent


def _load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


@pytest.fixture
def cri():
    return _load("ads_cri", SCRIPT)


@pytest.fixture
def pb2():
    return _load("cri_api_1_36_pb2", TOOLS / "cri_api_1_36_pb2.py")


@pytest.fixture
def pb2_grpc(pb2):
    return _load("cri_api_1_36_pb2_grpc", TOOLS / "cri_api_1_36_pb2_grpc.py")


def test_stubs_load_from_sibling_files(pb2, pb2_grpc):
    # The vendored stubs must load as plain sibling modules from the image's
    # bin directory, exactly the way ads-cri loads them at runtime.
    assert pb2.DESCRIPTOR.package == "runtime.v1"
    assert hasattr(pb2_grpc, "RuntimeServiceStub")
    assert hasattr(pb2_grpc, "RuntimeServiceServicer")


def test_stub_runtime_version_guard_matches_pinned_grpcio(pb2):
    # Generated with grpcio-tools 1.84.0 (protobuf runtime 7.35.1 gate) and
    # the image/test stack pins protobuf 7.36.2: newer runtime is accepted.
    import google.protobuf

    assert tuple(int(part) for part in google.protobuf.__version__.split(".")[:3]) >= (7, 35, 1)


def test_deadline_exceeded_surfaces_before_rpc(cri):
    client = cri.Cri("unix:///tmp/ads-never-connected.sock", time.monotonic() - 1)
    with pytest.raises(ValueError, match="cri deadline exceeded"):
        client._rpc("Version", client.api.VersionRequest(version="0.1.0"))


def test_rpc_error_fails_closed_with_details(cri, pb2, pb2_grpc, tmp_path):
    class Failing(pb2_grpc.RuntimeServiceServicer):
        def Version(self, request, context):
            context.abort(grpc.StatusCode.INTERNAL, "simulated runtime failure")

    path = str(tmp_path / "fail.sock")
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
    pb2_grpc.add_RuntimeServiceServicer_to_server(Failing(), server)
    server.add_insecure_port("unix://" + path)
    server.start()
    try:
        client = cri.Cri("unix://" + path, time.monotonic() + 8)
        with pytest.raises(ValueError, match="cri rpc failed: simulated runtime failure"):
            client.call("Version", client.api.VersionRequest(version="0.1.0"))
    finally:
        server.stop(0).wait()


def test_unknown_dead_server_fails_within_deadline(cri):
    # No server listens here; the client must raise inside its deadline
    # budget instead of hanging past it.
    started = time.monotonic()
    client = cri.Cri("unix:///tmp/ads-never-connected.sock", time.monotonic() + 2)
    with pytest.raises((ValueError, grpc.RpcError)):
        client.call("Version", client.api.VersionRequest(version="0.1.0"))
    assert time.monotonic() - started < 4
