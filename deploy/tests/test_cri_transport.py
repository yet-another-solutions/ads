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
import json
import re
import sys
import time
from concurrent import futures
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

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


# --- Recorded-shape replay: real wire format, both runtimes -----------------
#
# PR #168/#169 class of failure: the helper-side pid fallback was written
# against a hand-modeled CRI-O info shape ({}), while real CRI-O 1.36.4
# verbose PodSandboxStatus sends info = {"runtimeSpec": <7-key dict>} with
# no pid, and real containerd sends a flat info map including "pid" as a
# JSON number. Unit fixtures dict-mocking the client cannot catch a wrong
# model of the wire; these tests replay recorded-shaped responses through
# the real grpcio server -> pb2 -> _info_map -> Cri -> helper path.
#
# Shapes are transcribed from live test-lab captures (2026-10-02, CRI-O
# 1.36.4 on node1, containerd 2.3.5 on sandbox1; capture helper kept at
# knowledge/2026-10-02-capture-cri-cassettes.sh). All env values, paths,
# image tags, cgroup paths, and identities are scrubbed to inert fixtures;
# only the structural facts the helpers consume survive: the single
# nested "info" map entry, info-map key sets, JSON-number pid, state
# enums, and label/uid plumbing.


CRIO_SANDBOX_ID = "c" * 64
CRIO_CONTAINER_ID = "d" * 64
CD_SANDBOX_ID = "e" * 64
CD_CONTAINER_ID = "f" * 64


def _runtime_spec(args, hostname):
    return {
        "ociVersion": "1.3.0",
        "process": {"user": {"uid": 0}, "args": args, "env": ["PATH=/usr/bin"], "cwd": "/"},
        "root": {"path": "/scrubbed/merged", "readonly": True},
        "hostname": hostname,
        "mounts": [{"destination": "/proc"}, {"destination": "/dev"}, {"destination": "/sys"}],
        "annotations": {},
        "linux": {"namespaces": [], "resources": {}, "cgroupsPath": "kubepods-scrubbed"},
    }


REPLAY = {
    "crio": {
        "uid": "11111111-0000-4000-8000-111111111111",
        "namespace": "ads-sandbox",
        "pod_name": "ads-sandbox-ipc-replay",
        "container_name": "ipc",
        "sandbox_id": CRIO_SANDBOX_ID,
        "container_id": CRIO_CONTAINER_ID,
        "image_ref": "ghcr.io/yet-another-solutions/ads-sandbox-ipc:0.0.58",
        # Measured on CRI-O 1.36.4: sandbox info carries runtimeSpec only.
        "sandbox_info": {"runtimeSpec": _runtime_spec(["/pause"], "ads-sandbox-ipc-replay")},
        "container_info": {
            "sandboxID": CRIO_SANDBOX_ID,
            "pid": 4024349,
            "privileged": False,
            "runtimeSpec": _runtime_spec(["/app/.venv/bin/python"], "ads-sandbox-ipc-replay"),
        },
    },
    "containerd": {
        "uid": "22222222-0000-4000-8000-222222222222",
        "namespace": "ads-sandbox",
        "pod_name": "ads-egress-relay-replay",
        "container_name": "relay",
        "sandbox_id": CD_SANDBOX_ID,
        "container_id": CD_CONTAINER_ID,
        "image_ref": "ghcr.io/yet-another-solutions/ads-ptp-tools:0.0.58",
        # Measured on containerd 2.3.5: flat sandbox info with real sandbox pid.
        "sandbox_info": {
            "pid": 923364,
            "processStatus": "running",
            "netNamespaceClosed": False,
            "image": {"image": "scrubbed"},
            "snapshotKey": "scrubbed",
            "snapshotter": "overlayfs",
            "runtimeType": "io.containerd.runc.v2",
            "runtimeOptions": None,
            "config": {},
            "runtimeSpec": _runtime_spec(["/pause"], "ads-egress-relay-replay"),
            "cniResult": {},
            "sandboxMetadata": {},
        },
        "container_info": {
            "sandboxID": CD_SANDBOX_ID,
            "pid": 923467,
            "removing": False,
            "snapshotKey": "scrubbed",
            "snapshotter": "overlayfs",
            "runtimeType": "io.containerd.runc.v2",
            "runtimeOptions": None,
            "config": {},
            "runtimeSpec": _runtime_spec(["relay"], "ads-egress-relay-replay"),
        },
    },
}


def _start_replay(pb2, pb2_grpc, path, sc, sandbox, sandbox_status, container, container_status):
    """Factory: bind one scenario's messages per server instance. The servicer
    must close over per-iteration bindings, never the fixture loop variable."""

    class Replay(pb2_grpc.RuntimeServiceServicer):
        def ListPodSandbox(self, request, context):
            return pb2.ListPodSandboxResponse(items=[sandbox])

        def PodSandboxStatus(self, request, context):
            if request.pod_sandbox_id != sc["sandbox_id"]:
                context.abort(grpc.StatusCode.NOT_FOUND, "no such sandbox")
            return pb2.PodSandboxStatusResponse(
                status=sandbox_status, info={"info": json.dumps(sc["sandbox_info"])}
            )

        def ListContainers(self, request, context):
            if request.filter.pod_sandbox_id not in ("", sc["sandbox_id"]):
                return pb2.ListContainersResponse(containers=[])
            return pb2.ListContainersResponse(containers=[container])

        def ContainerStatus(self, request, context):
            if request.container_id != sc["container_id"]:
                context.abort(grpc.StatusCode.NOT_FOUND, "no such container")
            return pb2.ContainerStatusResponse(
                status=container_status, info={"info": json.dumps(sc["container_info"])}
            )

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    pb2_grpc.add_RuntimeServiceServicer_to_server(Replay(), server)
    server.add_insecure_port("unix://" + str(path))
    server.start()
    return server


@pytest.fixture
def replay(pb2, pb2_grpc, tmp_path):
    """One real unix-socket grpcio server per runtime scenario, serving the
    recorded shapes as verbose responses (single nested "info" entry)."""
    endpoints = {}
    servers = []
    for sc in REPLAY.values():
        sandbox = pb2.PodSandbox(
            id=sc["sandbox_id"],
            state=pb2.SANDBOX_READY,
            created_at=1759363200000000000,
            metadata=pb2.PodSandboxMetadata(
                name=sc["pod_name"], uid=sc["uid"], namespace=sc["namespace"], attempt=0
            ),
            labels={
                "io.kubernetes.pod.uid": sc["uid"],
                "io.kubernetes.pod.namespace": sc["namespace"],
            },
        )
        container = pb2.Container(
            id=sc["container_id"],
            pod_sandbox_id=sc["sandbox_id"],
            state=pb2.CONTAINER_RUNNING,
            created_at=1759363200000000000,
            metadata=pb2.ContainerMetadata(name=sc["container_name"], attempt=0),
            image_ref=sc["image_ref"],
            image=pb2.ImageSpec(image=sc["image_ref"].split("@")[0]),
            labels={
                "io.kubernetes.container.name": sc["container_name"],
                "io.kubernetes.pod.uid": sc["uid"],
                "io.kubernetes.pod.namespace": sc["namespace"],
            },
        )
        # Status responses carry their own message types (PodSandboxStatus /
        # ContainerStatus), not the list-response messages.
        sandbox_status = pb2.PodSandboxStatus(
            id=sandbox.id,
            state=sandbox.state,
            created_at=sandbox.created_at,
            metadata=sandbox.metadata,
            labels=sandbox.labels,
            annotations=sandbox.annotations,
        )
        container_status = pb2.ContainerStatus(
            id=container.id,
            state=container.state,
            created_at=container.created_at,
            metadata=container.metadata,
            image=container.image,
            image_ref=container.image_ref,
            labels=container.labels,
            annotations=container.annotations,
        )
        path = tmp_path / (sc["sandbox_id"][:8] + ".sock")
        servers.append(
            _start_replay(
                pb2, pb2_grpc, path, sc, sandbox, sandbox_status, container, container_status
            )
        )
        endpoints[sc["sandbox_id"]] = ("unix://" + str(path), sc)
    yield endpoints
    for server in servers:
        server.stop(0).wait()


def _replay_client(cri, endpoints, sandbox_id):
    endpoint, sc = endpoints[sandbox_id]
    return cri.Cri(endpoint, time.monotonic() + 8), sc


@pytest.mark.parametrize("key", ["crio", "containerd"])
def test_replay_info_map_shapes_match_recorded_wire(cri, replay, key):
    # The JSON-decoded info map must reproduce the measured key sets and the
    # JSON-number pid contract before any helper consumes it.
    sc = REPLAY[key]
    client, _ = _replay_client(cri, replay, sc["sandbox_id"])
    detail = client.inspectp(sc["sandbox_id"])
    assert set(detail["info"]) == set(sc["sandbox_info"])
    if key == "crio":
        assert set(detail["info"]) == {"runtimeSpec"}
        assert "pid" not in detail["info"]
    else:
        assert type(detail["info"]["pid"]) is int
    container = client.inspect(sc["container_id"])
    assert type(container["info"]["pid"]) is int
    assert container["info"]["sandboxID"] == sc["sandbox_id"]


@pytest.mark.parametrize(
    "key,expected_pids", [("crio", (4024349, 4024349)), ("containerd", (923364, 923467))]
)
def test_replay_runtime_pid_fallback_through_wire(ipc_release, cri, replay, key, expected_pids):
    # The exact failure PR #169 fixes, now exercised over the real wire:
    # CRI-O degrades the sandbox pin to the container pid (no sandbox
    # process exists), containerd pins the true sandbox pid. Both must
    # return the recorded pid pairs without an ownership fault.
    sc = REPLAY[key]
    client, sc_full = _replay_client(cri, replay, sc["sandbox_id"])
    observer = SimpleNamespace(config={"container": sc_full["container_name"]}, cri=lambda: client)
    wanted = {
        "node": "application",
        "namespace": sc_full["namespace"],
        "generation": str(uuid4()),
        "sandbox_id": str(uuid4()),
        "pod_uid": sc_full["uid"],
        "volume_uid": str(uuid4()),
    }
    pod = {
        "metadata": {
            "name": sc_full["pod_name"],
            "uid": sc_full["uid"],
            "namespace": sc_full["namespace"],
        },
        "spec": {"nodeName": "application"},
    }
    sandbox_id, pids = ipc_release.runtime(observer, wanted, pod, sc_full["container_id"])
    assert re.fullmatch(r"[0-9a-f]{64}", sandbox_id)
    assert pids == expected_pids
    assert all(type(pid) is int and pid > 1 for pid in pids)


@pytest.fixture
def ipc_release():
    # ads-ipc-release loads its sibling helpers (ads-ptp, ads-ptp-release,
    # ads-cri) through the same with-name loader used in the image.
    return _load("ipc_node_release", TOOLS / "ads-ipc-release")


@pytest.fixture
def attest():
    return _load("ads_ptp_attest", TOOLS / "ads-ptp-attest")


@pytest.mark.parametrize(
    "key,expected_pids", [("crio", (4024349, 4024349)), ("containerd", (923364, 923467))]
)
def test_replay_runtime_identity_through_wire(attest, cri, replay, key, expected_pids):
    # Second call site (ads-ptp-attest.runtime_identity) against the same
    # recorded wire shapes: CRI-O degrades to the container pid, containerd
    # keeps the real sandbox pid, both without an identity fault.
    sc = REPLAY[key]
    client, _ = _replay_client(cri, replay, sc["sandbox_id"])
    observer = SimpleNamespace(
        config={
            "namespace": sc["namespace"],
            "relay_container": sc["container_name"],
            "relay_image": sc["image_ref"],
        },
        cri=lambda: client,
    )
    relay = {"metadata": {"uid": sc["uid"], "name": sc["pod_name"]}}
    sandbox_id, pids = attest.runtime_identity(observer, relay, sc["container_id"])
    assert sandbox_id == sc["sandbox_id"]
    assert pids == expected_pids


@pytest.mark.parametrize("key", ["crio", "containerd"])
def test_replay_rejects_foreign_sandbox_status_over_wire(attest, cri, replay, key):
    # Tampered verbose status (wrong pod uid in the status message) must
    # still fail closed through the full wire path.
    sc = REPLAY[key]
    client, _ = _replay_client(cri, replay, sc["sandbox_id"])
    observer = SimpleNamespace(
        config={
            "namespace": sc["namespace"],
            "relay_container": sc["container_name"],
            "relay_image": sc["image_ref"],
        },
        cri=lambda: client,
    )
    relay = {"metadata": {"uid": str(uuid4()), "name": sc["pod_name"]}}
    with pytest.raises(ValueError):
        attest.runtime_identity(observer, relay, sc["container_id"])
