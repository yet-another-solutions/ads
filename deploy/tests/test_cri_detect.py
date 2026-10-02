from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import socket
import sys
import time
from concurrent import futures
from pathlib import Path

import grpc
import pytest

SCRIPT = Path(__file__).parents[2] / "services/ads-ptp-tools/ads-cri"
TOOLS = SCRIPT.parent
CONTAINERD = "unix:///run/containerd/containerd.sock"
CRIO = "unix:///var/run/crio/crio.sock"
FAKE_SOCKET = "/tmp/ads-test-cri.sock"


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


def _socket(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    if path.exists():
        path.unlink()
    server.bind(str(path))
    server.listen(1)
    return server


def test_one_containerd_socket_wins(cri, tmp_path, monkeypatch):
    held = _socket(tmp_path / "containerd.sock")
    missing = tmp_path / "missing" / "crio.sock"
    monkeypatch.setattr(cri, "SOCKETS", (str(tmp_path / "containerd.sock"), str(missing)))
    assert cri.detect() == f"unix://{tmp_path / 'containerd.sock'}"
    held.close()


def test_one_crio_socket_wins(cri, tmp_path, monkeypatch):
    held = _socket(tmp_path / "crio.sock")
    missing = tmp_path / "missing" / "containerd.sock"
    monkeypatch.setattr(cri, "SOCKETS", (str(missing), str(tmp_path / "crio.sock")))
    assert cri.detect() == f"unix://{tmp_path / 'crio.sock'}"
    held.close()


def test_both_live_sockets_fail_closed(cri, tmp_path, monkeypatch):
    held = (_socket(tmp_path / "containerd.sock"), _socket(tmp_path / "crio.sock"))
    monkeypatch.setattr(
        cri, "SOCKETS", (str(tmp_path / "containerd.sock"), str(tmp_path / "crio.sock"))
    )
    with pytest.raises(ValueError, match="exactly one"):
        cri.detect()
    for item in held:
        item.close()


def test_neither_socket_fails_closed(cri, tmp_path, monkeypatch):
    absent = (tmp_path / "no-containerd.sock", tmp_path / "no-crio.sock")
    monkeypatch.setattr(cri, "SOCKETS", tuple(str(path) for path in absent))
    with pytest.raises(ValueError, match="exactly one"):
        cri.detect()


def test_non_socket_path_is_not_a_winner(cri, tmp_path, monkeypatch):
    plain = tmp_path / "containerd.sock"
    plain.write_text("not a socket")
    absent = tmp_path / "no-crio.sock"
    monkeypatch.setattr(cri, "SOCKETS", (str(plain), str(absent)))
    with pytest.raises(ValueError, match="exactly one"):
        cri.detect()


def test_symlinked_socket_is_not_a_winner(cri, tmp_path, monkeypatch):
    held = _socket(tmp_path / "real.sock")
    link = tmp_path / "containerd.sock"
    if link.exists():
        link.unlink()
    link.symlink_to(tmp_path / "real.sock")
    absent = tmp_path / "no-crio.sock"
    monkeypatch.setattr(cri, "SOCKETS", (str(link), str(absent)))
    with pytest.raises(ValueError, match="exactly one"):
        cri.detect()
    held.close()


def test_socket_path_requires_canonical_unix_endpoint(cri):
    with pytest.raises(ValueError, match="local CRI endpoint"):
        cri.socket_path("tcp://127.0.0.1:1234")
    with pytest.raises(ValueError, match="canonical CRI path"):
        cri.socket_path("unix:///run/../run/containerd/containerd.sock")
    assert cri.socket_path(CONTAINERD) == Path("/run/containerd/containerd.sock")


# --- grpcio client against an in-process fake RuntimeService ---


class FakeState:
    """Canned replies the fake servicer returns; one failing rpc at a time."""

    def __init__(self, pb2):
        self.pb2 = pb2
        self.version = pb2.VersionResponse(
            version="0.1.0",
            runtime_name="containerd",
            runtime_version="1.7.0",
            runtime_api_version="v1",
        )
        self.pod_items = []
        self.sandbox_status = None
        self.sandbox_info = {}
        self.container_items = []
        self.container_status = None
        self.container_info = {}
        self.fail = None  # (grpc.StatusCode, message)


class FakeRuntime:
    """Answers the five read-only RuntimeService methods from FakeState."""

    def __init__(self, pb2_grpc, state):
        self.pb2_grpc = pb2_grpc
        self.state = state

    def _guard(self, context):
        if self.state.fail is not None:
            context.abort(self.state.fail[0], self.state.fail[1])

    def build(self):
        pb2 = self.state.pb2
        pb2_grpc = self.pb2_grpc
        state, guard = self.state, self._guard

        class Servicer(pb2_grpc.RuntimeServiceServicer):
            def Version(self, request, context):
                guard(context)
                return state.version

            def ListPodSandbox(self, request, context):
                guard(context)
                return pb2.ListPodSandboxResponse(items=state.pod_items)

            def PodSandboxStatus(self, request, context):
                guard(context)
                return pb2.PodSandboxStatusResponse(
                    status=state.sandbox_status, info=state.sandbox_info
                )

            def ListContainers(self, request, context):
                guard(context)
                return pb2.ListContainersResponse(containers=state.container_items)

            def ContainerStatus(self, request, context):
                guard(context)
                return pb2.ContainerStatusResponse(
                    status=state.container_status, info=state.container_info
                )

        return Servicer()


@pytest.fixture
def runtime(cri, pb2, pb2_grpc):
    state = FakeState(pb2)
    fake = FakeRuntime(pb2_grpc, state)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    pb2_grpc.add_RuntimeServiceServicer_to_server(fake.build(), server)
    path = Path(FAKE_SOCKET)
    if path.exists():
        path.unlink()
    server.add_insecure_port("unix://" + FAKE_SOCKET)
    server.start()
    try:
        yield state
    finally:
        server.stop(0).wait()
        path.unlink(missing_ok=True)


def _client(cri):
    return cri.Cri("unix://" + FAKE_SOCKET, time.monotonic() + 8)


def _sandbox_item(pb2, sandbox_id, uid, name, namespace):
    return pb2.PodSandbox(
        id=sandbox_id,
        metadata=pb2.PodSandboxMetadata(name=name, uid=uid, namespace=namespace, attempt=0),
    )


def _sandbox_status(pb2, sandbox_id, uid, name, namespace):
    return pb2.PodSandboxStatus(
        id=sandbox_id,
        metadata=pb2.PodSandboxMetadata(name=name, uid=uid, namespace=namespace, attempt=0),
    )


def test_version_and_json_shapes(cri, runtime):
    client = _client(cri)
    reply = client.call("Version", client.api.VersionRequest(version="0.1.0"))
    assert reply.runtime_name == "containerd" and reply.runtime_api_version == "v1"


def test_pods_and_inspectp(cri, pb2, runtime):
    runtime.pod_items = [_sandbox_item(pb2, "c" * 64, "u1", "ipc", "sandboxes")]
    runtime.sandbox_status = _sandbox_status(pb2, "c" * 64, "u1", "ipc", "sandboxes")
    runtime.sandbox_info = {"pid": "4242"}

    client = _client(cri)
    pods = client.pods()
    assert pods == [
        {
            "id": "c" * 64,
            "state": "SANDBOX_READY",
            "createdAt": 0,
            "metadata": {"uid": "u1", "name": "ipc", "namespace": "sandboxes", "attempt": 0},
            "labels": {},
            "annotations": {},
            "runtimeHandler": "",
        }
    ]
    detail = client.inspectp("c" * 64)
    assert detail["status"]["id"] == "c" * 64
    assert detail["info"]["pid"] == 4242 and type(detail["info"]["pid"]) is int


def _container_item(pb2, container_id, sandbox_id, name, image_ref, label_uid):
    return pb2.Container(
        id=container_id,
        pod_sandbox_id=sandbox_id,
        metadata=pb2.ContainerMetadata(name=name, attempt=0),
        image=pb2.ImageSpec(image="ghcr.io/example/relay:v1"),
        image_ref=image_ref,
        state=pb2.CONTAINER_RUNNING,
        labels={"io.kubernetes.pod.uid": label_uid},
    )


def _container_status(pb2, container_id, name, image_ref, label_uid):
    return pb2.ContainerStatus(
        id=container_id,
        metadata=pb2.ContainerMetadata(name=name, attempt=0),
        state=pb2.CONTAINER_RUNNING,
        image_ref=image_ref,
        labels={
            "io.kubernetes.container.name": name,
            "io.kubernetes.pod.namespace": "ads-sandbox",
            "io.kubernetes.pod.uid": label_uid,
        },
        annotations={
            "io.kubernetes.container.hash": "bf209fda",
            "io.kubernetes.container.ports": "[]",
        },
    )


def test_containers_and_inspect(cri, pb2, runtime):
    runtime.container_items = [_container_item(pb2, "d" * 64, "c" * 64, "ipc", "ref:v1", "u1")]
    runtime.container_status = _container_status(pb2, "d" * 64, "relay", "ref:v1", "u1")
    runtime.container_info = {"pid": "5151", "sandboxID": "c" * 64}

    client = _client(cri)
    containers = client.containers()
    assert containers[0]["podSandboxId"] == "c" * 64
    assert containers[0]["state"] == "CONTAINER_RUNNING"
    assert containers[0]["metadata"] == {"uid": "", "name": "ipc", "namespace": "", "attempt": 0}
    assert containers[0]["labels"]["io.kubernetes.pod.uid"] == "u1"
    detail = client.inspect("d" * 64)
    assert detail["info"]["pid"] == 5151
    assert detail["info"]["sandboxID"] == "c" * 64
    assert detail["status"]["labels"]["io.kubernetes.container.name"] == "relay"
    assert detail["status"]["labels"]["io.kubernetes.pod.namespace"] == "ads-sandbox"
    assert detail["status"]["labels"]["io.kubernetes.pod.uid"] == "u1"
    assert detail["status"]["annotations"]["io.kubernetes.container.hash"] == "bf209fda"
    assert detail["status"]["annotations"]["io.kubernetes.container.ports"] == "[]"


def test_grpc_error_fails_closed(cri, runtime):
    runtime.fail = (grpc.StatusCode.INTERNAL, "boom")
    client = _client(cri)
    with pytest.raises(ValueError, match="cri rpc failed: boom"):
        client.call("Version", client.api.VersionRequest(version="0.1.0"))


def test_unsupported_rpc_fails_closed(cri):
    client = _client(cri)
    with pytest.raises(ValueError, match="unsupported CRI rpc"):
        client.call("RunPodSandbox", client.api.RunPodSandboxRequest())


def test_probe_rejects_unknown_runtime(cri, runtime):
    runtime.version = runtime.pb2.VersionResponse(
        version="0.1.0", runtime_name="alien", runtime_api_version="v1"
    )
    with pytest.raises(ValueError, match="unexpected cri runtime"):
        cri.probe("unix://" + FAKE_SOCKET, timeout=8)


def test_info_map_json_passthrough(cri):
    # info values that are not JSON stay strings; JSON-typed values parse.
    parsed = cri._info_map({"pid": "4242", "note": "plain text"})
    assert parsed["pid"] == 4242 and parsed["note"] == "plain text"


def test_containerd_verbose_info_nesting(cri, pb2, runtime):
    # containerd verbose responses wrap every info field under one "info"
    # key; the decoded shape must match the crictl contract where pid and
    # sandboxID are top-level info entries.
    runtime.container_status = pb2.ContainerStatus(
        id="d" * 64, metadata=pb2.ContainerMetadata(name="relay"), state=pb2.CONTAINER_RUNNING
    )
    runtime.sandbox_status = _sandbox_status(pb2, "c" * 64, "u1", "ipc", "sandboxes")
    nested = json.dumps({"pid": 5151, "sandboxID": "c" * 64, "image": "x"})
    runtime.container_info = {"info": nested}
    runtime.sandbox_info = {"info": nested}

    client = _client(cri)
    detail = client.inspect("d" * 64)
    assert detail["info"]["pid"] == 5151 and type(detail["info"]["pid"]) is int
    assert detail["info"]["sandboxID"] == "c" * 64
    sandbox = client.inspectp("c" * 64)
    assert sandbox["info"]["pid"] == 5151
    assert sandbox["info"]["sandboxID"] == "c" * 64
