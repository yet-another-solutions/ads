from __future__ import annotations

import importlib.machinery
import importlib.util
import socket
import struct
import threading
import time
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[2] / "services/ads-ptp-tools/ads-cri"
WIRE = Path(__file__).parents[2] / "services/ads-ptp-tools/cri_wire.py"
CONTAINERD = "unix:///run/containerd/containerd.sock"
CRIO = "unix:///var/run/crio/crio.sock"


@pytest.fixture
def cri():
    loader = importlib.machinery.SourceFileLoader("ads_cri", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


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


# --- gRPC-over-unix-socket client against an in-process fake runtime ---


def hpack_int(data, index, bits=7):
    mask = (1 << bits) - 1
    value = data[index] & mask
    if value < mask:
        return value, index + 1
    shift = 0
    while True:
        index += 1
        byte = data[index]
        value += (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, index + 1


class _Raw:
    """Pre-encoded response body; FakeRuntime sends it verbatim."""

    def __init__(self, body):
        self.body = body

    def serialize(self):
        return self.body


class FakeRuntime:
    """Minimal HTTP/2 gRPC server answering the four RuntimeService reads."""

    def __init__(self, path, wire):
        self.wire = wire
        self.reply = {}
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if Path(path).exists():
            Path(path).unlink()
        self.server.bind(path)
        self.server.listen(1)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    @staticmethod
    def _frame(ftype, flags, sid, payload):
        return len(payload).to_bytes(3, "big") + struct.pack(">BBI", ftype, flags, sid) + payload

    def _serve(self):
        try:
            self._serve_inner()
        except OSError:
            pass

    def _serve_inner(self):
        conn, _ = self.server.accept()
        conn.settimeout(8)
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        buf = b""
        while len(buf) < len(preface):
            chunk = conn.recv(65536)
            if not chunk:
                return
            buf += chunk
        rest = buf[len(preface) :]
        method = None
        while True:
            while len(rest) < 9:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                rest += chunk
            length = int.from_bytes(rest[:3], "big")
            ftype, flags, sid = struct.unpack(">BBI", rest[3:9])
            while len(rest) < 9 + length:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                rest += chunk
            body = rest[9 : 9 + length]
            rest = rest[9 + length :]
            if ftype == 4:
                conn.sendall(self._frame(4, 0, 0, b""))
            elif ftype == 1:
                index = 0
                while index < len(body):
                    index += 1
                    name_len, index = hpack_int(body, index)
                    name = body[index : index + name_len].decode()
                    index += name_len
                    value_len, index = hpack_int(body, index)
                    value = body[index : index + value_len].decode()
                    index += value_len
                    if name == ":path":
                        method = value.rsplit("/", 1)[-1]
            elif ftype == 0:
                response = self.reply.get(method) or self.reply.get("Version") or _Raw(b"")
                raw = response.serialize()
                grpc = b"\x00" + struct.pack(">I", len(raw)) + raw
                conn.sendall(self._frame(1, 0x04, sid, b"\x00\x0ccontent-type\x11application/grpc"))
                conn.sendall(self._frame(0, 0x01, sid, grpc))
                conn.sendall(self._frame(1, 0x05, sid, b"\x00\x0bgrpc-status\x01\x30"))


@pytest.fixture
def runtime(cri):
    wire = cri.load("cri_wire")
    path = "/tmp/ads-test-cri.sock"
    fake = FakeRuntime(path, wire)
    fake.wire = wire
    yield fake
    fake.server.close()
    if Path(path).exists():
        Path(path).unlink()


def _client(cri, endpoint):
    return cri.Cri(endpoint, time.monotonic() + 8)


def test_version_and_json_shapes(cri, runtime):
    runtime.reply["Version"] = _version(
        runtime.wire, version="0.1.0", runtime_name="containerd", api="v1"
    )
    client = _client(cri, "unix:///tmp/ads-test-cri.sock")
    reply = client.call("Version", runtime.wire.VersionRequest(version="0.1.0"))
    assert reply.runtime_name == "containerd" and reply.runtime_api_version == "v1"


def _version(wire, *, version, runtime_name, runtime_version="1.7.0", api):
    # Build the VersionResponse body through the wire encoder itself.
    body = wire.pb_string(1, version) + wire.pb_string(2, runtime_name)
    body += wire.pb_string(3, runtime_version) + wire.pb_string(4, api)
    return _Raw(body)


def _sandbox_item(wire, sandbox_id, uid, name, namespace, state_code=0):
    wire_body = (
        wire.pb_string(1, name)
        + wire.pb_string(2, uid)
        + wire.pb_string(3, namespace)
        + wire.pb_int(4, 0)
    )
    item = wire.pb_string(1, sandbox_id) + wire.pb_message(2, wire_body)
    if state_code:  # proto3 implicit presence: default (0) is never on the wire
        item += wire.pb_int(3, state_code)
    return _Raw(wire.pb_message(1, item))


def _sandbox_status(wire, sandbox_id, uid, name, namespace, state_code=0):
    wire_body = (
        wire.pb_string(1, name)
        + wire.pb_string(2, uid)
        + wire.pb_string(3, namespace)
        + wire.pb_int(4, 0)
    )
    body = wire.pb_string(1, sandbox_id) + wire.pb_message(2, wire_body)
    if state_code:
        body += wire.pb_int(3, state_code)
    return _Raw(body)


def _info_entry(wire, key, value):
    return wire.pb_message(2, wire.pb_string(1, key) + wire.pb_string(2, str(value)))


def test_pods_and_inspectp(cri, runtime):
    wire = runtime.wire
    runtime.reply["ListPodSandbox"] = _sandbox_item(wire, "c" * 64, "u1", "ipc", "sandboxes")

    status_msg = _sandbox_status(wire, "c" * 64, "u1", "ipc", "sandboxes").body
    runtime.reply["PodSandboxStatus"] = _Raw(
        wire.pb_message(1, status_msg) + _info_entry(wire, "pid", "4242")
    )

    client = _client(cri, "unix:///tmp/ads-test-cri.sock")
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


def _container_item(wire, container_id, sandbox_id, name, image_ref, label_uid):
    wire_body = wire.pb_string(1, name)
    body = (
        wire.pb_string(1, container_id)
        + wire.pb_string(2, sandbox_id)
        + wire.pb_message(3, wire_body)
        + wire.pb_message(4, wire.pb_string(1, "ghcr.io/example/relay:v1"))
        + wire.pb_string(5, image_ref)
    )
    # state CONTAINER_RUNNING = 1 (non-default, on the wire)
    body += wire.pb_int(6, 1)
    label = wire.pb_string(1, "io.kubernetes.pod.uid") + wire.pb_string(2, label_uid)
    body += wire.pb_message(8, label)
    return _Raw(body)


def _container_status(wire, container_id, name, image_ref, label_uid):
    label = wire.pb_string(1, "io.kubernetes.pod.uid") + wire.pb_string(2, label_uid)
    body = (
        wire.pb_string(1, container_id)
        + wire.pb_message(2, wire.pb_string(1, name))
        + wire.pb_int(3, 1)
        + wire.pb_string(9, image_ref)
        + wire.pb_message(12, label)
    )
    return _Raw(body)


def test_containers_and_inspect(cri, runtime):
    wire = runtime.wire
    runtime.reply["ListContainers"] = _Raw(
        wire.pb_message(
            1,
            _container_item(wire, "d" * 64, "c" * 64, "ipc", "ghcr.io/example/relay:v1", "u1").body,
        )
    )
    status_msg = _container_status(wire, "d" * 64, "ipc", "ghcr.io/example/relay:v1", "u1").body
    runtime.reply["ContainerStatus"] = _Raw(
        wire.pb_message(1, status_msg)
        + _info_entry(wire, "pid", "5151")
        + _info_entry(wire, "sandboxID", "c" * 64)
    )

    client = _client(cri, "unix:///tmp/ads-test-cri.sock")
    containers = client.containers()
    assert containers[0]["podSandboxId"] == "c" * 64
    assert containers[0]["state"] == "CONTAINER_RUNNING"
    assert containers[0]["labels"]["io.kubernetes.pod.uid"] == "u1"
    detail = client.inspect("d" * 64)
    assert detail["info"]["pid"] == 5151
    assert detail["info"]["sandboxID"] == "c" * 64


def test_grpc_error_fails_closed(cri, runtime, monkeypatch):
    client = _client(cri, "unix:///tmp/ads-test-cri.sock")
    connection = client._connect()

    def truncated(count):
        raise ValueError("cri connection closed early")

    monkeypatch.setattr(connection, "_read_exact", truncated)
    with pytest.raises((ValueError, TimeoutError, OSError)):
        client.call("Version", runtime.wire.VersionRequest(version="0.1.0"))


def test_probe_rejects_unknown_runtime(cri, runtime):
    runtime.reply["Version"] = _version(
        runtime.wire, version="0.1.0", runtime_name="alien", api="v1"
    )
    with pytest.raises(ValueError, match="unexpected cri runtime"):
        cri.probe("unix:///tmp/ads-test-cri.sock", timeout=8)


def test_info_map_json_passthrough(cri):
    # info values that are not JSON stay strings; JSON-typed values parse.
    wire = cri.load("cri_wire")
    entries = [
        _Raw(wire.pb_string(1, "pid") + wire.pb_string(2, "4242")),
        _Raw(wire.pb_string(1, "note") + wire.pb_string(2, "plain text")),
    ]
    parsed = wire._info_map([entry.body for entry in entries])
    assert parsed["pid"] == 4242 and parsed["note"] == "plain text"
