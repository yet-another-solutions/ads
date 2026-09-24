from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import json
import stat
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest


@pytest.fixture
def service():
    path = Path(__file__).parents[2] / "services/ads-ptp-tools/ads-node-owner"
    loader = importlib.machinery.SourceFileLoader("ads_node_owner", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@pytest.fixture
def node_request():
    return {
        "schema": "ads-node-owner-v1",
        "nonce": str(uuid4()),
        "operation": "pair-capture",
        "node": "worker",
        "namespace": "sandboxes",
        "network": "private",
        "generation": str(uuid4()),
        "sandbox_id": str(uuid4()),
        "pod_uid": None,
        "volume_uid": None,
        "boot_id": None,
        "inventory_sha256": None,
    }


@pytest.fixture
def config():
    return {
        "node": "worker",
        "namespace": "sandboxes",
        "network": "private",
        "pair": {"attestorConfig": "/platform/attestor", "stateDir": "/state"},
        "ipc": None,
    }


def test_pair_capture_has_fixed_fence_and_observer_operations(
    service, node_request, config, monkeypatch
):
    calls = []
    report = {
        **{
            key: node_request[key]
            for key in ("node", "namespace", "network", "generation", "sandbox_id")
        },
        "boot_id": str(uuid4()),
        "inventory_sha256": "a" * 64,
    }

    def helper(name, payload):
        calls.append((name, payload))
        return report if name == "ads-ptp-release" else {"attachment_admission_fenced": True}

    monkeypatch.setattr(service, "helper", helper)
    raw = json.dumps(node_request).encode()
    result = service.perform(raw, config)
    assert [name for name, _ in calls] == ["ads-ptp-retire", "ads-ptp-release"]
    assert calls[0][1]["network"] == "private"
    assert calls[1][1]["action"] == "capture"
    assert result["request_sha256"] == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize(
    "change",
    [
        {"operation": "shell"},
        {"node": "other"},
        {"network": "other"},
        {"pod_uid": str(uuid4())},
        {"boot_id": str(uuid4())},
        {"inventory_sha256": "a" * 64},
        {"extra": True},
    ],
)
def test_capture_rejects_commands_scope_and_observe_fields(service, node_request, config, change):
    with pytest.raises(ValueError):
        service.request(json.dumps({**node_request, **change}).encode(), config)


def test_observe_requires_original_boot_and_digest(service, node_request, config):
    node_request.update(operation="pair-observe", boot_id=str(uuid4()), inventory_sha256="a" * 64)
    assert service.request(json.dumps(node_request).encode(), config) == node_request
    for field in ("boot_id", "inventory_sha256"):
        with pytest.raises(ValueError):
            service.request(json.dumps({**node_request, field: None}).encode(), config)


@pytest.mark.parametrize("action", ["capture", "observe"])
def test_storage_calls_only_fixed_ipc_backing_observer(
    service, node_request, config, monkeypatch, action
):
    config["ipc"] = "/platform/ipc"
    node_request.update(
        operation="ipc-storage-" + action,
        pod_uid=str(uuid4()),
        volume_uid=str(uuid4()),
        boot_id=str(uuid4()) if action == "observe" else None,
        inventory_sha256="a" * 64 if action == "observe" else None,
    )
    calls = []

    def helper(name, payload):
        calls.append((name, payload))
        return {**node_request}

    monkeypatch.setattr(service, "helper", helper)
    service.perform(json.dumps(node_request).encode(), config)
    assert len(calls) == 1 and calls[0][0] == "ads-ipc-storage"
    assert calls[0][1]["config"] == config["ipc"]
    assert calls[0][1]["action"] == action
    config["ipc"] = None
    with pytest.raises(ValueError):
        service.perform(json.dumps(node_request).encode(), config)


@pytest.mark.parametrize(
    "fault", ["owner", "write", "private", "executable", "directory", "symlink", "parent"]
)
def test_protected_files_reject_replaceable_or_exposed_platform_authority(
    service, monkeypatch, fault
):
    info = SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o600)
    parent = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)
    monkeypatch.setattr(Path, "lstat", lambda self: info)
    monkeypatch.setattr(Path, "stat", lambda self: parent)
    if fault == "owner":
        info.st_uid = 1001
    elif fault == "write":
        info.st_mode |= 0o020
    elif fault == "private":
        info.st_mode |= 0o004
    elif fault == "directory":
        info.st_mode = stat.S_IFDIR | 0o700
    elif fault == "symlink":
        monkeypatch.setattr(Path, "resolve", lambda self: Path("/different"))
    elif fault == "parent":
        parent.st_mode |= 0o002
    with pytest.raises(ValueError, match="protected"):
        service.protected(
            "/platform/config", private=fault == "private", executable=fault == "executable"
        )


def test_protected_files_accept_only_the_expected_modes(service, monkeypatch):
    info = SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o600)
    monkeypatch.setattr(Path, "lstat", lambda self: info)
    monkeypatch.setattr(
        Path, "stat", lambda self: SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)
    )
    assert service.protected("/platform/config", private=True) == Path("/platform/config")
    info.st_mode = stat.S_IFREG | 0o755
    assert service.protected("/platform/helper", executable=True) == Path("/platform/helper")


@pytest.fixture
def startup(service, config, monkeypatch):
    values = {
        **config,
        "bind": "127.0.0.1",
        "port": 9443,
        "ca": "/platform/ca",
        "certificate": "/platform/certificate",
        "key": "/platform/key",
        "manager_fingerprints": ["a" * 64],
    }
    observer = {key: values[key] for key in ("node", "namespace", "network")}
    checked = []

    def protected(path, **kwargs):
        checked.append((str(path), kwargs))
        return Path(path)

    def read(path):
        return values if path == Path("/platform/config") else observer

    modules = {
        "ads-ptp": SimpleNamespace(read_record=read, private_directory=lambda path: Path(path)),
        "ads-ptp-attest": SimpleNamespace(validate=lambda value: value),
        "ads-ipc-release": SimpleNamespace(config=lambda value: value),
    }
    monkeypatch.setattr(service, "protected", protected)
    monkeypatch.setattr(service, "load", lambda name: modules[name])
    return SimpleNamespace(values=values, observer=observer, checked=checked)


def test_startup_binds_protected_helpers_and_observer_scope(service, startup):
    assert service.settings("/platform/config") == startup.values
    checked = {Path(path).name: flags for path, flags in startup.checked}
    for name in (
        "ads-ptp",
        "ads-ptp-attest",
        "ads-ptp-retire",
        "ads-ptp-release",
        "ads-ptp-partial",
        "ads-ipc-release",
        "ads-node-owner",
    ):
        assert checked[name]["executable"]
    assert checked["config"]["private"] and checked["key"]["private"]


@pytest.mark.parametrize(
    "fault", ["scope", "roles", "pin", "duplicate-pin", "extra", "port", "pair-fields", "ipc-scope"]
)
def test_startup_rejects_unsafe_configuration_before_listening(service, startup, fault):
    values = startup.values
    if fault == "scope":
        startup.observer["node"] = "other"
    elif fault == "roles":
        values["pair"] = None
    elif fault == "pin":
        values["manager_fingerprints"] = ["not-a-fingerprint"]
    elif fault == "duplicate-pin":
        values["manager_fingerprints"] *= 2
    elif fault == "extra":
        values["arbitrary_command"] = "rejected"
    elif fault == "port":
        values["port"] = True
    elif fault == "pair-fields":
        values["pair"]["unknown"] = "rejected"
    elif fault == "ipc-scope":
        values["pair"], values["ipc"] = None, "/platform/ipc"
        startup.observer["namespace"] = "other"
    with pytest.raises(ValueError):
        service.settings("/platform/config")


def test_service_entrypoint_refuses_nonroot_before_configuration(service, monkeypatch):
    monkeypatch.setattr(service.os, "geteuid", lambda: 1001)
    with pytest.raises(ValueError, match="node-root"):
        service.main()


@pytest.mark.parametrize("action", ["capture", "observe"])
def test_partial_operations_keep_exact_uid_map_and_fixed_helper(
    service, node_request, config, monkeypatch, action
):
    node_request.update(operation="partial-" + action, pod_uids={"guest": str(uuid4())})
    if action == "observe":
        node_request.update(boot_id=str(uuid4()), inventory_sha256="b" * 64)
    calls = []
    report = {
        **{
            key: node_request[key]
            for key in ("node", "namespace", "network", "generation", "sandbox_id", "pod_uids")
        },
        "boot_id": node_request["boot_id"] or str(uuid4()),
        "inventory_sha256": node_request["inventory_sha256"] or "a" * 64,
    }

    def helper(name, payload):
        calls.append((name, payload))
        return report

    monkeypatch.setattr(service, "helper", helper)
    result = service.perform(json.dumps(node_request).encode(), config)
    assert result["report"] == report
    assert [name for name, _ in calls] == (
        ["ads-ptp-retire", "ads-ptp-partial"] if action == "capture" else ["ads-ptp-partial"]
    )
    assert calls[-1][1] == {
        "generation": node_request["generation"],
        "sandbox_id": node_request["sandbox_id"],
        **config["pair"],
        "action": action,
        "pod_uids": node_request["pod_uids"],
    }


@pytest.mark.parametrize("uids", [{}, {"ipc": str(uuid4())}, {"guest": "wrong"}, []])
def test_partial_request_cannot_hide_or_replace_original_roles(service, node_request, config, uids):
    node_request.update(operation="partial-capture", pod_uids=uids)
    with pytest.raises(ValueError):
        service.request(json.dumps(node_request).encode(), config)


def test_nonpartial_request_cannot_supply_partial_map(service, node_request, config):
    node_request["pod_uids"] = {"guest": str(uuid4())}
    with pytest.raises(ValueError):
        service.request(json.dumps(node_request).encode(), config)


@pytest.mark.parametrize("action", ["capture", "observe"])
def test_block_operations_use_only_original_scope_and_configured_kubelet_root(
    service, node_request, config, monkeypatch, action
):
    config["pair"]["kubeletRoot"] = "/platform/kubelet"
    node_request.update(
        operation="block-" + action,
        runtime_sha256="a" * 64,
        volumes={
            "workspace": {"name": "claim", "volume_uid": str(uuid4()), "pod_uid": str(uuid4())}
        },
    )
    if action == "observe":
        node_request.update(boot_id=str(uuid4()), inventory_sha256="b" * 64)
    calls = []

    def helper(name, payload):
        calls.append((name, payload))
        return dict(node_request)

    monkeypatch.setattr(service, "helper", helper)
    service.perform(json.dumps(node_request).encode(), config)
    assert len(calls) == 1 and calls[0][0] == "ads-block-release"
    assert calls[0][1] == {
        **config["pair"],
        "action": action,
        **{
            key: node_request[key]
            for key in (
                "generation",
                "sandbox_id",
                "volumes",
                "runtime_sha256",
                "inventory_sha256",
            )
        },
    }
    node_request["kubeletRoot"] = "/caller-path"
    with pytest.raises(ValueError):
        service.request(json.dumps(node_request).encode(), config)
