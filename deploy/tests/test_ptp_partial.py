# ruff: noqa: F811
from __future__ import annotations

import contextlib
import json
from copy import deepcopy
from types import SimpleNamespace
from uuid import uuid4

import pytest
from test_ptp_attachment import plugin  # noqa: F401
from test_ptp_attestation import RuntimeObserver, attest, fixture  # noqa: F401
from test_ptp_release import Observer, release  # noqa: F401

from ads_commons.sandbox.partial_release import decode_partial_release


@pytest.fixture
def partial(release):
    return release.load("ads-ptp-partial")


@pytest.fixture
def inventory(partial, release, plugin, attest, fixture, tmp_path, monkeypatch):
    f = fixture
    f.root = tmp_path / "state"
    f.root.mkdir(mode=0o700)
    f.scope = {
        **{key: f.config[key] for key in ("node", "namespace", "network")},
        "generation": f.vm["metadata"]["labels"]["ads.io/attachment-generation"],
        "sandbox_id": f.vm["metadata"]["labels"]["ads.io/sandbox-id"],
        "pod_uids": {
            "guest": f.vm["metadata"]["uid"],
            "guest-relay": f.relay["metadata"]["uid"],
        },
    }
    req = plugin.request(
        {"cniVersion": "1.0.0", "type": "ads-ptp", "name": f.config["network"]},
        {
            "CNI_COMMAND": "ADD",
            "CNI_CONTAINERID": "d" * 64,
            "CNI_IFNAME": "eth0",
            "CNI_NETNS": "/original/vm",
            "CNI_ARGS": "K8S_POD_UID=" + f.vm["metadata"]["uid"],
        },
    )
    f.attempt = {
        "schema": "ads-ptp-attempt-v1",
        "request": req,
        "boot_id": release.boot_id(),
        "vm_identity": [7, 203],
        "binding": None,
    }
    f.path = f.root / ("attempt-" + req["key"] + ".json")
    plugin.save_record(f.path, f.attempt)
    f.relay_record = {
        "pod_uid": f.relay["metadata"]["uid"],
        "generation": f.scope["generation"],
        "sandbox_id": f.scope["sandbox_id"],
        "private": [7, 201],
        "transport": [7, 202],
        "complete": True,
    }
    f.vm_sandbox = {
        "id": "d" * 64,
        "state": "SANDBOX_NOTREADY",
        "metadata": {key: f.vm["metadata"][key] for key in ("uid", "namespace", "name")},
    }
    read = plugin.read_record

    def read_record(path):
        if str(path) == "/proc/202/root/run/relay-state/state.json":
            return deepcopy(f.relay_record)
        return read(path)

    monkeypatch.setattr(plugin, "read_record", read_record)

    @contextlib.contextmanager
    def namespace(path, expected=None):
        fd = 201 if "/private-" in path else 202
        if expected is not None:
            assert expected == [7, fd]
        yield fd

    @contextlib.contextmanager
    def processes(pids):
        assert pids == (101, 202)
        yield lambda: None

    monkeypatch.setattr(plugin, "namespace", namespace)
    monkeypatch.setattr(plugin, "ns_identity", lambda fd: [7, fd])
    monkeypatch.setattr(plugin, "links", lambda fd: {"eth0": {"link_index": 20}})
    monkeypatch.setattr(attest, "processes", processes)
    f.observer = RuntimeObserver(f)
    original_cri = f.observer.cri

    def cri(*args):
        if args[0] == "pods":
            return {"items": [f.sandbox, f.vm_sandbox]}
        if args[0] == "inspectp" and args[-1] == f.vm_sandbox["id"]:
            return {"status": deepcopy(f.vm_sandbox)}
        return original_cri(*args)

    f.observer.cri = cri
    f.observer.command = lambda *args: [{"ifname": "peer1", "ifindex": 20}]
    return f


def capture(f, partial, plugin, attest, release):
    return partial.capture(plugin, attest, f.observer, release, f.root, f.scope)


def test_one_sided_and_pre_attestation_inventory_never_needs_a_fictional_second_side(
    partial, plugin, attest, release, inventory
):
    f = inventory
    before = f.path.read_bytes()
    value = capture(f, partial, plugin, attest, release)
    assert set(value["members"]) == {"guest", "guest-relay"}
    assert value["members"]["guest"] == {
        "runtime_ids": ["d" * 64],
        "namespaces": [[7, 203]],
        "links": [],
    }
    assert value["members"]["guest-relay"] == {
        "runtime_ids": ["c" * 64, "b" * 64],
        "namespaces": [[7, 201], [7, 202]],
        "links": [{"ifname": "peer1", "ifindex": 20}],
    }
    assert value["attempts"] == {f.path.name: partial.digest(f.attempt)}
    result = decode_partial_release(json.dumps(partial.report(value)).encode())
    assert not result.observed_runtime_released and not result.generation_retired
    assert f.path.read_bytes() == before


def test_relay_only_has_positive_actual_runtime_not_an_empty_vm(
    partial, plugin, attest, release, inventory
):
    f = inventory
    f.scope["pod_uids"].pop("guest")
    f.observer.pods = lambda: [f.relay]
    value = capture(f, partial, plugin, attest, release)
    assert set(value["members"]) == {"guest-relay"}
    assert value["members"]["guest-relay"]["namespaces"] == [[7, 201], [7, 202]]
    assert value["attempts"] == {}  # This map has no issued VM role.


def test_original_vm_attempt_history_survives_cri_collection_without_recapturing(
    partial, plugin, attest, release, inventory
):
    f = inventory
    f.scope["pod_uids"].pop("guest-relay")
    f.observer.pods = lambda: [f.vm]
    f.observer.cri = lambda *args: {"items": []}
    value = capture(f, partial, plugin, attest, release)
    assert value["members"]["guest"]["runtime_ids"] == ["d" * 64]
    assert value["members"]["guest"]["namespaces"] == [[7, 203]]
    assert value["attempts"]  # Absence alone would fail the next test.


@pytest.mark.parametrize("fault", [None, "missing", "ready", "pid", "host", "changed"])
def test_assigned_pre_cni_vm_requires_positive_original_live_namespace(
    partial, plugin, attest, release, inventory, monkeypatch, fault
):
    f = inventory
    f.path.unlink()
    f.scope["pod_uids"].pop("guest-relay")
    f.observer.pods = lambda: [f.vm]
    inspected = {"status": deepcopy(f.vm_sandbox), "info": {"pid": 303}}
    if fault == "ready":
        inspected["status"]["state"] = "SANDBOX_READY"
    elif fault == "pid":
        inspected["info"]["pid"] = 0
    reads = 0

    def cri(*args):
        nonlocal reads
        if args[0] == "pods":
            return {"items": [] if fault == "missing" else [deepcopy(f.vm_sandbox)]}
        reads += 1
        result = deepcopy(inspected)
        if fault == "changed" and reads == 2:
            result["info"]["pid"] = 404
        return result

    @contextlib.contextmanager
    def processes(pids):
        assert pids == (303,)
        yield lambda: None

    @contextlib.contextmanager
    def namespace(path):
        yield 301 if path == "/proc/1/ns/net" else 303

    f.observer.cri = cri
    monkeypatch.setattr(attest, "processes", processes)
    monkeypatch.setattr(plugin, "namespace", namespace)
    monkeypatch.setattr(plugin, "ns_identity", lambda fd: [7, 301 if fault == "host" else fd])
    if fault:
        with pytest.raises(ValueError):
            capture(f, partial, plugin, attest, release)
    else:
        value = capture(f, partial, plugin, attest, release)
        assert value["members"]["guest"] == {
            "runtime_ids": ["d" * 64],
            "namespaces": [[7, 303]],
            "links": [],
        }
        assert value["attempts"] == {}
        assert not partial.report(value)["observed_runtime_released"]


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "namespace",
        "boot",
        "request",
        "role",
        "runtime",
        "uid",
        "owner",
        "node",
        "scope",
        "extra-pod",
        "relay-journal",
        "relay-private",
        "relay-image",
    ],
)
def test_partial_capture_refuses_missing_unknown_or_reassigned_history(
    partial, plugin, attest, release, inventory, fault
):
    f = inventory
    if fault == "missing":
        f.path.unlink()
    elif fault in ("namespace", "boot", "request", "role"):
        if fault == "namespace":
            f.attempt["vm_identity"] = None
        elif fault == "boot":
            f.attempt["boot_id"] = str(uuid4())
        elif fault == "request":
            f.attempt["request"]["container_id"] = "e" * 64
        else:
            f.attempt["request"]["ifname"] = "eth1"
        plugin.save_record(f.path, f.attempt)
    elif fault == "runtime":
        f.vm_sandbox["id"] = "e" * 64
    elif fault == "uid":
        f.vm["metadata"]["uid"] = str(uuid4())
    elif fault == "owner":
        f.vm["metadata"]["ownerReferences"] = [{"uid": str(uuid4())}]
    elif fault == "node":
        f.vm["spec"]["nodeName"] = "foreign"
    elif fault == "scope":
        f.vm["metadata"]["labels"]["ads.io/sandbox-id"] = str(uuid4())
    elif fault == "extra-pod":
        extra = deepcopy(f.relay)
        extra["metadata"]["uid"] = str(uuid4())
        f.observer.pods = lambda: [f.vm, f.relay, extra]
    elif fault == "relay-journal":
        f.relay_record["complete"] = "false"
    elif fault == "relay-private":
        f.relay_record["private"] = [7, 999]
    else:
        f.relay["spec"]["containers"][0]["image"] = "foreign"
    with pytest.raises((ValueError, KeyError)):
        capture(f, partial, plugin, attest, release)


@pytest.mark.parametrize("stopped", [False, True])
def test_incomplete_and_stopped_relay_keep_original_namespace_inventory(
    partial, plugin, attest, release, inventory, stopped
):
    f = inventory
    f.relay_record["complete"] = False
    if stopped:
        f.relay_record["stopped"] = True
    value = capture(f, partial, plugin, attest, release)
    assert value["members"]["guest-relay"]["namespaces"] == [[7, 201], [7, 202]]
    assert value["members"]["guest-relay"]["runtime_ids"] == ["c" * 64, "b" * 64]
    assert not partial.report(value)["observed_runtime_released"]


@pytest.mark.parametrize("stopped", [False, True])
def test_no_private_identity_requires_terminal_original_relay_history(
    partial, plugin, attest, release, inventory, stopped
):
    f = inventory
    f.relay_record.update(complete=False, private=None, stopped=stopped)
    if stopped:
        value = capture(f, partial, plugin, attest, release)
        assert value["members"]["guest-relay"]["namespaces"] == [[7, 202]]
        assert not partial.report(value)["observed_runtime_released"]
    else:
        with pytest.raises(ValueError, match="history unavailable"):
            capture(f, partial, plugin, attest, release)


@pytest.mark.parametrize("fault", ["pod", "attempt", "boot"])
def test_capture_detects_changes_during_observation(
    partial, plugin, attest, release, inventory, monkeypatch, fault
):
    f = inventory
    original = partial.relay_inventory

    def change(*args):
        result = original(*args)
        if fault == "pod":
            f.vm["metadata"]["uid"] = str(uuid4())
        elif fault == "attempt":
            f.attempt["vm_identity"] = [7, 999]
            plugin.save_record(f.path, f.attempt)
        else:
            monkeypatch.setattr(release, "boot_id", lambda: str(uuid4()))
        return result

    monkeypatch.setattr(partial, "relay_inventory", change)
    with pytest.raises(ValueError):
        capture(f, partial, plugin, attest, release)


@pytest.mark.parametrize(
    "blocker",
    [
        None,
        "pod",
        "sandbox",
        "container",
        "host-link",
        "process",
        "late-pod",
        "changed-attempt",
        "lost-attempt",
        "boot",
    ],
)
def test_partial_observation_requires_all_actual_runtime_references_clear(
    partial, plugin, attest, release, inventory, monkeypatch, blocker
):
    f = inventory
    value = capture(f, partial, plugin, attest, release)
    observer = Observer()
    uid = f.vm["metadata"]["uid"]
    pod = {"metadata": {"uid": uid}}
    if blocker == "pod":
        observer.api = [pod]
    elif blocker == "sandbox":
        observer.sandboxes = [f.vm_sandbox | {"state": "SANDBOX_READY"}]
    elif blocker == "container":
        observer.containers = [{"podSandboxId": "d" * 64, "state": "CONTAINER_CREATED"}]
    elif blocker == "host-link":
        observer.links = [{"ifname": "peer1", "ifindex": 99}]
    elif blocker == "late-pod":

        def pods():
            observer.reads += 1
            return [pod] if observer.reads == 2 else []

        observer.pods = pods
    elif blocker == "changed-attempt":
        f.attempt["vm_identity"] = [7, 999]
        plugin.save_record(f.path, f.attempt)
    elif blocker == "lost-attempt":
        f.path.unlink()
    elif blocker == "boot":
        monkeypatch.setattr(release, "boot_id", lambda: str(uuid4()))
    monkeypatch.setattr(release, "process_references", lambda *args: int(blocker == "process"))
    if blocker in ("changed-attempt", "lost-attempt", "boot"):
        with pytest.raises(ValueError):
            partial.observe(plugin, observer, release, f.root, value)
    else:
        result = decode_partial_release(
            json.dumps(partial.observe(plugin, observer, release, f.root, value)).encode()
        )
        assert result.observed_runtime_released == (blocker is None)
        assert result.inventory_sha256 == partial.digest(value)
        assert not result.generation_retired and observer.reads == 2


def test_protected_capture_is_immutable_fenced_and_bound_to_original_map(
    partial, plugin, attest, release, inventory, monkeypatch
):
    f = inventory
    config_path = f.root / "config"
    plugin.save_record(config_path, f.config)
    monkeypatch.setattr(attest, "validate", lambda value: value)
    monkeypatch.setattr(attest, "Observer", lambda config: f.observer)
    monkeypatch.setattr(partial, "os", SimpleNamespace(geteuid=lambda: 0))
    modules = {"ads-ptp": plugin, "ads-ptp-attest": attest, "ads-ptp-release": release}
    monkeypatch.setattr(partial, "load", lambda name: modules[name])
    request = {
        **{key: f.scope[key] for key in ("generation", "sandbox_id", "pod_uids")},
        "action": "capture",
        "attestorConfig": str(config_path),
        "stateDir": str(f.root),
    }
    with pytest.raises(FileNotFoundError):
        partial.perform(request)
    plugin.retire(
        {
            **{key: f.scope[key] for key in ("generation", "sandbox_id", "network")},
            "stateDir": str(f.root),
        }
    )
    original = partial.perform(request)
    path = f.root / ("partial-release-" + f.scope["generation"] + ".json")
    saved = path.read_bytes()
    monkeypatch.setattr(partial, "capture", lambda *args: pytest.fail("must not recapture"))
    assert partial.perform(request) == original and path.read_bytes() == saved
    changed = {**request, "pod_uids": {"guest": str(uuid4())}}
    with pytest.raises(ValueError):
        partial.perform(changed)
    assert path.read_bytes() == saved
    monkeypatch.setattr(release, "boot_id", lambda: str(uuid4()))
    with pytest.raises(ValueError, match="boot"):
        partial.perform(request)
