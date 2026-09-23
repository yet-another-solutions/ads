# ruff: noqa: F811
from __future__ import annotations

import contextlib
import importlib.machinery
import importlib.util
import os
import time
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from test_ptp_attachment import inputs, plugin  # noqa: F401


@pytest.fixture
def release():
    path = Path(__file__).parents[2] / "services/ads-ptp-tools/ads-ptp-release"
    loader = importlib.machinery.SourceFileLoader("node_release", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@pytest.fixture
def snapshot(release):
    return {
        "node": "worker",
        "namespace": "sandboxes",
        "network": "ads-private",
        "generation": str(uuid4()),
        "sandbox_id": str(uuid4()),
        "boot_id": release.boot_id(),
        "pod_uids": [str(uuid4()) for _ in range(4)],
        "runtime_ids": [c * 64 for c in "abcd"],
        "namespaces": [[4, i] for i in range(100, 106)],
        "links": [{"ifname": "peer1", "ifindex": 20}, {"ifname": "peer2", "ifindex": 21}],
    }


def scope(snapshot):
    return {
        key: snapshot[key] for key in ("node", "namespace", "network", "generation", "sandbox_id")
    }


class Observer:
    def __init__(self):
        self.deadline = time.monotonic() + 60
        self.api = []
        self.sandboxes = []
        self.containers = []
        self.links = []
        self.reads = 0

    def pods(self):
        self.reads += 1
        return self.api

    def cri(self, command, *args):
        return {"items": self.sandboxes} if command == "pods" else {"containers": self.containers}

    def command(self, *args):
        assert args == ("ip", "-j", "link")
        return self.links


@pytest.fixture
def observer():
    return Observer()


@pytest.mark.parametrize(
    "change",
    [
        {"node": "foreign"},
        {"extra": 1},
        {"boot_id": "bad"},
        {"pod_uids": []},
        {"runtime_ids": ["a" * 64] * 4},
        {"namespaces": [[4, 1]] * 6},
        {"namespaces": [[True, i] for i in range(6)]},
        {"links": []},
        {"links": [{"ifname": "x", "ifindex": 1}] * 2},
    ],
)
def test_snapshot_validation_fails_closed(release, snapshot, change):
    assert release.validate_snapshot(snapshot, scope(snapshot)) == snapshot
    with pytest.raises((ValueError, TypeError)):
        release.validate_snapshot({**snapshot, **change}, scope(snapshot))


def test_node_boot_change_is_not_release(
    release, plugin, snapshot, observer, tmp_path, monkeypatch
):
    monkeypatch.setattr(release, "boot_id", lambda: str(uuid4()))
    with pytest.raises(ValueError, match="boot changed"):
        release.observe(plugin, observer, tmp_path, snapshot)
    assert observer.reads == 0


def test_empty_observations_are_repeated_not_retirement(
    release, plugin, snapshot, observer, tmp_path, monkeypatch
):
    monkeypatch.setattr(release, "process_references", lambda *args: 0)
    result = release.observe(plugin, observer, tmp_path, snapshot)
    assert result["observed_runtime_released"] and not result["generation_retired"]
    assert not any(result["leftovers"].values()) and observer.reads == 2


@pytest.mark.parametrize(
    "leftover",
    [
        "pod",
        "replacement-pod",
        "sandbox",
        "container",
        "created-container",
        "host-index",
        "host-name",
        "process",
        "late-pod",
        "early-pod",
    ],
)
def test_each_positive_blocker_prevents_release(
    release, plugin, snapshot, observer, tmp_path, monkeypatch, leftover
):
    monkeypatch.setattr(release, "process_references", lambda *args: int(leftover == "process"))
    pod = {"metadata": {"uid": snapshot["pod_uids"][0]}}
    if leftover in ("pod", "replacement-pod"):
        observer.api = [pod]
        if leftover == "replacement-pod":
            pod["metadata"] = {
                "uid": str(uuid4()),
                "labels": {"ads.io/attachment-generation": snapshot["generation"]},
            }
    elif leftover == "sandbox":
        observer.sandboxes = [
            {
                "id": snapshot["runtime_ids"][0],
                "metadata": {"uid": snapshot["pod_uids"][0]},
                "state": "SANDBOX_READY",
            }
        ]
    elif leftover in ("container", "created-container"):
        observer.containers = [
            {
                "podSandboxId": snapshot["runtime_ids"][0],
                "state": "CONTAINER_RUNNING" if leftover == "container" else "CONTAINER_CREATED",
            }
        ]
    elif leftover in ("host-index", "host-name"):
        observer.links = [
            {
                "ifindex": 20 if leftover == "host-index" else 900,
                "ifname": "peer1" if leftover == "host-name" else "new",
            }
        ]
    elif leftover in ("late-pod", "early-pod"):

        def pods():
            observer.reads += 1
            return [pod] if (observer.reads == 2) == (leftover == "late-pod") else []

        observer.pods = pods
    result = release.observe(plugin, observer, tmp_path, snapshot)
    assert not result["observed_runtime_released"] and any(result["leftovers"].values())


def test_incomplete_api_and_process_observations_never_become_absence(
    release, plugin, snapshot, observer, tmp_path, monkeypatch
):
    observer.api = [{}]
    with pytest.raises(KeyError):
        release.observe(plugin, observer, tmp_path, snapshot)
    observer.api = []
    monkeypatch.setattr(
        release,
        "process_references",
        lambda *args: (_ for _ in ()).throw(PermissionError("unreadable task")),
    )
    with pytest.raises(PermissionError):
        release.observe(plugin, observer, tmp_path, snapshot)


def fake_proc(tmp_path):
    proc = tmp_path / "proc"
    task = proc / "123" / "task" / "124"
    (task / "ns").mkdir(parents=True)
    (task / "fd").mkdir()
    (task / "ns/net").touch()
    (task / "mountinfo").write_text("")
    (task / "stat").write_text("124 (task) S 0")
    (proc / "123" / "cmdline").write_text("ordinary")
    return proc, task


@pytest.mark.parametrize("kind", ["task", "fd", "mount", "runtime"])
def test_process_scan_checks_nonleader_tasks_fds_mount_roots_and_runtime_ids(
    release, snapshot, tmp_path, kind
):
    proc, task = fake_proc(tmp_path)
    if kind == "task":
        info = (task / "ns/net").stat()
        snapshot["namespaces"][0] = [info.st_dev, info.st_ino]
    elif kind == "fd":
        (task / "fd/5").symlink_to("net:[100]")
    elif kind == "mount":
        (task / "mountinfo").write_text("12 1 0:4 net:[100] /other rw - nsfs nsfs rw\n")
    else:
        (proc / "123" / "cmdline").write_text("shim\0" + snapshot["runtime_ids"][0])
    assert release.process_references(snapshot, time.monotonic() + 5, proc) > 0


def test_scan_deadline_oversize_missing_live_task_and_zombie(release, snapshot, tmp_path):
    proc, task = fake_proc(tmp_path)
    with pytest.raises(ValueError, match="bound"):
        release.process_references(snapshot, 0, proc)
    (task / "ns/net").unlink()
    with pytest.raises(ValueError, match="disappeared"):
        release.process_references(snapshot, time.monotonic() + 5, proc)
    (task / "stat").write_text("124 (task) Z 0")
    assert release.process_references(snapshot, time.monotonic() + 5, proc) == 0
    data = tmp_path / "large"
    data.write_bytes(b"x" * 10)
    with pytest.raises(ValueError, match="bound"):
        release.bounded_text(data, 9)


def test_unreadable_mount_and_fd_are_not_silently_ignored(release, snapshot, tmp_path, monkeypatch):
    proc, task = fake_proc(tmp_path)
    (task / "fd/5").symlink_to("net:[100]")
    original = os.readlink

    def denied(path, *args, **kwargs):
        if str(path).endswith("/fd/5"):
            raise PermissionError("denied")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(release.os, "readlink", denied)
    with pytest.raises(PermissionError):
        release.process_references(snapshot, time.monotonic() + 5, proc)


@pytest.fixture
def operation(release, plugin, inputs, snapshot, monkeypatch):
    config, _, _ = inputs
    request = {
        "action": "capture",
        "attestorConfig": str(Path(config["stateDir"]) / "config"),
        "stateDir": config["stateDir"],
        "generation": snapshot["generation"],
        "sandbox_id": snapshot["sandbox_id"],
    }
    settings = {key: snapshot[key] for key in ("node", "namespace", "network")}
    plugin.save_record(Path(request["attestorConfig"]), settings)
    observer = Observer()
    attestor = SimpleNamespace(validate=lambda value: value, Observer=lambda config: observer)
    monkeypatch.setattr(release, "load", lambda name: plugin if name == "ads-ptp" else attestor)
    monkeypatch.setattr(release, "os", SimpleNamespace(geteuid=lambda: 0))
    monkeypatch.setattr(release, "capture", lambda *args: deepcopy(snapshot))
    monkeypatch.setattr(release, "process_references", lambda *args: 0)
    plugin.retire(
        {key: request[key] for key in ("stateDir", "generation", "sandbox_id")}
        | {"network": snapshot["network"]}
    )
    return request, observer


def test_capture_is_immutable_and_observe_requires_exact_durable_fence(
    release, plugin, snapshot, operation, monkeypatch
):
    request, observer = operation
    result = release.perform(request)
    assert result["release_inventory_captured"] and not result["observed_runtime_released"]
    monkeypatch.setattr(release, "capture", lambda *args: pytest.fail("must not recapture"))
    assert release.perform(request) == result
    request["action"] = "observe"
    fence = Path(request["stateDir"]) / ("retired-" + request["generation"] + ".json")
    fence.unlink()
    with pytest.raises(FileNotFoundError):
        release.perform(request)
    plugin.retire(
        {key: request[key] for key in ("stateDir", "generation", "sandbox_id")}
        | {"network": snapshot["network"]}
    )
    assert release.perform(request)["observed_runtime_released"]
    snapshot_file = Path(request["stateDir"]) / ("release-" + request["generation"] + ".json")
    assert plugin.read_record(snapshot_file) == snapshot


def test_capture_cannot_start_without_retirement(release, plugin, snapshot, operation):
    request, _ = operation
    fence = Path(request["stateDir"]) / ("retired-" + request["generation"] + ".json")
    fence.unlink()
    with pytest.raises(FileNotFoundError):
        release.perform(request)


def test_capture_retry_reasserts_sync_without_overwriting_identities(
    release, plugin, snapshot, operation, monkeypatch
):
    request, _ = operation
    release.perform(request)
    synced = []
    original = plugin.sync_directory

    def sync(path):
        synced.append(path)
        original(path)

    monkeypatch.setattr(plugin, "sync_directory", sync)
    release.perform(request)
    assert synced == [Path(request["stateDir"])]


@pytest.mark.parametrize("bad", [{}, {"network": "foreign"}, {"generation": "wrong"}])
def test_malformed_or_foreign_fence_rejects_capture_and_observation(
    release, plugin, operation, bad
):
    request, _ = operation
    fence = Path(request["stateDir"]) / ("retired-" + request["generation"] + ".json")
    plugin.save_record(fence, bad)
    for action in ("capture", "observe"):
        with pytest.raises(ValueError, match="admission fence"):
            release.perform({**request, "action": action})
    assert not list(Path(request["stateDir"]).glob("release-*.json"))


def test_changed_boot_during_scan_cannot_return_release(
    release, plugin, snapshot, observer, tmp_path, monkeypatch
):
    sequence = iter((snapshot["boot_id"], str(uuid4())))
    monkeypatch.setattr(release, "boot_id", lambda: next(sequence))
    monkeypatch.setattr(release, "process_references", lambda *args: 0)
    with pytest.raises(ValueError, match="boot changed during"):
        release.observe(plugin, observer, tmp_path, snapshot)


def test_missing_capture_is_not_empty_release(release, operation):
    request, _ = operation
    with pytest.raises(FileNotFoundError):
        release.perform({**request, "action": "observe"})


@pytest.mark.parametrize(
    "fault",
    [
        "none",
        "live-binding",
        "vm-uid",
        "scope",
        "duplicate-side",
        "namespace-collision",
        "host-peer",
    ],
)
def test_capture_uses_real_adapter_boundaries_and_exact_both_journals(
    release, plugin, inputs, snapshot, monkeypatch, fault
):
    config, env, binding = inputs
    root = Path(config["stateDir"])
    bindings = []
    for i, side in enumerate(("guest", "egress")):
        req = plugin.request(
            config,
            {
                **env,
                "CNI_CONTAINERID": snapshot["runtime_ids"][i * 2],
                "CNI_IFNAME": "eth0" if i == 0 else "eth1",
                "CNI_ARGS": "K8S_POD_UID=" + snapshot["pod_uids"][i * 2],
            },
        )
        value = {
            **binding,
            "pod_uid": req["pod_uid"],
            "ifname": req["ifname"],
            "role": side,
            "generation": snapshot["generation"],
            "sandbox_id": snapshot["sandbox_id"],
            "relay_pod_uid": snapshot["pod_uids"][i * 2 + 1],
            "relay_runtime_id": snapshot["runtime_ids"][i * 2 + 1],
            "private": {"path": f"/private/{i}", "identity": snapshot["namespaces"][i * 3 + 1]},
            "transport": {"path": f"/transport/{i}", "identity": snapshot["namespaces"][i * 3 + 2]},
        }
        if side == "egress":
            value.update(address="10.10.30.1/24", gateway=None)
        if fault == "scope":
            value["sandbox_id"] = str(uuid4())
        if fault == "duplicate-side":
            value.update(role="guest", address="10.10.30.2/24", gateway="10.10.30.1")
        bindings.append(value)
        plugin.save_record(
            root / (req["key"] + ".json"),
            {
                "request": req,
                "binding": value,
                "vm_identity": snapshot["namespaces"][i * 3 + int(fault == "namespace-collision")],
                "result": {"test": i},
                "indices": {"vm": 11, "peer": 12},
            },
        )
    checks = []
    monkeypatch.setattr(plugin, "check", lambda *args: checks.append(args))

    @contextlib.contextmanager
    def namespace(path, expected):
        yield int(path.rsplit("/", 1)[1])

    monkeypatch.setattr(plugin, "namespace", namespace)
    monkeypatch.setattr(plugin, "links", lambda fd: {"eth0": {"link_index": 20 + fd}})
    observer = Observer()
    observer.links = snapshot["links"] if fault != "host-peer" else []

    def cri(command, option, fmt, runtime):
        index = snapshot["runtime_ids"].index(runtime)
        return {
            "status": {
                "id": runtime,
                "state": "SANDBOX_READY",
                "metadata": {
                    "uid": snapshot["pod_uids"][index] if fault != "vm-uid" else str(uuid4()),
                    "namespace": snapshot["namespace"],
                },
            }
        }

    observer.cri = cri

    def observed(o, p, req):
        value = next(value for value in bindings if value["pod_uid"] == req["pod_uid"])
        return {**value, "mtu": 999} if fault == "live-binding" else value

    attestor = SimpleNamespace(observe_binding=observed)
    if fault != "none":
        with pytest.raises(ValueError):
            release.capture(plugin, attestor, observer, root, scope(snapshot))
        return
    captured = release.capture(plugin, attestor, observer, root, scope(snapshot))
    assert set(captured["pod_uids"]) == set(snapshot["pod_uids"])
    assert len(checks) == 2
    next(root.glob("*.json")).unlink()
    with pytest.raises(ValueError, match="both live"):
        release.capture(plugin, attestor, observer, root, scope(snapshot))
