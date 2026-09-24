from __future__ import annotations

import contextlib
import importlib.machinery
import importlib.util
import json
import os
import time
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from ads_commons.sandbox.ipc_release import decode_ipc_release


@pytest.fixture
def ipc():
    path = Path(__file__).parents[2] / "services/ads-ptp-tools/ads-ipc-release"
    loader = importlib.machinery.SourceFileLoader("ipc_node_release", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@pytest.fixture
def captured(ipc):
    return {
        "node": "application",
        "namespace": "sandboxes",
        **{k: str(uuid4()) for k in ("generation", "sandbox_id", "pod_uid", "volume_uid")},
        "boot_id": ipc.load("ads-ptp-release").boot_id(),
        "runtime_id": "a" * 64,
        "container_id": "b" * 64,
        "namespaces": {"net": [4, 101], "mnt": [4, 102], "pid": [4, 103]},
        "filesystem": {
            "device": "8:1",
            "root": "/storage/original",
            "target": "/ipc-state",
            "root_identity": [os.makedev(8, 1), 789],
        },
    }


def wanted(captured):
    return {
        k: captured[k]
        for k in ("node", "namespace", "generation", "sandbox_id", "pod_uid", "volume_uid")
    }


class Observer:
    def __init__(self, captured):
        self.deadline = time.monotonic() + 60
        self.config = {
            "node": captured["node"],
            "namespace": captured["namespace"],
            "container": "ipc",
            "mount": "/ipc-state",
            "kubectl": "/platform/kubectl",
            "kubeconfig": "/platform/config",
        }
        self.reads = 0
        self.api, self.sandboxes, self.containers = [], [], []

    def pods(self):
        self.reads += 1
        return deepcopy(self.api)

    def cri(self, command, *args):
        return (
            {"items": deepcopy(self.sandboxes)}
            if command == "pods"
            else {"containers": deepcopy(self.containers)}
        )


@pytest.fixture
def observer(captured):
    return Observer(captured)


@pytest.mark.parametrize(
    "field",
    [
        "generation",
        "pod_uid",
        "volume_uid",
        "boot_id",
        "runtime_id",
        "container_id",
        "namespaces",
        "filesystem",
    ],
)
def test_digest_binds_original_protected_inventory_without_leaking_it(ipc, captured, field):
    before = ipc.report(captured)
    changed = deepcopy(captured)
    if field == "namespaces":
        changed[field]["mnt"][1] += 1
    elif field == "filesystem":
        changed[field]["root"] += "/other"
    elif field in ("runtime_id", "container_id"):
        changed[field] = "c" * 64
    else:
        changed[field] = str(uuid4())
    after = ipc.report(changed)
    assert before["inventory_sha256"] != after["inventory_sha256"]
    assert not {"runtime_id", "container_id", "namespaces", "filesystem"} & set(before)
    assert not decode_ipc_release(json.dumps(before).encode()).observed_runtime_released


@pytest.mark.parametrize(
    "field,value",
    [
        ("boot_id", "bad"),
        ("runtime_id", "bad"),
        ("container_id", None),
        ("namespaces", {}),
        ("namespaces", {"net": [4, 1], "mnt": [True, 2], "pid": [4, 3]}),
        ("filesystem", {}),
        ("extra", True),
    ],
)
def test_corrupt_capture_is_never_reused(ipc, captured, field, value):
    with pytest.raises((ValueError, TypeError)):
        ipc.validate_snapshot({**captured, field: value}, wanted(captured))


@pytest.mark.parametrize(
    "field,value",
    [
        ("device", "8:2"),
        ("root", "/"),
        ("root", "/storage/../other"),
        ("target", "/"),
        ("root_identity", [0, 123]),
    ],
)
def test_ambiguous_volume_identity_fails_closed(ipc, captured, field, value):
    captured["filesystem"][field] = value
    with pytest.raises(ValueError):
        ipc.validate_snapshot(captured, wanted(captured))


@pytest.mark.parametrize(
    "field",
    [
        "pods",
        "ready_sandboxes",
        "live_containers",
        "process_references",
        "mount_references",
    ],
)
def test_every_leftover_blocks_positive_verdict(ipc, captured, field):
    counts = dict.fromkeys(
        ("pods", "ready_sandboxes", "live_containers", "process_references", "mount_references"), 0
    )
    assert ipc.report(captured, counts)["observed_runtime_released"]
    counts[field] = 1
    report = ipc.report(captured, counts)
    assert not decode_ipc_release(json.dumps(report).encode()).observed_runtime_released
    for invalid in (-1, True, 2147483648):
        with pytest.raises(ValueError):
            ipc.report(captured, {**counts, field: invalid})


@pytest.mark.parametrize(
    "kind",
    [
        "pod",
        "replacement",
        "sandbox",
        "unknown-sandbox",
        "container",
        "unknown-container",
        "process",
        "mount",
        "late-pod",
    ],
)
def test_observation_is_positive_and_repeated_not_api_absence(
    ipc, captured, observer, monkeypatch, kind
):
    pod = {"metadata": {"uid": captured["pod_uid"]}}
    if kind in ("pod", "replacement"):
        observer.api = [pod]
        if kind == "replacement":
            pod["metadata"] = {
                "uid": str(uuid4()),
                "labels": {
                    "ads.io/attachment-generation": captured["generation"],
                    "app.kubernetes.io/component": "ads-sandbox-ipc",
                },
            }
    elif kind.endswith("sandbox"):
        observer.sandboxes = [
            {
                "id": captured["runtime_id"],
                "metadata": {"uid": captured["pod_uid"]},
                "state": "UNKNOWN" if kind.startswith("unknown") else "SANDBOX_READY",
            }
        ]
    elif kind.endswith("container"):
        observer.containers = [
            {
                "id": captured["container_id"],
                "podSandboxId": captured["runtime_id"],
                "state": "UNKNOWN" if kind.startswith("unknown") else "CONTAINER_RUNNING",
            }
        ]
    elif kind == "late-pod":

        def pods():
            observer.reads += 1
            return [] if observer.reads == 1 else [pod]

        observer.pods = pods
    monkeypatch.setattr(
        ipc, "references", lambda *args: (int(kind == "process"), int(kind == "mount"))
    )
    result = ipc.observe(observer, captured, ipc.load("ads-ptp-release"))
    assert observer.reads == 2 and not result["observed_runtime_released"]


def test_matching_clear_observation_and_reboot_refusal(ipc, captured, observer, monkeypatch):
    release = ipc.load("ads-ptp-release")
    monkeypatch.setattr(ipc, "references", lambda *args: (0, 0))
    assert ipc.observe(observer, captured, release)["observed_runtime_released"]
    monkeypatch.setattr(release, "boot_id", lambda: str(uuid4()))
    with pytest.raises(ValueError, match="boot"):
        ipc.observe(observer, captured, release)


@pytest.fixture
def live(ipc, captured, observer, tmp_path):
    name = "ads-sandbox-ipc-" + captured["sandbox_id"]
    pod = {
        "metadata": {
            "name": name,
            "namespace": captured["namespace"],
            "uid": captured["pod_uid"],
            "labels": {
                "ads.io/sandbox-id": captured["sandbox_id"],
                "ads.io/attachment-generation": captured["generation"],
                "app.kubernetes.io/component": "ads-sandbox-ipc",
            },
        },
        "spec": {
            "nodeName": captured["node"],
            "containers": [
                {"name": "ipc", "volumeMounts": [{"name": "pids", "mountPath": "/ipc-state"}]}
            ],
            "volumes": [{"name": "pids", "persistentVolumeClaim": {"claimName": name}}],
        },
        "status": {
            "containerStatuses": [
                {"name": "ipc", "containerID": "cri-o://" + captured["container_id"]}
            ]
        },
    }
    pvc = {
        "metadata": {
            "name": name,
            "namespace": captured["namespace"],
            "uid": captured["volume_uid"],
        },
        "spec": {"volumeMode": "Filesystem"},
        "status": {"phase": "Bound"},
    }
    observer.api = [pod]
    observer.command = lambda *args: deepcopy(pvc)
    sandbox = {
        "status": {
            "id": captured["runtime_id"],
            "state": "SANDBOX_READY",
            "metadata": {
                "uid": captured["pod_uid"],
                "namespace": captured["namespace"],
                "name": name,
            },
        },
        "info": {"pid": 21},
    }
    container = {
        "status": {
            "id": captured["container_id"],
            "state": "CONTAINER_RUNNING",
            "metadata": {"name": "ipc"},
            "labels": {
                "io.kubernetes.pod.uid": captured["pod_uid"],
                "io.kubernetes.pod.namespace": captured["namespace"],
            },
        },
        "info": {"pid": 22, "sandboxID": captured["runtime_id"]},
    }

    def cri(command, *args):
        return deepcopy(
            {"pods": {"items": [sandbox["status"]]}, "inspectp": sandbox, "inspect": container}[
                command
            ]
        )

    observer.cri = cri
    proc = tmp_path / "proc"
    for pid in (1, 22):
        (proc / str(pid) / "ns").mkdir(parents=True)
        for ns in ("net", "pid", "mnt"):
            (proc / str(pid) / "ns" / ns).touch()
    volume = proc / "22/root/ipc-state"
    volume.mkdir(parents=True)
    device = volume.stat().st_dev
    table = (
        f"10 1 {os.major(device)}:{os.minor(device)} "
        "/storage/original /ipc-state rw - ext4 /dev/test rw\n"
    )
    (proc / "22/mountinfo").write_text(table)

    @contextlib.contextmanager
    def processes(pids):
        assert pids == (21, 22)
        yield lambda: None

    attestor = SimpleNamespace(processes=processes)
    return SimpleNamespace(
        pod=pod,
        pvc=pvc,
        sandbox=sandbox,
        container=container,
        observer=observer,
        proc=proc,
        attestor=attestor,
    )


def test_capture_uses_exact_kubernetes_cri_and_filesystem_identity(ipc, captured, live):
    result = ipc.capture(
        live.observer, wanted(captured), live.attestor, ipc.load("ads-ptp-release"), live.proc
    )
    assert result["container_id"] == captured["container_id"]
    assert result["filesystem"]["root"] == "/storage/original"
    assert live.observer.reads == 2
    assert ipc.validate_snapshot(result, wanted(captured)) == result


@pytest.mark.parametrize(
    "fault",
    [
        "pod-uid",
        "node",
        "owner",
        "generation",
        "host",
        "pvc-uid",
        "pvc-block",
        "sidecar",
        "subpath",
        "runtime",
        "container-uid",
        "container-state",
        "sandbox-uid",
        "pid",
    ],
)
def test_capture_rejects_mismatched_or_partial_runtime(ipc, captured, live, fault):
    if fault == "pod-uid":
        live.pod["metadata"]["uid"] = str(uuid4())
    elif fault == "node":
        live.pod["spec"]["nodeName"] = "other"
    elif fault == "owner":
        live.pod["metadata"]["ownerReferences"] = [{"uid": str(uuid4())}]
    elif fault == "generation":
        live.pod["metadata"]["labels"]["ads.io/attachment-generation"] = str(uuid4())
    elif fault == "host":
        live.pod["spec"]["hostPID"] = True
    elif fault == "pvc-uid":
        live.pvc["metadata"]["uid"] = str(uuid4())
    elif fault == "pvc-block":
        live.pvc["spec"]["volumeMode"] = "Block"
    elif fault == "sidecar":
        live.pod["spec"]["containers"].append({"name": "sidecar"})
    elif fault == "subpath":
        live.pod["spec"]["containers"][0]["volumeMounts"][0]["subPath"] = "fragment"
    elif fault == "runtime":
        live.pod["status"]["containerStatuses"][0]["containerID"] = "unknown://value"
    elif fault == "container-uid":
        live.container["status"]["labels"]["io.kubernetes.pod.uid"] = str(uuid4())
    elif fault == "container-state":
        live.container["status"]["state"] = "CONTAINER_EXITED"
    elif fault == "sandbox-uid":
        live.sandbox["status"]["metadata"]["uid"] = str(uuid4())
    else:
        live.container["info"]["pid"] = True
    with pytest.raises(ValueError):
        ipc.capture(
            live.observer, wanted(captured), live.attestor, ipc.load("ads-ptp-release"), live.proc
        )


@pytest.mark.parametrize(
    "text", ["", "broken", "1 2 8:1 / /x rw - ext4", "1 2 xx / /x rw - ext4 /dev/x rw"]
)
def test_incomplete_mount_observations_fail_closed(ipc, text):
    with pytest.raises(ValueError):
        ipc.mounts(text)


def test_mount_escapes_and_subtree_boundaries(ipc):
    result = ipc.mounts("1 2 8:1 /storage/a\\040b /alias rw - ext4 /dev/x rw\n")
    assert result[1]["root"] == "/storage/a b"
    assert ipc.beneath("/storage/a/file", "/storage/a")
    assert not ipc.beneath("/storage/ab/file", "/storage/a")


@pytest.fixture
def operation(ipc, captured, observer, tmp_path, monkeypatch):
    plugin = ipc.load("ads-ptp")
    release = ipc.load("ads-ptp-release")
    root = tmp_path / "protected"
    root.mkdir(mode=0o700)
    settings = {**observer.config, "stateDir": str(root)}
    path = root / "config"
    plugin.save_record(path, settings)
    request = {
        "action": "capture",
        "config": str(path),
        "inventory_sha256": None,
        **{k: captured[k] for k in ("generation", "sandbox_id", "pod_uid", "volume_uid")},
    }
    attestor = SimpleNamespace(Observer=lambda settings: observer)
    modules = {"ads-ptp": plugin, "ads-ptp-attest": attestor, "ads-ptp-release": release}
    monkeypatch.setattr(ipc, "load", lambda name: modules[name])
    monkeypatch.setattr(ipc, "config", lambda value: value)
    monkeypatch.setattr(
        ipc, "os", SimpleNamespace(geteuid=lambda: 0, major=os.major, minor=os.minor)
    )
    monkeypatch.setattr(ipc, "capture", lambda *a: deepcopy(captured))
    monkeypatch.setattr(ipc, "references", lambda *a: (0, 0))
    return SimpleNamespace(request=request, root=root, plugin=plugin, release=release)


def test_capture_retry_preserves_original_and_observe_requires_matching_digest(
    ipc, captured, operation, monkeypatch
):
    first = ipc.perform(operation.request)
    monkeypatch.setattr(ipc, "capture", lambda *args: pytest.fail("must not recapture"))
    assert ipc.perform(operation.request) == first
    request = {
        **operation.request,
        "action": "observe",
        "inventory_sha256": first["inventory_sha256"],
    }
    assert ipc.perform(request)["observed_runtime_released"]
    with pytest.raises(ValueError, match="inventory changed"):
        ipc.perform({**request, "inventory_sha256": "0" * 64})
    saved = operation.plugin.read_record(
        operation.root / ("ipc-release-" + captured["generation"] + ".json")
    )
    assert saved == captured
    for key in ("pod_uid", "volume_uid", "sandbox_id"):
        with pytest.raises(ValueError, match="scope"):
            ipc.perform({**operation.request, key: str(uuid4())})


def test_missing_capture_is_not_release_and_reboot_does_not_replace_it(
    ipc, captured, operation, monkeypatch
):
    with pytest.raises(FileNotFoundError):
        ipc.perform({**operation.request, "action": "observe", "inventory_sha256": "a" * 64})
    first = ipc.perform(operation.request)
    monkeypatch.setattr(operation.release, "boot_id", lambda: str(uuid4()))
    for request in (
        operation.request,
        {**operation.request, "action": "observe", "inventory_sha256": first["inventory_sha256"]},
    ):
        with pytest.raises(ValueError, match="boot"):
            ipc.perform(request)


def test_failed_directory_sync_retains_capture_for_exact_retry(
    ipc, captured, operation, monkeypatch
):
    original = operation.plugin.sync_directory
    monkeypatch.setattr(
        operation.plugin,
        "sync_directory",
        lambda *args: (_ for _ in ()).throw(OSError("sync failure")),
    )
    with pytest.raises(OSError):
        ipc.perform(operation.request)
    monkeypatch.setattr(operation.plugin, "sync_directory", original)
    monkeypatch.setattr(ipc, "capture", lambda *args: pytest.fail("must not recapture"))
    assert ipc.perform(operation.request) == ipc.report(captured)


def test_busy_generation_lock_does_not_start_capture(ipc, captured, operation):
    with operation.plugin.generation_lock(operation.root, captured["generation"]):
        with pytest.raises(BlockingIOError):
            ipc.perform(operation.request)
    assert not list(operation.root.glob("ipc-release-*"))


@pytest.mark.parametrize(
    "change",
    [
        {"action": "delete"},
        {"extra": True},
        {"generation": "../bad"},
        {"pod_uid": "bad"},
        {"inventory_sha256": "a" * 64},
    ],
)
def test_invalid_requests_never_create_inventory(ipc, operation, change):
    with pytest.raises(ValueError):
        ipc.perform({**operation.request, **change})
    assert not list(operation.root.glob("ipc-release-*"))


@pytest.fixture
def process_tree(tmp_path):
    proc = tmp_path / "proc"
    process = proc / "20"
    task = process / "task/20"
    (task / "ns").mkdir(parents=True)
    (task / "fd").mkdir()
    (task / "fdinfo").mkdir()
    (process / "map_files").mkdir()
    (task / "stat").write_text("20 (fixture) S 0 0 0 0 0 0\n")
    (process / "cmdline").write_text("native fixture")
    (task / "cgroup").write_text("0::/unrelated")
    for ns in ("net", "pid", "mnt"):
        (task / "ns" / ns).touch()
    (task / "cwd").symlink_to("/dev/null")
    (task / "root").symlink_to("/dev/null")
    (task / "exe").symlink_to("/dev/null")
    (task / "mountinfo").write_text("1 2 8:1 / / rw - ext4 /dev/x rw\n")
    return proc, process, task


@pytest.mark.parametrize(
    "kind", ["namespace", "cgroup", "command", "mount", "descriptor", "detached"]
)
def test_actual_scanner_detects_each_reference_type(ipc, captured, process_tree, tmp_path, kind):
    proc, process, task = process_tree
    release = ipc.load("ads-ptp-release")
    if kind == "namespace":
        info = (task / "ns/net").stat()
        captured["namespaces"]["net"] = [info.st_dev, info.st_ino]
    elif kind == "cgroup":
        (task / "cgroup").write_text("0::/kubepods-" + captured["pod_uid"].replace("-", "_"))
    elif kind == "command":
        (process / "cmdline").write_text("shim " + captured["container_id"])
    elif kind == "mount":
        (task / "mountinfo").write_text(
            "1 2 8:1 /storage/original /other-alias rw - ext4 /dev/x rw\n"
        )
    else:
        held = tmp_path / "held"
        held.touch()
        info = held.stat()
        captured["filesystem"]["root_identity"] = [info.st_dev, info.st_ino]
        captured["filesystem"]["device"] = device = (
            f"{os.major(info.st_dev)}:{os.minor(info.st_dev)}"
        )
        (task / "fd/5").symlink_to(held)
        (task / "fdinfo/5").write_text("mnt_id:\t44\n")
        root = "/storage/original" if kind == "descriptor" else "/"
        mount_id = 44 if kind == "descriptor" else 45
        (task / "mountinfo").write_text(
            f"{mount_id} 2 {device} {root} /alias rw - ext4 /dev/x rw\n"
        )
    references = ipc.references(captured, time.monotonic() + 5, release, proc)
    assert sum(references) > 0
    assert references[0] > 0 if kind in ("namespace", "cgroup", "command") else references[1] > 0


def test_scan_limits_and_unreadable_or_incomplete_state_are_errors(
    ipc, captured, process_tree, monkeypatch
):
    proc, _, task = process_tree
    release = ipc.load("ads-ptp-release")
    assert ipc.references(captured, time.monotonic() + 5, release, proc) == (0, 0)
    with pytest.raises(ValueError, match="bound"):
        ipc.references(captured, time.monotonic() - 1, release, proc)
    original = release.bounded_text

    def denied(path, *args):
        if path == task / "mountinfo":
            raise PermissionError
        return original(path, *args)

    monkeypatch.setattr(release, "bounded_text", denied)
    with pytest.raises(PermissionError):
        ipc.references(captured, time.monotonic() + 5, release, proc)


@pytest.mark.parametrize("kind", ["map", "exe"])
def test_scanner_keeps_mapped_or_executable_file_without_original_fd(
    ipc, captured, process_tree, tmp_path, kind
):
    proc, process, task = process_tree
    held = tmp_path / "mapped"
    held.write_text("synthetic")
    info = held.stat()
    captured["filesystem"]["root_identity"] = [info.st_dev, info.st_ino]
    device = f"{os.major(info.st_dev)}:{os.minor(info.st_dev)}"
    captured["filesystem"]["device"] = device
    (task / "mountinfo").write_text(f"1 2 {device} / / rw - ext4 /dev/x rw\n")
    if kind == "map":
        (process / "map_files/100-200").symlink_to(held)
    else:
        (task / "exe").unlink()
        (task / "exe").symlink_to(held)
    # The fake namespace table has no mount ID for the real referenced file:
    # exactly the ambiguity that a detached reference must not turn into zero.
    result = ipc.references(captured, time.monotonic() + 5, ipc.load("ads-ptp-release"), proc)
    assert result[1] > 0 and not list((task / "fd").iterdir())


@pytest.mark.parametrize("state,flags", [("Z", 0), ("X", 0), ("I", 0x00200000)])
def test_only_positively_identified_nonuserspace_tasks_can_skip_scan(
    ipc, captured, process_tree, state, flags
):
    proc, _, task = process_tree
    (task / "stat").write_text(f"20 (fixture) {state} 0 0 0 0 0 {flags}\n")
    (task / "mountinfo").unlink()
    assert ipc.references(captured, time.monotonic() + 5, ipc.load("ads-ptp-release"), proc) == (
        0,
        0,
    )


def test_unknown_live_task_with_missing_observation_is_not_release(ipc, captured, process_tree):
    proc, _, task = process_tree
    (task / "mountinfo").unlink()
    with pytest.raises(ValueError, match="incomplete"):
        ipc.references(captured, time.monotonic() + 5, ipc.load("ads-ptp-release"), proc)
