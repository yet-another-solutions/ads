from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import stat
import time
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import msgspec
import pytest

from ads_commons.sandbox.block_release import decode_block_release


@pytest.fixture
def block(tmp_path, monkeypatch):
    path = Path(__file__).parents[2] / "services/ads-ptp-tools/ads-block-release"
    loader = importlib.machinery.SourceFileLoader("block_release_helper", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    scope = {
        "node": "worker",
        "namespace": "sandboxes",
        "network": "ads-ptp",
        "generation": str(uuid4()),
        "sandbox_id": str(uuid4()),
    }
    uid, pvc_uid = str(uuid4()), str(uuid4())
    volumes = {"workspace": {"name": "workspace", "pod_uid": uid, "volume_uid": pvc_uid}}
    runtime = {**scope, "boot_id": str(uuid4()), "pod_uids": [uid], "inventory_sha256": "b" * 64}
    pod = {
        "metadata": {
            "uid": uid,
            "namespace": scope["namespace"],
            "labels": {
                "ads.io/sandbox-id": scope["sandbox_id"],
                "ads.io/attachment-generation": scope["generation"],
            },
        },
        "spec": {
            "nodeName": scope["node"],
            "volumes": [{"name": "workspace", "persistentVolumeClaim": {"claimName": "workspace"}}],
            "containers": [
                {"volumeDevices": [{"name": "workspace", "devicePath": "/dev/workspace"}]}
            ],
        },
    }
    pvc = {
        "metadata": {"uid": pvc_uid},
        "status": {"phase": "Bound"},
        "spec": {"volumeName": "pv-original", "volumeMode": "Block"},
    }
    pv = {
        "metadata": {"uid": str(uuid4())},
        "spec": {
            "claimRef": {"uid": pvc_uid, "name": "workspace", "namespace": scope["namespace"]},
            "csi": {"driver": "fixture.csi", "volumeHandle": "original"},
        },
    }
    observer = SimpleNamespace(
        config={
            "kubectl": "/fixture/kubectl",
            "kubeconfig": "/fixture/config",
            "namespace": scope["namespace"],
        },
        pods=lambda: deepcopy([pod]),
        command=lambda *args: deepcopy(pvc if "pvc" in args else pv),
    )
    release = module.load("ads-ptp-release")
    monkeypatch.setattr(release, "boot_id", lambda: runtime["boot_id"])
    root, sysfs, proc = tmp_path / "kubelet", tmp_path / "sysfs", tmp_path / "proc"
    root.mkdir()
    proc.mkdir()
    device = os.makedev(7, 123)
    kernel = sysfs / "7:123"
    (kernel / "holders").mkdir(parents=True)
    mapping = module.paths(root, uid, "pv-original")
    target = Path(mapping["pod"])
    target.parent.mkdir(parents=True)
    target.touch()
    real_stat = Path.stat

    def device_stat(self, *args, **kwargs):
        if self == target and kwargs.get("follow_symlinks", True):
            real_stat(self)
            return SimpleNamespace(st_mode=stat.S_IFBLK | 0o600, st_rdev=device)
        return real_stat(self, *args, **kwargs)

    # mknod is unavailable in Computer; fake only this kernel interface.
    monkeypatch.setattr(Path, "stat", device_stat)
    f = SimpleNamespace(
        module=module,
        scope=scope,
        volumes=volumes,
        runtime=runtime,
        observer=observer,
        pod=pod,
        pvc=pvc,
        pv=pv,
        release=release,
        root=root,
        sysfs=sysfs,
        proc=proc,
        target=target,
        kernel=kernel,
    )
    return f


def capture(f):
    return f.module.capture(f.observer, f.root, f.scope, f.runtime, f.volumes, f.release, f.sysfs)


def observe(f, saved):
    return f.module.references(saved, f.release, time.monotonic() + 5, f.proc, f.sysfs)


def test_original_capture_is_private_and_mapping_release_is_observed(block):
    f = block
    saved = capture(f)
    assert f.module.validate(saved, f.scope, f.volumes, f.root) == saved
    report = decode_block_release(msgspec.json.encode(f.module.report(saved)))
    assert not report.released and report.leftovers is None
    assert str(report.volumes["workspace"].pv_uid) == f.pv["metadata"]["uid"]
    assert "paths" not in msgspec.to_builtins(report)["volumes"]["workspace"]
    assert observe(f, saved)["mappings"] == 1
    f.target.unlink()
    assert decode_block_release(
        msgspec.json.encode(f.module.report(saved, observe(f, saved)))
    ).released
    (f.kernel / "holders" / "dependent").touch()
    assert observe(f, saved)["holders"] == 1


@pytest.mark.parametrize("fault", ["pod", "pvc", "claim", "mode", "node", "owner", "mapping"])
def test_capture_rejects_missing_replaced_or_foreign_originals(block, fault):
    f = block
    if fault == "pod":
        f.pod["metadata"]["uid"] = str(uuid4())
    elif fault == "pvc":
        f.pvc["metadata"]["uid"] = str(uuid4())
    elif fault == "claim":
        f.pv["spec"]["claimRef"]["uid"] = str(uuid4())
    elif fault == "mode":
        f.pvc["spec"]["volumeMode"] = "Filesystem"
    elif fault == "node":
        f.pod["spec"]["nodeName"] = "foreign"
    elif fault == "owner":
        f.pod["metadata"]["ownerReferences"] = [{"uid": str(uuid4())}]
    else:
        f.target.unlink()
    with pytest.raises((ValueError, FileNotFoundError)):
        capture(f)


@pytest.mark.parametrize("fault", ["paths", "runtime", "pv", "identity"])
def test_saved_original_shape_cannot_redirect_observer(block, fault):
    f = block
    saved = capture(f)
    if fault == "paths":
        saved["volumes"]["workspace"]["paths"]["global"] = "/unrelated"
    elif fault == "runtime":
        saved["runtime_sha256"] = "invalid"
    elif fault == "pv":
        saved["volumes"]["workspace"]["identity"]["pv_uid"] = "bad"
    else:
        saved["volumes"]["workspace"]["identity"]["volume_uid"] = str(uuid4())
    with pytest.raises(ValueError):
        f.module.validate(saved, f.scope, f.volumes, f.root)


def test_unreadable_path_and_reused_device_are_not_absence(block, monkeypatch):
    f = block
    saved = capture(f)
    saved["volumes"]["workspace"]["kernel_identity"][1] += 1
    with pytest.raises(ValueError, match="reused"):
        observe(f, saved)
    original = Path.lstat

    def denied(self, *args, **kwargs):
        if self == f.target:
            raise PermissionError
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", denied)
    with pytest.raises(PermissionError):
        observe(f, saved)


def test_unreadable_live_task_and_expired_budget_refuse_release(block):
    f = block
    saved = capture(f)
    (f.proc / "100" / "task" / "100").mkdir(parents=True)
    with pytest.raises(ValueError, match="observation incomplete"):
        observe(f, saved)
    with pytest.raises(ValueError, match="budget"):
        f.module.references(saved, f.release, time.monotonic() - 1, f.proc, f.sysfs)


def test_kernel_backing_mapping_remains_use_without_a_userspace_descriptor(block):
    f = block
    saved = capture(f)
    f.target.unlink()
    (f.kernel / "loop").mkdir()
    (f.kernel / "loop" / "backing_file").write_text("original-backing\n")
    assert observe(f, saved)["mappings"] == 1
    (f.kernel / "loop" / "backing_file").unlink()
    (f.kernel / "slaves").mkdir()
    (f.kernel / "slaves" / "dependency").touch()
    assert observe(f, saved)["mappings"] == 1


def test_distinct_claims_cannot_alias_one_captured_block_device(block):
    f = block
    saved = capture(f)
    other = deepcopy(saved["volumes"]["workspace"])
    other["identity"].update(
        name="other",
        volume_uid=str(uuid4()),
        pv_name="other-pv",
        pv_uid=str(uuid4()),
        volume_key="kubernetes.io/csi/fixture.csi^other",
    )
    other["paths"] = f.module.paths(f.root, other["identity"]["pod_uid"], "other-pv")
    saved["volumes"]["guest"] = other
    volumes = {
        **f.volumes,
        "guest": {key: other["identity"][key] for key in ("name", "volume_uid", "pod_uid")},
    }
    with pytest.raises(ValueError, match="alias"):
        f.module.validate(saved, f.scope, volumes, f.root)


@pytest.mark.parametrize(
    "field,value",
    [
        ("leftovers", {"mappings": -1, "mounts": 0, "descriptors": 0, "holders": 0}),
        ("released", True),
        ("runtime_sha256", "wrong"),
        ("extra", True),
    ],
)
def test_block_wire_refuses_inconsistent_or_unknown_fields(block, field, value):
    raw = {**block.module.report(capture(block)), field: value}
    with pytest.raises(ValueError):
        decode_block_release(msgspec.json.encode(raw))
