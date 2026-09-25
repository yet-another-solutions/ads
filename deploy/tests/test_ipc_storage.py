from __future__ import annotations

import ctypes
import errno
import fcntl
import importlib.machinery
import importlib.util
import os
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import msgspec
import pytest
from test_ipc_node_release import captured, ipc, observer, wanted  # noqa: F401

from ads_commons.sandbox.ipc_storage import decode_ipc_storage, decode_unused_ipc_storage


@pytest.fixture
def storage_module():
    path = Path(__file__).parents[2] / "services/ads-ptp-tools/ads-ipc-storage"
    loader = importlib.machinery.SourceFileLoader("ipc_storage", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@pytest.mark.parametrize("error", [None, errno.ESTALE, errno.EBADF, errno.EPERM, errno.EIO])
def test_handle_lookup_uses_readable_mount_anchor_and_only_estale_is_absence(
    storage_module, tmp_path, monkeypatch, error
):
    descriptors = []

    def lookup(mount_fd, handle, flags):
        descriptors.append(mount_fd)
        # Inspect a real descriptor, not just a mocked os.open argument.
        actual_flags = fcntl.fcntl(mount_fd, fcntl.F_GETFL)
        assert not actual_flags & os.O_PATH
        assert actual_flags & os.O_ACCMODE == os.O_RDONLY
        assert actual_flags & os.O_DIRECTORY
        assert actual_flags & os.O_NOFOLLOW
        assert not os.get_inheritable(mount_fd)
        assert flags == os.O_PATH | os.O_CLOEXEC
        assert handle._obj.handle_bytes == 2
        if error is not None:
            ctypes.set_errno(error)
            return -1
        fd = os.open(tmp_path, flags)
        descriptors.append(fd)
        return fd

    monkeypatch.setattr(
        storage_module.ctypes, "CDLL", lambda *a, **kw: SimpleNamespace(open_by_handle_at=lookup)
    )
    saved = {"type": 1, "bytes": "aabb"}
    expected = storage_module.directory(tmp_path)
    if error in (None, errno.ESTALE):
        assert storage_module.handle_exists(tmp_path, saved, expected) is (error is None)
    else:
        with pytest.raises(OSError) as failure:
            storage_module.handle_exists(tmp_path, saved, expected)
        assert failure.value.errno == error
    for fd in descriptors:
        with pytest.raises(OSError) as closed:
            os.fstat(fd)
        assert closed.value.errno == errno.EBADF


@pytest.fixture
def backing(storage_module, ipc, captured, observer, tmp_path, monkeypatch):  # noqa: F811
    module = storage_module
    folder = tmp_path / "volume"
    folder.mkdir()
    info = folder.stat()
    captured["filesystem"].update(
        root=str(folder),
        device=f"{os.major(info.st_dev)}:{os.minor(info.st_dev)}",
        root_identity=[info.st_dev, info.st_ino],
    )
    name = "ads-sandbox-ipc-" + captured["sandbox_id"]
    pvc = {
        "metadata": {"uid": captured["volume_uid"]},
        "status": {"phase": "Bound"},
        "spec": {"volumeName": "original-pv"},
    }
    pv = {
        "metadata": {"uid": str(uuid4())},
        "spec": {
            "claimRef": {
                "uid": captured["volume_uid"],
                "name": name,
                "namespace": captured["namespace"],
            },
            "persistentVolumeReclaimPolicy": "Delete",
            "hostPath": {"path": str(folder)},
        },
    }
    monkeypatch.setattr(ipc, "exact_pod", lambda *a: None)
    monkeypatch.setattr(module, "filesystem_handle", lambda path: {"type": 1, "bytes": "aabb"})
    # External kernel handle calls are faked here; real inode/rename proof is
    # exercised separately by the privileged CI kernel smoke.
    monkeypatch.setattr(
        module,
        "handle_exists",
        lambda parent, handle, identity: any(
            p.is_dir() and [p.stat().st_dev, p.stat().st_ino] == identity
            for p in Path(parent).iterdir()
        ),
    )
    observer.command = lambda *args: deepcopy(pvc if "pvc" in args else pv)
    return SimpleNamespace(
        module=module,
        ipc=ipc,
        runtime=captured,
        observer=observer,
        folder=folder,
        pvc=pvc,
        pv=pv,
        release=ipc.load("ads-ptp-release"),
    )


def snapshot(f):
    return f.module.capture(f.observer, f.runtime, f.ipc)


def unused_snapshot(f):
    scope = {
        key: f.runtime[key]
        for key in ("node", "namespace", "generation", "sandbox_id", "volume_uid")
    }
    scope["pv_uid"] = f.pv["metadata"]["uid"]
    f.pv["spec"]["nodeAffinity"] = {
        "required": {
            "nodeSelectorTerms": [
                {
                    "matchExpressions": [
                        {
                            "key": "kubernetes.io/hostname",
                            "operator": "In",
                            "values": [scope["node"]],
                        }
                    ],
                }
            ]
        }
    }
    return scope, f.module.unused_capture(f.observer, scope, f.ipc, f.release)


def test_unused_capture_is_real_backing_not_a_fabricated_runtime(backing, monkeypatch):
    f = backing
    scope, saved = unused_snapshot(f)
    assert f.module.unused_validate(saved, scope, f.ipc) == saved
    assert "runtime" not in saved and "pod_uid" not in saved
    report = decode_unused_ipc_storage(msgspec.json.encode(f.module.unused_report(saved)))
    assert not report.observed and str(report.pv_uid) == scope["pv_uid"]
    monkeypatch.setattr(f.ipc, "filesystem_references", lambda *a: (0, 0))
    observed = f.module.unused_observe(f.observer, saved, f.ipc, f.release)
    assert observed["released"] and not observed["reclaimed"]
    f.folder.rmdir()
    assert f.module.unused_observe(f.observer, saved, f.ipc, f.release)["reclaimed"]
    assert observed["inventory_sha256"] == report.inventory_sha256


@pytest.mark.parametrize("fault", ["busy", "boot", "rename", "replacement", "parent"])
def test_unused_backing_never_turns_path_absence_or_lost_boot_into_reclamation(
    backing, monkeypatch, fault
):
    f = backing
    _, saved = unused_snapshot(f)
    monkeypatch.setattr(f.ipc, "filesystem_references", lambda *a: (0, int(fault == "busy")))
    if fault == "busy":
        f.folder.rmdir()
        report = f.module.unused_observe(f.observer, saved, f.ipc, f.release)
        assert report["observed"] and not report["released"] and not report["reclaimed"]
        return
    if fault == "boot":
        monkeypatch.setattr(f.release, "boot_id", lambda: str(uuid4()))
    elif fault in ("rename", "replacement"):
        f.folder.rename(f.folder.with_name("original-moved"))
        if fault == "replacement":
            f.folder.mkdir()
    else:
        saved["parent"][1] += 1
    with pytest.raises((ValueError, FileNotFoundError)):
        f.module.unused_observe(f.observer, saved, f.ipc, f.release)


@pytest.mark.parametrize("fault", ["pv", "node", "scope", "filesystem"])
def test_unused_scope_and_backing_binding_are_exact(backing, fault):
    f = backing
    scope, saved = unused_snapshot(f)
    if fault == "scope":
        saved["volume_uid"] = str(uuid4())
    elif fault == "filesystem":
        saved["filesystem"]["root_identity"] = [saved["identity"][0], saved["identity"][1] + 1]
    elif fault == "pv":
        scope["pv_uid"] = str(uuid4())
    else:
        f.pv["spec"]["nodeAffinity"]["required"]["nodeSelectorTerms"][0]["matchExpressions"][0][
            "values"
        ] = ["different-node"]
        with pytest.raises(ValueError):
            f.module.unused_capture(f.observer, scope, f.ipc, f.release)
        return
    with pytest.raises(ValueError):
        f.module.unused_validate(saved, scope, f.ipc)


def test_backing_capture_and_actual_path_reclamation_are_distinct(backing, monkeypatch):
    f = backing
    saved = snapshot(f)
    assert f.module.validate(saved, wanted(f.runtime), f.ipc) == saved
    report = decode_ipc_storage(msgspec.json.encode(f.module.report(saved)))
    assert not report.observed and not report.released and not report.reclaimed
    assert str(report.pv_uid) == f.pv["metadata"]["uid"]
    monkeypatch.setattr(f.ipc, "references", lambda *a: (0, 0))
    observed = f.module.observe(f.observer, saved, f.ipc, f.release)
    assert observed["released"] and not observed["reclaimed"]
    f.folder.rmdir()
    observed = f.module.observe(f.observer, saved, f.ipc, f.release)
    assert decode_ipc_storage(msgspec.json.encode(observed)).reclaimed
    assert observed["inventory_sha256"] == report.inventory_sha256
    assert "path" not in observed  # Host inventory stays at the node.


@pytest.mark.parametrize(
    "fault", ["uid", "claim", "policy", "csi", "source", "symlink", "identity"]
)
def test_capture_rejects_unknown_or_foreign_backing(backing, fault, tmp_path):
    f = backing
    if fault == "uid":
        f.pvc["metadata"]["uid"] = str(uuid4())
    elif fault == "claim":
        f.pv["spec"]["claimRef"]["uid"] = str(uuid4())
    elif fault == "policy":
        f.pv["spec"]["persistentVolumeReclaimPolicy"] = "Retain"
    elif fault == "csi":
        f.pv["spec"]["csi"] = {"driver": "foreign"}
    elif fault == "source":
        f.pv["spec"]["local"] = {"path": str(f.folder)}
    elif fault == "symlink":
        alias = tmp_path / "alias"
        alias.symlink_to(f.folder)
        f.pv["spec"]["hostPath"]["path"] = str(alias)
    else:
        f.runtime["filesystem"]["root_identity"][1] += 1
    with pytest.raises(ValueError):
        snapshot(f)


@pytest.mark.parametrize("fault", ["boot", "replacement", "parent", "missing-parent", "symlink"])
def test_observe_never_equates_missing_api_with_reclaimed_storage(backing, monkeypatch, fault):
    f = backing
    saved = snapshot(f)
    monkeypatch.setattr(f.ipc, "references", lambda *a: (0, 0))
    if fault == "boot":
        monkeypatch.setattr(f.release, "boot_id", lambda: str(uuid4()))
    elif fault == "replacement":
        f.folder.rename(f.folder.with_name("old"))
        f.folder.mkdir()
    elif fault == "parent":
        saved["parent"][1] += 1
    elif fault == "missing-parent":
        f.folder.rmdir()
        f.folder.parent.rmdir()
    else:
        f.folder.rename(f.folder.with_name("old"))
        f.folder.symlink_to(f.folder.with_name("old"))
    with pytest.raises((ValueError, FileNotFoundError)):
        f.module.observe(f.observer, saved, f.ipc, f.release)


def test_held_runtime_or_mount_prevents_reclamation(backing, monkeypatch):
    f = backing
    saved = snapshot(f)
    f.folder.rmdir()
    monkeypatch.setattr(f.ipc, "references", lambda *a: (0, 1))
    observed = f.module.observe(f.observer, saved, f.ipc, f.release)
    assert observed["observed"] and not observed["released"] and not observed["reclaimed"]


def test_renamed_original_inode_is_not_reclaimed(backing, monkeypatch):
    f = backing
    saved = snapshot(f)
    f.folder.rename(f.folder.with_name("moved-original"))
    monkeypatch.setattr(f.ipc, "references", lambda *a: (0, 0))
    observed = f.module.observe(f.observer, saved, f.ipc, f.release)
    assert observed["released"] and not observed["reclaimed"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("pv_uid", "bad"),
        ("runtime_sha256", "a"),
        ("inventory_sha256", "F" * 64),
        ("observed", 1),
        ("released", True),
        ("reclaimed", True),
        ("extra", False),
    ],
)
def test_malformed_or_inconsistent_storage_wire_refused(backing, field, value):
    raw = {**backing.module.report(snapshot(backing)), field: value}
    with pytest.raises(ValueError):
        decode_ipc_storage(msgspec.json.encode(raw))
