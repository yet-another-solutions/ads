"""CI-only ext4 original-inode deletion proof, not a live lab result."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import subprocess
import tempfile
import time
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

loader = importlib.machinery.SourceFileLoader("ipc_storage", "/usr/local/bin/ads-ipc-storage")
spec = importlib.util.spec_from_loader(loader.name, loader)
storage = importlib.util.module_from_spec(spec)
loader.exec_module(storage)


def run(*args):
    subprocess.run(args, check=True, capture_output=True, timeout=20)


with tempfile.TemporaryDirectory(prefix="ipc-storage-") as directory:
    root = Path(directory)
    image, mount = root / "filesystem", root / "mount"
    image.touch()
    image.chmod(0o600)
    with image.open("r+b") as stream:
        stream.truncate(32 * 1024 * 1024)
    mount.mkdir()
    mounted = False
    try:
        run("mkfs.ext4", "-q", "-F", str(image))
        run("mount", "-o", "loop", str(image), str(mount))
        mounted = True
        original = mount / "original"
        original.mkdir()
        identity = storage.directory(original)
        handle = storage.filesystem_handle(original)
        assert storage.handle_exists(mount, handle, identity)
        renamed = mount / "renamed"
        original.rename(renamed)
        assert storage.handle_exists(mount, handle, identity), "rename must not prove reclamation"
        original.mkdir()
        assert storage.handle_exists(mount, handle, identity), "replacement path is not old inode"
        original.rmdir()
        renamed.rmdir()
        assert not storage.handle_exists(mount, handle, identity), "removed original must be stale"
        for _ in range(64):
            original.mkdir()
            assert not storage.handle_exists(mount, handle, identity), (
                "inode generation must fence reuse"
            )
            original.rmdir()
        # A separate never-started consumer mode uses actual host backing and
        # process/descriptor scans, without fabricating a Pod/runtime snapshot.
        original.mkdir()
        ipc, release = storage.load("ads-ipc-release"), storage.load("ads-ptp-release")
        wanted = {
            "node": "test-node",
            "namespace": "test-sandboxes",
            **{key: str(uuid4()) for key in ("generation", "sandbox_id", "volume_uid", "pv_uid")},
        }
        pvc = {
            "metadata": {"uid": wanted["volume_uid"]},
            "status": {"phase": "Bound"},
            "spec": {"volumeName": "test-original"},
        }
        pv = {
            "metadata": {"uid": wanted["pv_uid"]},
            "spec": {
                "claimRef": {
                    "name": "ads-sandbox-ipc-" + wanted["sandbox_id"],
                    "namespace": wanted["namespace"],
                    "uid": wanted["volume_uid"],
                },
                "persistentVolumeReclaimPolicy": "Delete",
                "hostPath": {"path": str(original)},
                "nodeAffinity": {
                    "required": {
                        "nodeSelectorTerms": [
                            {
                                "matchExpressions": [
                                    {
                                        "key": "kubernetes.io/hostname",
                                        "operator": "In",
                                        "values": [wanted["node"]],
                                    }
                                ],
                            }
                        ]
                    }
                },
            },
        }
        observer = SimpleNamespace(
            config={
                "kubectl": "/unused",
                "kubeconfig": "/unused",
                "namespace": wanted["namespace"],
            },
            command=lambda *args: deepcopy(pvc if "pvc" in args else pv),
            deadline=time.monotonic() + 60,
        )
        saved = storage.unused_capture(observer, wanted, ipc, release)
        assert storage.unused_validate(saved, wanted, ipc) == saved
        assert storage.unused_observe(observer, saved, ipc, release)["released"]
        held = original / "held"
        held.write_bytes(b"original descriptor")
        fd = os.open(held, os.O_RDONLY)
        try:
            assert not storage.unused_observe(observer, saved, ipc, release)["released"]
            held.unlink()
            original.rmdir()
            assert not storage.unused_observe(observer, saved, ipc, release)["reclaimed"]
        finally:
            os.close(fd)
        assert storage.unused_observe(observer, saved, ipc, release)["reclaimed"]
        # Check the implementation did not leave descriptor references behind.
        assert not any(
            os.readlink(fd).startswith(str(mount))
            for fd in Path("/proc/self/fd").iterdir()
            if fd.exists()
        )
    finally:
        if mounted:
            run("umount", str(mount))
print("Original ext4 backing handles distinguish rename, replacement, removal and inode reuse.")
