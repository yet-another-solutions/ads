"""CI-only real kernel Block-reference smoke; no cluster or network."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def main():
    assert os.geteuid() == 0
    loader = importlib.machinery.SourceFileLoader("block_smoke", "/usr/local/bin/ads-block-release")
    spec = importlib.util.spec_from_loader(loader.name, loader)
    helper = importlib.util.module_from_spec(spec)
    loader.exec_module(helper)
    release = helper.load("ads-ptp-release")
    loop, fd = None, None
    with tempfile.TemporaryDirectory(prefix="ads-block-smoke-") as folder:
        root = Path(folder)
        try:
            backing = root / "block.img"
            with backing.open("wb") as stream:
                stream.truncate(16 * 1024 * 1024)
            loop = run("losetup", "--find", "--show", str(backing))
            pod_uid, pvc_uid = str(uuid4()), str(uuid4())
            scope = {
                "node": "kernel-smoke",
                "namespace": "sandboxes",
                "network": "private",
                "generation": str(uuid4()),
                "sandbox_id": str(uuid4()),
            }
            runtime = {
                **scope,
                "boot_id": release.boot_id(),
                "inventory_sha256": "a" * 64,
                "pod_uids": [pod_uid],
            }
            requested = {
                "workspace": {"name": "workspace", "volume_uid": pvc_uid, "pod_uid": pod_uid}
            }
            pod = {
                "metadata": {
                    "uid": pod_uid,
                    "namespace": scope["namespace"],
                    "labels": {
                        "ads.io/sandbox-id": scope["sandbox_id"],
                        "ads.io/attachment-generation": scope["generation"],
                    },
                },
                "spec": {
                    "nodeName": scope["node"],
                    "volumes": [
                        {"name": "workspace", "persistentVolumeClaim": {"claimName": "workspace"}}
                    ],
                    "containers": [
                        {"volumeDevices": [{"name": "workspace", "devicePath": "/dev/workspace"}]}
                    ],
                },
            }
            pvc = {
                "metadata": {"uid": pvc_uid},
                "status": {"phase": "Bound"},
                "spec": {"volumeMode": "Block", "volumeName": "original-pv"},
            }
            pv = {
                "metadata": {"uid": str(uuid4())},
                "spec": {
                    "claimRef": {
                        "uid": pvc_uid,
                        "name": "workspace",
                        "namespace": scope["namespace"],
                    },
                    "csi": {"driver": "smoke.csi", "volumeHandle": "original"},
                },
            }
            observer = SimpleNamespace(
                config={
                    "kubectl": "/fixture/kubectl",
                    "kubeconfig": "/fixture/config",
                    "namespace": scope["namespace"],
                },
                pods=lambda: [pod],
                command=lambda *args: pvc if "pvc" in args else pv,
            )
            kubelet = root / "kubelet"
            mapping = Path(helper.paths(kubelet, pod_uid, "original-pv")["pod"])
            mapping.parent.mkdir(parents=True)
            mapping.symlink_to(loop)
            saved = helper.capture(observer, kubelet, scope, runtime, requested, release)

            def references():
                return helper.references(saved, release, time.monotonic() + 60)

            assert references()["mappings"] > 0
            fd = os.open(loop, os.O_RDONLY)
            mapping.unlink()
            counts = references()
            assert counts["descriptors"] > 0 and counts["mappings"] > 0
            os.close(fd)
            fd = None
            # Allocated kernel loop backing remains a blocker without an FD.
            assert references()["mappings"] > 0
            run("losetup", "--detach", loop)
            loop = None
            assert not any(references().values())
            print(json.dumps({"block-kernel-reference-smoke": "passed"}))
        finally:
            if fd is not None:
                os.close(fd)
            if loop is not None:
                run("losetup", "--detach", loop)


if __name__ == "__main__":
    main()
