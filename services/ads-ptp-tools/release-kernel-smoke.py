"""CI-only real process/namespace reference observation, not live manager proof."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import subprocess
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

loader = importlib.machinery.SourceFileLoader("release", "/usr/local/bin/ads-ptp-release")
spec = importlib.util.spec_from_loader(loader.name, loader)
release = importlib.util.module_from_spec(spec)
loader.exec_module(release)
plugin = release.load("ads-ptp")
partial = release.load("ads-ptp-partial")
state = TemporaryDirectory(prefix="ads-partial-release-")
root = Path(state.name)
root.chmod(0o700)
name = "release-" + str(uuid4())
path = Path("/run/netns") / name
child = None
held = None
created = False


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, timeout=10)


try:
    run("ip", "netns", "add", name)
    created = True
    info = path.stat()
    journal = {
        "request": {"command": "ADD", "netns": str(path)},
        "vm_identity": [info.st_dev, info.st_ino],
        "indices": None,
    }
    # A real pre-effect namespace can be captured without an operational link.
    release.startup_namespace(plugin, journal)
    try:
        release.startup_namespace(
            plugin, {**journal, "vm_identity": [info.st_dev, info.st_ino + 1]}
        )
    except ValueError:
        pass
    else:
        raise AssertionError("replaced startup namespace accepted")
    snapshot = {"namespaces": [[info.st_dev, info.st_ino]], "runtime_ids": []}
    scope = {
        "node": "ci-worker",
        "namespace": "ci-sandboxes",
        "network": "ci-private",
        "generation": str(uuid4()),
        "sandbox_id": str(uuid4()),
        "pod_uids": {"guest": str(uuid4())},
    }
    request = plugin.request(
        {"cniVersion": "1.0.0", "type": "ads-ptp", "name": scope["network"]},
        {
            "CNI_COMMAND": "ADD",
            "CNI_CONTAINERID": "d" * 64,
            "CNI_IFNAME": "eth0",
            "CNI_NETNS": str(path),
            "CNI_ARGS": "K8S_POD_UID=" + scope["pod_uids"]["guest"],
        },
    )
    plugin.capture_attempt(root, request)  # Actual durable original namespace capture.

    class Observer:
        config = {"guest_runtime": "ci-runtime"}
        live = True
        deadline = time.monotonic() + 60

        def pods(self):
            return (
                [
                    {
                        "metadata": {
                            "name": "ci-guest",
                            "uid": scope["pod_uids"]["guest"],
                            "namespace": scope["namespace"],
                            "labels": {
                                "ads.io/attachment-generation": scope["generation"],
                                "ads.io/sandbox-id": scope["sandbox_id"],
                                "app.kubernetes.io/component": "ads-sandbox",
                            },
                        },
                        "spec": {"nodeName": scope["node"], "runtimeClassName": "ci-runtime"},
                    }
                ]
                if self.live
                else []
            )

        def cri(self, command, *args):
            # API/CRI are explicit component-test boundaries; kernel references are real.
            return {"items": []} if command == "pods" else {"containers": []}

        def command(self, *args):
            return json.loads(run(*args).stdout)

    observer = Observer()
    captured = partial.capture(plugin, None, observer, release, root, scope)
    observer.live = False

    def partial_released():
        observer.deadline = time.monotonic() + 10
        result = partial.observe(plugin, observer, release, root, captured)
        assert result["inventory_sha256"] == partial.digest(captured)
        assert not result["generation_retired"]
        return result["observed_runtime_released"]

    assert not partial_released()  # Real original namespace mount, no API blocker.
    assert release.process_references(snapshot, time.monotonic() + 10) > 0  # Bind mount.
    child = subprocess.Popen(
        ["ip", "netns", "exec", name, "sleep", "60"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 5
    while Path(f"/proc/{child.pid}/ns/net").stat().st_ino != info.st_ino:
        assert child.poll() is None and time.monotonic() < deadline
        time.sleep(0.02)
    held = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    run("ip", "netns", "delete", name)
    created = False
    try:
        release.startup_namespace(plugin, journal)
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("missing startup namespace accepted")
    assert release.process_references(snapshot, time.monotonic() + 10) > 0  # Process + FD.
    assert not partial_released()
    child.terminate()
    child.wait(timeout=5)
    child = None
    assert release.process_references(snapshot, time.monotonic() + 10) > 0  # Held FD only.
    assert not partial_released()
    os.close(held)
    held = None
    assert release.process_references(snapshot, time.monotonic() + 10) == 0
    assert partial_released()
finally:
    if child is not None:
        child.kill()
        child.wait(timeout=5)
    if held is not None:
        os.close(held)
    if created:
        run("ip", "netns", "delete", name)
    state.cleanup()
assert not path.exists()
print(
    json.dumps(
        {
            "real_process_namespace_references": True,
            "held_namespace_descriptor_blocks_release": True,
            "namespace_mount_blocks_release": True,
            "reference_removal_observed": True,
            "interrupted_add_namespace_identity_verified": True,
            "partial_report_real_reference_release_verified": True,
            "manager_live_integration_proven": False,
        }
    )
)
