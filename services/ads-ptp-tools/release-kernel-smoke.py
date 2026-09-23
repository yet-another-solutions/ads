"""CI-only real process/namespace reference observation, not live manager proof."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import subprocess
import time
from pathlib import Path
from uuid import uuid4

loader = importlib.machinery.SourceFileLoader("release", "/usr/local/bin/ads-ptp-release")
spec = importlib.util.spec_from_loader(loader.name, loader)
release = importlib.util.module_from_spec(spec)
loader.exec_module(release)
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
    snapshot = {"namespaces": [[info.st_dev, info.st_ino]], "runtime_ids": []}
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
    assert release.process_references(snapshot, time.monotonic() + 10) > 0  # Process + FD.
    child.terminate()
    child.wait(timeout=5)
    child = None
    assert release.process_references(snapshot, time.monotonic() + 10) > 0  # Held FD only.
    os.close(held)
    held = None
    assert release.process_references(snapshot, time.monotonic() + 10) == 0
finally:
    if child is not None:
        child.kill()
        child.wait(timeout=5)
    if held is not None:
        os.close(held)
    if created:
        run("ip", "netns", "delete", name)
assert not path.exists()
print(
    json.dumps(
        {
            "real_process_namespace_references": True,
            "held_namespace_descriptor_blocks_release": True,
            "namespace_mount_blocks_release": True,
            "reference_removal_observed": True,
            "manager_live_integration_proven": False,
        }
    )
)
