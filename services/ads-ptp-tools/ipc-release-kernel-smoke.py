"""CI-only native filesystem reference proof, not live manager acceptance."""

from __future__ import annotations

import ctypes
import importlib.machinery
import importlib.util
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from uuid import uuid4

loader = importlib.machinery.SourceFileLoader("ipc_release", "/usr/local/bin/ads-ipc-release")
spec = importlib.util.spec_from_loader(loader.name, loader)
ipc = importlib.util.module_from_spec(spec)
loader.exec_module(ipc)
release = ipc.load("ads-ptp-release")
libc = ctypes.CDLL(None, use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_long,
]
libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, timeout=10)


with tempfile.TemporaryDirectory(prefix="ipc-release-") as directory:
    root = Path(directory)
    source, target = root / "source", root / "alias"
    source.mkdir()
    target.mkdir()
    (source / "held").write_text("synthetic")
    mounted, held, child, mapping = False, None, None, None
    try:
        run("mount", "--bind", str(source), str(target))
        mounted = True
        table = ipc.mounts(Path("/proc/self/mountinfo").read_text())
        entry = next(m for m in table.values() if m["target"] == str(target))
        info = target.stat()
        snapshot = {
            "node": "ci",
            "namespace": "ci",
            **{k: str(uuid4()) for k in ("generation", "sandbox_id", "pod_uid", "volume_uid")},
            "boot_id": release.boot_id(),
            "runtime_id": "a" * 64,
            "container_id": "b" * 64,
            # This smoke isolates filesystem references, not namespace capture.
            "namespaces": {
                key: [4, 9223372036854775800 + i] for i, key in enumerate(("net", "mnt", "pid"))
            },
            "filesystem": {**entry, "root_identity": [info.st_dev, info.st_ino]},
        }
        ipc.report(snapshot)

        def count():
            return ipc.references(snapshot, time.monotonic() + 30, release)[1]

        assert count() > 0, "live bind mount must block release"
        held = os.open(target / "held", os.O_RDONLY | os.O_CLOEXEC)
        run("umount", "-l", str(target))
        mounted = False
        assert count() > 0, "held descriptor on detached bind must block release"
        os.close(held)
        held = None
        assert count() == 0, "release requires all original mount references gone"
        run("mount", "--bind", str(source), str(target))
        mounted = True
        child = subprocess.Popen(
            ["sleep", "60"], cwd=target, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        run("umount", "-l", str(target))
        mounted = False
        assert count() > 0, "detached cwd must block release"
        child.terminate()
        child.wait(timeout=5)
        child = None
        assert count() == 0, "exited cwd holder must release the original mount"
        run("mount", "--bind", str(source), str(target))
        mounted = True
        with (target / "held").open("rb") as stream:
            # Python 3.12 duplicates mmap descriptors. Use the kernel call
            # directly so this proof has no FD once the with-block closes.
            mapping = libc.mmap(None, 9, 1, 2, stream.fileno(), 0)
            assert mapping != ctypes.c_void_p(-1).value, "mmap must succeed"
        run("umount", "-l", str(target))
        mounted = False
        assert count() > 0, "mapping outlives its closed file descriptor"
        assert libc.munmap(mapping, 9) == 0
        mapping = None
        assert count() == 0, "released mapping must permit release"
    finally:
        if child is not None:
            child.kill()
            child.wait(timeout=5)
        if held is not None:
            os.close(held)
        if mapping is not None:
            assert libc.munmap(mapping, 9) == 0
        if mounted:
            run("umount", "-l", str(target))
print(
    json.dumps(
        {
            "original_mount_blocks_release": True,
            "detached_descriptor_blocks_release": True,
            "detached_working_directory_blocks_release": True,
            "detached_memory_mapping_blocks_release": True,
            "reference_removal_observed": True,
            "manager_live_integration_proven": False,
        }
    )
)
