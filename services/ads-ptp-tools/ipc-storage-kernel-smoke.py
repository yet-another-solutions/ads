"""CI-only ext4 original-inode deletion proof, not a live lab result."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import subprocess
import tempfile
from pathlib import Path

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
