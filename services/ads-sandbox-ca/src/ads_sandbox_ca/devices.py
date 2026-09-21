from __future__ import annotations

import os
import stat
import subprocess
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path

PUBLIC_DEVICE = Path("/dev/ads-ca-public")
PRIVATE_DEVICE = Path("/dev/ads-ca-private")


def run(*argv: str) -> None:
    # Commands never contain keys; output is withheld to keep logs bounded.
    subprocess.run(
        argv, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=90
    )


def check_device(device: Path, expected_bytes: int) -> int:
    """Only the two explicitly supplied CSI devices, no node disk discovery or mknod."""
    info = device.lstat()
    if not stat.S_ISBLK(info.st_mode):
        raise ValueError("CA output must be a block device, not a file or symlink")
    identity = f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
    block = Path("/sys/dev/block") / identity
    if (
        not block.exists()
        or (block / "partition").exists()
        or any((block / "holders").iterdir())
        or (block / "ro").read_text().strip() != "0"
        or int((block / "size").read_text()) * 512 != expected_bytes
    ):
        raise ValueError("CA output device shape, ownership or size is unsafe")
    # O_EXCL checks kernel claims across mount namespaces, unlike findmnt alone.
    fd = os.open(device, os.O_RDWR | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW)
    os.close(fd)
    result = subprocess.run(
        ("blkid", "-p", str(device)),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
        check=False,
    )
    if result.returncode != 2:
        raise ValueError("CA initialization refuses nonblank or unreadable output")
    return info.st_rdev


@contextmanager
def mounted_outputs(expected_bytes: int) -> Iterator[tuple[Path, Path]]:
    if expected_bytes < 64 * 1024**2 or expected_bytes > 1024**3:
        raise ValueError("CA source size must be between 64Mi and 1Gi")
    identities = [check_device(path, expected_bytes) for path in (PUBLIC_DEVICE, PRIVATE_DEVICE)]
    if identities[0] == identities[1]:
        raise ValueError("CA outputs alias the same block device")
    # Both preflights finish before touching either disk. A failed/partial attempt
    # is never reformatted in place: manager must release/delete the whole pair.
    with ExitStack() as cleanup:
        outputs = (Path("/outputs/public"), Path("/outputs/private"))
        for device, directory in zip((PUBLIC_DEVICE, PRIVATE_DEVICE), outputs, strict=True):
            directory.mkdir(parents=True, exist_ok=True)
            if directory.is_symlink() or any(directory.iterdir()) or os.path.ismount(directory):
                raise ValueError("mount target must be fresh and unmounted")
            run("mkfs.ext4", "-F", "-q", "-m", "0", str(device))
            run("mount", "-o", "nodev,nosuid,noexec", str(device), str(directory))
            cleanup.callback(run, "umount", str(directory))
        yield outputs
    # ExitStack propagates unmount failure; no successful Job until both released.
