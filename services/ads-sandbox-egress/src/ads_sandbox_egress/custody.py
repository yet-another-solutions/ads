"""Guest block-device custody before private credentials or listeners.

Only manager-named CSI devices are examined. No device discovery, adoption,
repair, partitioning or formatting of nonzero media. Replacement authority
comes from manager fencing; local filesystem locks do not replace that fence.
"""

from __future__ import annotations

import array
import fcntl
import json
import os
import stat
import subprocess
import time
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from ads_commons.egress_trust import EgressTrust, load_egress
from ads_sandbox_egress.identity_store import StateIdentity, StateUnavailable

_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"}


def execute(*args: str, allowed: tuple[int, ...] = (0,)) -> bytes:
    result = subprocess.run(args, capture_output=True, env=_ENV, timeout=30, check=False)
    if result.returncode not in allowed or len(result.stdout) > 65536:
        raise StateUnavailable("bounded custody operation failed")
    return result.stdout


@dataclass(frozen=True, slots=True)
class Devices:
    state: Path
    public: Path
    private: Path
    state_bytes: int
    identity: StateIdentity
    ca_attempt: UUID
    attachment_generation: UUID
    creator_generation: UUID

    def __post_init__(self) -> None:
        if (
            (self.state, self.public, self.private)
            != (
                Path("/dev/ads-egress-state"),
                Path("/dev/ads-ca-public"),
                Path("/dev/ads-ca-private"),
            )
            or type(self.state_bytes) is not int
            or not 64 * 1024**2 <= self.state_bytes <= 64 * 1024**3
            or not all(
                isinstance(value, UUID)
                for value in (self.ca_attempt, self.attachment_generation, self.creator_generation)
            )
        ):
            raise ValueError("fixed device contract and bounded state size required")


def inspect_device(path: Path, *, readonly: bool, expected_bytes: int | None = None) -> int:
    info = path.lstat()
    if not stat.S_ISBLK(info.st_mode):
        raise StateUnavailable("expected block device, not file or symlink")
    directory = Path("/sys/dev/block") / f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
    if (
        not directory.exists()
        or (directory / "partition").exists()
        or any((directory / "holders").iterdir())
    ):
        raise StateUnavailable("claimed or partitioned device")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_EXCL)
    try:
        value = array.array("i", [0])
        fcntl.ioctl(fd, 0x125E, value, True)  # BLKROGET
        if bool(value[0]) != readonly:
            raise StateUnavailable("kernel device read-only state differs")
        size = array.array("Q", [0])
        fcntl.ioctl(fd, 0x80081272, size, True)  # BLKGETSIZE64
        if expected_bytes is not None and size[0] != expected_bytes:
            raise StateUnavailable("state device size differs")
        if size[0] < 64 * 1024**2:
            raise StateUnavailable("device too small")
    finally:
        os.close(fd)
    return info.st_rdev


def require_zero(fd: int, size: int) -> None:
    """Examine the complete initial device, not only a signature/header sample."""
    started = time.monotonic()
    offset = 0
    while offset < size:
        if time.monotonic() - started > 30:
            raise StateUnavailable("blank-device verification deadline")
        data = os.pread(fd, min(4 * 1024**2, size - offset), offset)
        if not data or any(data):
            raise StateUnavailable("initial state device is not completely blank")
        offset += len(data)


def initialize_state(devices: Devices) -> bool:
    """Return true only for a freshly formatted, positively blank device."""
    result = subprocess.run(
        ["blkid", "-p", "-o", "export", str(devices.state)],
        capture_output=True,
        timeout=10,
        env=_ENV,
        check=False,
    )
    if result.returncode == 2 and not result.stdout:
        if devices.attachment_generation != devices.creator_generation:
            raise StateUnavailable("retained state must not be initialized")
        fd = os.open(devices.state, os.O_RDONLY | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            require_zero(fd, devices.state_bytes)
        finally:
            os.close(fd)
        execute(
            "mkfs.ext4",
            "-q",
            "-m",
            "0",
            "-U",
            str(devices.identity.state_id),
            "-E",
            "lazy_itable_init=0,lazy_journal_init=0",
            str(devices.state),
        )
        return True
    if result.returncode != 0 or len(result.stdout) > 4096:
        raise StateUnavailable("unrecognized state device")
    values = {}
    for line in result.stdout.decode("ascii").splitlines():
        name, separator, value = line.partition("=")
        if not separator or name in values:
            raise StateUnavailable("ambiguous state signature")
        values[name] = value
    if values.get("TYPE") != "ext4" or values.get("UUID") != str(devices.identity.state_id):
        raise StateUnavailable("foreign state filesystem")
    return False


def verify_mount(path: Path, device: int, *, readonly: bool) -> None:
    value = json.loads(
        execute("findmnt", "-J", "-M", str(path), "-o", "TARGET,MAJ:MIN,FSTYPE,OPTIONS")
    )
    rows = value.get("filesystems", ())
    if len(rows) != 1:
        raise StateUnavailable("exact mount unavailable")
    row = rows[0]
    options = set(row.get("options", "").split(","))
    if (
        row.get("target") != str(path)
        or row.get("maj:min") != f"{os.major(device)}:{os.minor(device)}"
        or row.get("fstype") != "ext4"
        or not {"nodev", "nosuid", "noexec", "ro" if readonly else "rw"} <= options
        or bool(os.statvfs(path).f_flag & os.ST_RDONLY) != readonly
    ):
        raise StateUnavailable("mounted device identity or options differ")


@dataclass(frozen=True, slots=True)
class MountedCustody:
    state_directory: Path
    initial: bool
    trust: EgressTrust


@contextmanager
def mounted_custody(devices: Devices, runtime: Path) -> Iterator[MountedCustody]:
    identities = [
        inspect_device(devices.state, readonly=False, expected_bytes=devices.state_bytes),
        inspect_device(devices.public, readonly=True),
        inspect_device(devices.private, readonly=True),
    ]
    if len(set(identities)) != 3:
        raise StateUnavailable("custody devices alias")
    # Check both read-only signer clones before ANY state initialization.
    with ExitStack() as cleanup:
        paths = []
        for role, device, identity in zip(
            ("public", "private"), (devices.public, devices.private), identities[1:], strict=True
        ):
            target = runtime / role
            target.mkdir(mode=0o700)
            execute(
                "mount",
                "-t",
                "ext4",
                "-o",
                "ro,noload,nodev,nosuid,noexec",
                str(device),
                str(target),
            )
            cleanup.callback(execute, "umount", str(target))
            verify_mount(target, identity, readonly=True)
            paths.append(target)
        trust = load_egress(paths[0], paths[1], devices.ca_attempt)
        initial = initialize_state(devices)
        target = runtime / "state"
        target.mkdir(mode=0o700)
        execute("mount", "-t", "ext4", "-o", "nodev,nosuid,noexec", str(devices.state), str(target))
        cleanup.callback(execute, "umount", str(target))
        verify_mount(target, identities[0], readonly=False)
        state = target / "identity"
        if initial:
            if {path.name for path in target.iterdir()} - {"lost+found"}:
                raise StateUnavailable("fresh state filesystem has unexpected content")
            state.mkdir(mode=0o700)
            fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        elif not state.is_dir() or state.is_symlink():
            raise StateUnavailable("retained identity directory missing")
        yield MountedCustody(state, initial, trust)
