import os
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from ads_sandbox_egress import custody as module
from ads_sandbox_egress.custody import (
    Devices,
    initialize_state,
    inspect_device,
    mounted_custody,
    require_zero,
    verify_mount,
)
from ads_sandbox_egress.identity_store import StateUnavailable
from test_identity_store import custody as custody


@pytest.fixture
def devices(custody):
    generation = uuid4()
    return Devices(
        Path("/dev/ads-egress-state"),
        Path("/dev/ads-ca-public"),
        Path("/dev/ads-ca-private"),
        64 * 1024**2,
        custody[1],
        uuid4(),
        generation,
        generation,
    )


@pytest.mark.parametrize(
    "change",
    [
        {"state": Path("/dev/other")},
        {"public": Path("/dev/ads-ca-private")},
        {"state_bytes": True},
        {"state_bytes": 1},
        {"state_bytes": 65 * 1024**3},
        {"creator_generation": "not-a-uuid"},
    ],
)
def test_fixed_device_inputs(devices, change):
    with pytest.raises(ValueError):
        replace(devices, **change)


def test_regular_and_symlink_devices_rejected(tmp_path):
    regular, symlink = tmp_path / "regular", tmp_path / "symlink"
    regular.write_bytes(b"")
    symlink.symlink_to(regular)
    for path in (regular, symlink):
        with pytest.raises(StateUnavailable, match="block device"):
            inspect_device(path, readonly=True)


@pytest.mark.parametrize("defect", ["none", "tail", "short", "deadline"])
def test_blank_scan_covers_entire_media(tmp_path, monkeypatch, defect):
    path = tmp_path / "device"
    size = 4 * 1024**2 + 8
    with path.open("wb") as stream:
        stream.truncate(size - 1 if defect == "short" else size)
        if defect == "tail":
            stream.seek(size - 1)
            stream.write(b"\1")
    if defect == "deadline":
        values = iter((0, 1, 31))
        monkeypatch.setattr(module.time, "monotonic", lambda: next(values))
    fd = os.open(path, os.O_RDONLY)
    try:
        if defect == "none":
            require_zero(fd, size)
        else:
            with pytest.raises(StateUnavailable):
                require_zero(fd, size)
    finally:
        os.close(fd)


@pytest.mark.parametrize("case", ["retained-blank", "foreign", "wrong-type", "duplicate", "error"])
def test_state_initialization_never_repairs_or_formats(devices, monkeypatch, case):
    body = {
        "retained-blank": b"",
        "foreign": b"TYPE=ext4\nUUID=foreign\n",
        "wrong-type": f"TYPE=xfs\nUUID={devices.identity.state_id}\n".encode(),
        "duplicate": f"TYPE=ext4\nTYPE=ext4\nUUID={devices.identity.state_id}\n".encode(),
        "error": b"",
    }[case]
    result = subprocess.CompletedProcess(
        [], 2 if case == "retained-blank" else 1 if case == "error" else 0, body
    )
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: result)
    monkeypatch.setattr(module, "execute", lambda *a, **k: pytest.fail("unexpected effect"))
    devices = replace(devices, attachment_generation=uuid4())
    with pytest.raises(StateUnavailable):
        initialize_state(devices)


def test_existing_matching_filesystem_is_not_formatted(devices, monkeypatch):
    result = subprocess.CompletedProcess(
        [], 0, f"TYPE=ext4\nUUID={devices.identity.state_id}\n".encode()
    )
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: result)
    assert initialize_state(devices) is False


def test_new_device_checks_all_bytes_before_formatting(devices, monkeypatch, tmp_path):
    path = tmp_path / "external-block-boundary"
    path.write_bytes(b"\0" * 32)
    real_open = os.open
    monkeypatch.setattr(module.os, "open", lambda *a, **k: real_open(path, os.O_RDONLY))
    monkeypatch.setattr(
        module.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 2, b"")
    )
    events = []
    monkeypatch.setattr(module, "require_zero", lambda fd, size: events.append(("scan", size)))
    monkeypatch.setattr(module, "execute", lambda *args: events.append(args))
    assert initialize_state(devices) is True
    assert events[0] == ("scan", devices.state_bytes)
    assert events[1][0] == "mkfs.ext4"
    assert str(devices.identity.state_id) in events[1]


@pytest.mark.parametrize("failure", ["device", "alias", "mount", "trust"])
def test_custody_preflight_and_mount_failure_cleanup(devices, tmp_path, monkeypatch, failure):
    events = []
    number = iter((1, 1, 3) if failure == "alias" else (1, 2, 3))

    def inspect(*a, **k):
        if failure == "device":
            raise StateUnavailable("device unavailable")
        return next(number)

    def execute(*args):
        events.append(args)
        return b""

    def verify(*args, **kwargs):
        if failure == "mount":
            raise StateUnavailable("wrong mount")

    def load(*args):
        raise StateUnavailable("wrong trust")

    monkeypatch.setattr(module, "inspect_device", inspect)
    monkeypatch.setattr(module, "execute", execute)
    monkeypatch.setattr(module, "verify_mount", verify)
    monkeypatch.setattr(module, "load_egress", load)
    monkeypatch.setattr(module, "initialize_state", lambda *a: pytest.fail("state effect"))
    with pytest.raises(StateUnavailable), mounted_custody(devices, tmp_path):
        pytest.fail("unverified custody yielded")
    mounts = [value[-1] for value in events if value[0] == "mount"]
    unmounts = [value[-1] for value in events if value[0] == "umount"]
    assert unmounts == list(reversed(mounts))
    assert len(mounts) == (0 if failure in ("device", "alias") else 1 if failure == "mount" else 2)


@pytest.mark.parametrize("defect", ["none", "source", "target", "type", "options", "kernel"])
def test_exact_mount_identity_and_kernel_readonly(tmp_path, monkeypatch, defect):
    import json

    row = {
        "target": str(tmp_path),
        "maj:min": "8:1",
        "fstype": "ext4",
        "options": "ro,nodev,nosuid,noexec",
    }
    if defect != "none" and defect != "kernel":
        row[
            {"source": "maj:min", "target": "target", "type": "fstype", "options": "options"}[
                defect
            ]
        ] = "wrong"
    monkeypatch.setattr(module, "execute", lambda *a: json.dumps({"filesystems": [row]}).encode())
    monkeypatch.setattr(
        module.os,
        "statvfs",
        lambda *a: SimpleNamespace(f_flag=0 if defect == "kernel" else os.ST_RDONLY),
    )
    if defect == "none":
        verify_mount(tmp_path, os.makedev(8, 1), readonly=True)
    else:
        with pytest.raises(StateUnavailable):
            verify_mount(tmp_path, os.makedev(8, 1), readonly=True)
