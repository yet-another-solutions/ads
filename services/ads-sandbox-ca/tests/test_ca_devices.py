from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from ads_sandbox_ca import devices
from ads_sandbox_ca.__main__ import main, read_input


def test_regular_file_and_symlink_never_reach_formatter(tmp_path, monkeypatch):
    device = tmp_path / "not-a-device"
    device.write_bytes(b"existing data")
    link = tmp_path / "link"
    link.symlink_to(device)
    calls = []
    monkeypatch.setattr(devices.subprocess, "run", lambda *a, **k: calls.append(a))
    for path in (device, link):
        with pytest.raises(ValueError, match="block device"):
            devices.check_device(path, 256 * 1024**2)
    assert calls == [] and device.read_bytes() == b"existing data"


@pytest.mark.parametrize("size", [0, 64 * 1024**2 - 1, 1024**3 + 1])
def test_size_bounds_before_device_access(size, monkeypatch):
    monkeypatch.setattr(devices, "check_device", lambda *a: pytest.fail("device touched"))
    with pytest.raises(ValueError, match="size"):
        with devices.mounted_outputs(size):
            pytest.fail("mounted")


def test_aliases_rejected_before_format(monkeypatch):
    monkeypatch.setattr(devices, "check_device", lambda *a: 42)
    monkeypatch.setattr(devices, "run", lambda *a: pytest.fail("formatter invoked"))
    with pytest.raises(ValueError, match="alias"):
        with devices.mounted_outputs(256 * 1024**2):
            pytest.fail("mounted")


def test_inputs_bounded_and_errors_sanitized(tmp_path, monkeypatch, capsys):
    oversized = tmp_path / "large"
    oversized.write_bytes(b"x" * (4 * 1024 * 1024 + 1))
    with pytest.raises(ValueError, match="limit"):
        read_input(oversized)
    monkeypatch.setenv("ADS_CA_ATTEMPT", "sensitive-fixture-not-a-uuid")
    with pytest.raises(SystemExit) as exc:
        main()
    output = capsys.readouterr()
    assert exc.value.code == 1
    assert "sensitive" not in output.err
    assert output.out == ""


@pytest.mark.parametrize("fault", ["partition", "holder", "readonly", "size", "busy", "signature"])
def test_device_checks_fail_before_format(monkeypatch, tmp_path, fault):
    import stat

    block = tmp_path / "sys"
    (block / "holders").mkdir(parents=True)
    (block / "ro").write_text("1" if fault == "readonly" else "0")
    (block / "size").write_text("1" if fault == "size" else str(256 * 1024**2 // 512))
    if fault == "partition":
        (block / "partition").touch()
    if fault == "holder":
        (block / "holders" / "used").touch()
    actual_path = Path
    monkeypatch.setattr(
        devices,
        "Path",
        lambda value: block.parent if value == "/sys/dev/block" else actual_path(value),
    )
    # The synthetic device identity resolves to tmp/sys; no real block access.
    monkeypatch.setattr(devices.os, "major", lambda _: 1)
    monkeypatch.setattr(devices.os, "minor", lambda _: 2)
    (block.parent / "1:2").symlink_to(block, target_is_directory=True)
    device = SimpleNamespace(lstat=lambda: SimpleNamespace(st_mode=stat.S_IFBLK, st_rdev=99))
    opened = []

    def open_device(*args):
        opened.append(args)
        if fault == "busy":
            raise OSError("claimed")
        return 88

    monkeypatch.setattr(devices.os, "open", open_device)
    monkeypatch.setattr(devices.os, "close", lambda _: None)
    monkeypatch.setattr(devices.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0))
    with pytest.raises((ValueError, OSError)):
        devices.check_device(device, 256 * 1024**2)
    if fault in ("busy", "signature"):
        assert opened[0][1] & os.O_EXCL
    else:
        assert opened == []


@pytest.mark.parametrize("fault", ["none", "second-mount", "writer", "unmount"])
def test_mount_lifecycle_is_bounded_and_partial_failure_is_not_success(
    tmp_path, monkeypatch, fault
):
    calls = []
    ids = iter((1, 2))
    monkeypatch.setattr(devices, "check_device", lambda *a: next(ids))
    actual_path = Path
    monkeypatch.setattr(devices, "Path", lambda path: tmp_path / path.removeprefix("/outputs/"))

    def command(*args):
        calls.append(args)
        if fault == "second-mount" and args[0] == "mount" and args[-1].endswith("/private"):
            raise RuntimeError("mount failed")
        if fault == "unmount" and args[0] == "umount":
            raise RuntimeError("unmount failed")

    monkeypatch.setattr(devices, "run", command)

    def work():
        with devices.mounted_outputs(256 * 1024**2) as pair:
            assert pair == (actual_path(tmp_path / "public"), actual_path(tmp_path / "private"))
            if fault == "writer":
                raise RuntimeError("write failed")

    if fault == "none":
        work()
    else:
        with pytest.raises(RuntimeError):
            work()
    unmounts = [c for c in calls if c[0] == "umount"]
    assert len(unmounts) == (1 if fault == "second-mount" else 2)
    assert unmounts[-1][-1].endswith("/public")
    if fault != "second-mount":
        assert unmounts[0][-1].endswith("/private")
