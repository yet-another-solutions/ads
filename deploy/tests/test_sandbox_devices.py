"""Read-only block-claim classification; no real device nodes needed in unit tests."""

import errno
import importlib.machinery
import importlib.util
import os
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "services/ads-sandbox-base/scripts/ads-session-device-check"
GOLDEN = ROOT / "services/ads-sandbox-golden/scripts/ads-session-device-check"
loader = importlib.machinery.SourceFileLoader("device_check", str(BASE))
spec = importlib.util.spec_from_loader(loader.name, loader)
assert spec is not None
device = importlib.util.module_from_spec(spec)
loader.exec_module(device)


def test_both_images_use_identical_safety_checks():
    assert BASE.read_bytes() == GOLDEN.read_bytes()


@pytest.mark.parametrize(
    "code,state",
    [(errno.EBUSY, "busy"), (errno.EPERM, "inaccessible"), (errno.EACCES, "inaccessible")],
)
def test_kernel_claim_and_device_policy_classification(monkeypatch, code, state):
    monkeypatch.setattr(device.os, "open", Mock(side_effect=OSError(code, "fixture")))
    assert device.exclusive_state(Path("/device")) == state


def test_exclusive_probe_is_read_only_nofollow_and_closed(monkeypatch):
    opened, closed = Mock(return_value=12), Mock()
    monkeypatch.setattr(device.os, "open", opened)
    monkeypatch.setattr(device.os, "close", closed)
    assert device.exclusive_state(Path("/device")) == "free"
    assert opened.call_args.args[1] == os.O_RDONLY | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    closed.assert_called_once_with(12)


def test_unknown_probe_errors_fail_closed(monkeypatch):
    monkeypatch.setattr(device.os, "open", Mock(side_effect=OSError(errno.EIO, "fixture")))
    with pytest.raises(OSError):
        device.exclusive_state(Path("/device"))


@pytest.fixture
def disks(tmp_path, monkeypatch):
    blocks, dev = tmp_path / "blocks", tmp_path / "dev"
    blocks.mkdir()
    dev.mkdir()
    session = SimpleNamespace(
        lstat=lambda: SimpleNamespace(st_mode=stat.S_IFBLK, st_rdev=os.makedev(254, 64))
    )
    probe = Mock(side_effect=lambda p: "free" if p is session else "busy")
    monkeypatch.setattr(device, "exclusive_state", probe)
    monkeypatch.setattr(device.os, "mknod", Mock())

    def add(name, identity, size="100", partition=False, backed=False):
        path = blocks / name
        path.mkdir()
        (path / "dev").write_text(identity)
        (path / "size").write_text(size)
        if partition:
            (path / "partition").touch()
        if backed:
            (path / "loop").mkdir()
            (path / "loop/backing_file").write_text("/backing")

    add("vde", "254:64")
    return SimpleNamespace(blocks=blocks, dev=dev, session=session, probe=probe, add=add)


def test_hidden_root_mounts_and_unused_loop_placeholders(disks):
    disks.add("vda", "254:0")
    disks.add("vda1", "254:1", partition=True)
    disks.add("loop0", "7:0", size="0")
    device.check(disks.session, disks.blocks, disks.dev)
    assert disks.probe.call_count == 2  # Session and hidden, busy root disk only.


@pytest.mark.parametrize("name,size,backed", [("vdf", "100", False), ("loop1", "0", True)])
def test_extra_accessible_disks_are_rejected(disks, name, size, backed):
    disks.add(name, "7:1", size=size, backed=backed)
    disks.probe.side_effect = None
    disks.probe.return_value = "free"
    with pytest.raises(RuntimeError, match="unexpected accessible"):
        device.check(disks.session, disks.blocks, disks.dev)


@pytest.mark.parametrize("state", ["busy", "inaccessible"])
def test_session_itself_must_be_free_and_accessible(disks, state):
    disks.probe.side_effect = None
    disks.probe.return_value = state
    with pytest.raises(RuntimeError, match="session device"):
        device.check(disks.session, disks.blocks, disks.dev)


def test_session_must_be_whole_disk_not_partition(disks):
    (disks.blocks / "vde/partition").touch()
    with pytest.raises(RuntimeError, match="whole disk"):
        device.check(disks.session, disks.blocks, disks.dev)


@pytest.mark.parametrize("mode", [stat.S_IFLNK, stat.S_IFREG])
def test_session_cannot_be_symlink_or_regular_file(disks, mode):
    disks.session.lstat = lambda: SimpleNamespace(st_mode=mode)
    with pytest.raises(RuntimeError, match="block device"):
        device.check(disks.session, disks.blocks, disks.dev)
