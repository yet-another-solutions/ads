from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest

from ads_commons import egress_trust

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "services/ads-sandbox-base/scripts/ads-sandbox-trust"
sys.modules["ads_egress_trust"] = egress_trust
loader = importlib.machinery.SourceFileLoader("sandbox_trust", str(HELPER))
spec = importlib.util.spec_from_loader(loader.name, loader)
assert spec is not None
trust = importlib.util.module_from_spec(spec)
loader.exec_module(trust)
install_loader = importlib.machinery.SourceFileLoader(
    "sandbox_trust_install", str(HELPER.with_name("ads-install-egress-trust"))
)
install_spec = importlib.util.spec_from_loader(install_loader.name, install_loader)
assert install_spec is not None
installer = importlib.util.module_from_spec(install_spec)
install_loader.exec_module(installer)


@pytest.mark.parametrize("mode", [stat.S_IFREG, stat.S_IFLNK])
def test_public_device_is_never_file_or_symlink(mode):
    with pytest.raises(RuntimeError, match="block device"):
        trust.check_readonly(SimpleNamespace(lstat=lambda: SimpleNamespace(st_mode=mode)))


@pytest.mark.parametrize("readonly", [0, 1])
def test_kernel_readonly_flag_required_and_fd_closed(monkeypatch, readonly):
    device = SimpleNamespace(lstat=lambda: SimpleNamespace(st_mode=stat.S_IFBLK))
    opened, closed = Mock(return_value=19), Mock()
    monkeypatch.setattr(trust.os, "open", opened)
    monkeypatch.setattr(trust.os, "close", closed)

    def ioctl(fd, operation, value, mutate):
        assert (fd, operation, mutate) == (19, trust.BLKROGET, True)
        value[0] = readonly

    monkeypatch.setattr(trust.fcntl, "ioctl", ioctl)
    if readonly:
        trust.check_readonly(device)
    else:
        with pytest.raises(RuntimeError, match="kernel read-only"):
            trust.check_readonly(device)
    assert opened.call_args.args[1] & os.O_NOFOLLOW
    closed.assert_called_once_with(19)


@pytest.mark.parametrize("failure", [None, "read-write", "manifest"])
def test_mount_is_readonly_noload_and_validation_failure_unmounts(tmp_path, monkeypatch, failure):
    public = tmp_path / "mount"
    monkeypatch.setattr(trust, "PUBLIC", public)
    monkeypatch.setattr(trust, "check_readonly", Mock())
    monkeypatch.setattr(trust.os.path, "ismount", lambda _: False)
    monkeypatch.setattr(
        trust.os,
        "statvfs",
        lambda _: SimpleNamespace(f_flag=0 if failure == "read-write" else os.ST_RDONLY),
    )
    commands = Mock()
    verified = Mock(side_effect=ValueError("bad manifest") if failure == "manifest" else None)
    monkeypatch.setattr(trust.subprocess, "run", commands)
    monkeypatch.setattr(trust, "load_public", verified)
    attempt = uuid4()
    if failure:
        with pytest.raises((ValueError, RuntimeError)):
            trust.mount(attempt)
        assert commands.call_args_list[-1].args[0] == ["umount", str(public)]
    else:
        trust.mount(attempt)
        verified.assert_called_once_with(public, attempt)
        assert commands.call_count == 1
    assert commands.call_args_list[0].args[0] == [
        "mount",
        "-t",
        "ext4",
        "-o",
        "ro,noload,nodev,nosuid,noexec",
        "/dev/ads-ca-public",
        str(public),
    ]


def test_boot_installs_validated_signing_chain_inside_rootless_container_before_ready():
    boot = HELPER.with_name("ads-sandbox-boot").read_text()
    assert boot.index("ads-sandbox-trust mount") < boot.index(
        "\n/usr/local/sbin/ads-session-device-check"
    )
    assert boot.index("ads-sandbox-trust certificate") < boot.index("touch /run/ads-sandbox-ready")
    assert "certificate | podman_cmd exec -i dev-sandbox" in boot
    assert 'python3 -c "$(</usr/local/sbin/ads-install-egress-trust)"' in boot
    assert "signing-chain.pem" not in boot and "egress-only-trust.pem" not in boot
    assert "chroot " not in boot
    assert "CA device without trusted attempt identity" in boot
    base = (ROOT / "services/ads-sandbox-base/Containerfile").read_text()
    assert "python3-cryptography" in base
    assert (
        "COPY libraries/ads-commons/src/ads_commons/egress_trust.py "
        "/usr/local/lib/ads-trust/ads_egress_trust.py"
    ) in base
    assert "COPY services/ads-sandbox-base/scripts/ads-install-egress-trust " in base


@pytest.mark.parametrize("value", [b"", b"PRIVATE KEY", b"x" * (2 * 1024**2 + 1)])
def test_inner_installer_rejects_invalid_or_oversized_bundle_before_effects(tmp_path, value):
    target = tmp_path / "trust"
    with pytest.raises(ValueError):
        installer.install(value, target)
    assert not target.exists()


def test_inner_installer_rejects_duplicate_and_mixed_pem_before_effects(tmp_path):
    pem = b"-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n"
    for value in (pem * 3, pem * 3 + b"PRIVATE KEY"):
        with pytest.raises(ValueError):
            installer.install(value, tmp_path / "trust")
    assert not (tmp_path / "trust").exists()


def test_inner_update_failure_propagates_and_temporary_files_are_removed(tmp_path, monkeypatch):
    # Structural transport fixture only; real X509 validation belongs to load_public.
    bundle = b"".join(
        b"-----BEGIN CERTIFICATE-----\n" + data + b"\n-----END CERTIFICATE-----\n"
        for data in (b"YWJj", b"ZGVm", b"Z2hp")
    )
    update = Mock(side_effect=subprocess.CalledProcessError(1, "update-ca-certificates"))
    monkeypatch.setattr(installer.subprocess, "run", update)
    with pytest.raises(subprocess.CalledProcessError):
        installer.install(bundle, tmp_path)
    assert not list((tmp_path / "ads-egress").glob(".pending-*"))
    update.assert_called_once_with(("update-ca-certificates", "--fresh"), check=True, timeout=30)
