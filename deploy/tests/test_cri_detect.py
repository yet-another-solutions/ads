from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import socket
import stat
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[2] / "services/ads-ptp-tools/ads-cri"
CONTAINERD = "unix:///run/containerd/containerd.sock"
CRIO = "unix:///var/run/crio/crio.sock"


@pytest.fixture
def cri():
    loader = importlib.machinery.SourceFileLoader("ads_cri", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _crictl(tmp_path):
    path = tmp_path / "crictl"
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(0o755)
    return path


def _socket(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    if path.exists():
        path.unlink()
    server.bind(str(path))
    server.listen(1)
    return server


def test_one_containerd_socket_wins(cri, tmp_path, monkeypatch):
    crictl = _crictl(tmp_path)
    held = _socket(tmp_path / "containerd.sock")
    missing = tmp_path / "missing" / "crio.sock"
    monkeypatch.setattr(
        cri, "PROBES", (f"unix://{tmp_path / 'containerd.sock'}", f"unix://{missing}")
    )
    monkeypatch.setattr(cri.Path, "lstat", _root_lstat(crictl))
    assert cri.detect(crictl) == f"unix://{tmp_path / 'containerd.sock'}"
    held.close()


def test_one_crio_socket_wins(cri, tmp_path, monkeypatch):
    crictl = _crictl(tmp_path)
    held = _socket(tmp_path / "crio.sock")
    missing = tmp_path / "missing" / "containerd.sock"
    monkeypatch.setattr(cri, "PROBES", (f"unix://{missing}", f"unix://{tmp_path / 'crio.sock'}"))
    monkeypatch.setattr(cri.Path, "lstat", _root_lstat(crictl))
    assert cri.detect(crictl) == f"unix://{tmp_path / 'crio.sock'}"
    held.close()


def test_both_live_sockets_fail_closed(cri, tmp_path, monkeypatch):
    crictl = _crictl(tmp_path)
    held = (_socket(tmp_path / "containerd.sock"), _socket(tmp_path / "crio.sock"))
    monkeypatch.setattr(
        cri,
        "PROBES",
        (f"unix://{tmp_path / 'containerd.sock'}", f"unix://{tmp_path / 'crio.sock'}"),
    )
    monkeypatch.setattr(cri.Path, "lstat", _root_lstat(crictl))
    with pytest.raises(ValueError, match="exactly one"):
        cri.detect(crictl)
    for item in held:
        item.close()


def test_neither_socket_fails_closed(cri, tmp_path, monkeypatch):
    crictl = _crictl(tmp_path)
    absent = (tmp_path / "no-containerd.sock", tmp_path / "no-crio.sock")
    monkeypatch.setattr(cri, "PROBES", tuple(f"unix://{path}" for path in absent))
    monkeypatch.setattr(cri.Path, "lstat", _root_lstat(crictl))
    with pytest.raises(ValueError, match="exactly one"):
        cri.detect(crictl)


def test_non_socket_path_is_not_a_winner(cri, tmp_path, monkeypatch):
    crictl = _crictl(tmp_path)
    plain = tmp_path / "containerd.sock"
    plain.write_text("not a socket")
    absent = tmp_path / "no-crio.sock"
    monkeypatch.setattr(cri, "PROBES", (f"unix://{plain}", f"unix://{absent}"))
    monkeypatch.setattr(cri.Path, "lstat", _root_lstat(crictl))
    with pytest.raises(ValueError, match="exactly one"):
        cri.detect(crictl)


def test_socket_that_does_not_answer_crictl_fails(cri, tmp_path, monkeypatch):
    crictl = _crictl(tmp_path)
    held = _socket(tmp_path / "containerd.sock")
    monkeypatch.setattr(cri, "PROBES", (f"unix://{tmp_path / 'containerd.sock'}", CRIO))
    monkeypatch.setattr(cri.Path, "lstat", _root_lstat(crictl))
    monkeypatch.setattr(cri, "answers", lambda *args: False)
    with pytest.raises(ValueError, match="did not answer"):
        cri.detect(crictl)
    held.close()


def _root_lstat(crictl):
    original = Path.lstat

    def info(path, *args, **kwargs):
        value = original(path, *args, **kwargs)
        if Path(path) == crictl:
            return os.stat_result(
                (stat.S_IFREG | 0o755, value.st_ino, value.st_dev, 1, 0, 0, value.st_size, 0, 0, 0)
            )
        return value

    return info
