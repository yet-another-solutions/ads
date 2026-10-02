"""The host installer copies the plugin and writes one conflist per runtime directory."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import socket
import stat
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[2] / "services/ads-ptp-tools/ads-ptp-cni"


@pytest.fixture
def installer():
    loader = importlib.machinery.SourceFileLoader("ads_ptp_cni", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _source(tmp_path):
    source = tmp_path / "image"
    source.mkdir()
    path = source / "ads-ptp"
    path.write_bytes(b"plugin-ads-ptp")
    path.chmod(0o755)
    return source


def _config(tmp_path):
    certs = tmp_path / "tls"
    certs.mkdir()
    for name in ("ca.crt", "tls.crt", "tls.key"):
        (certs / name).write_bytes(b"secret-" + name.encode())
    return {
        "cniVersion": "1.0.0",
        "name": "ads-private",
        "type": "ads-ptp",
        "attestorSocket": str(tmp_path / "attestor-v0.0.42.sock"),
        "ownerSocket": str(tmp_path / "node-owner-v0.0.42.sock"),
        "attestorCN": "ads-ptp-attestor",
        "ca": str(certs / "ca.crt"),
        "certificate": str(certs / "tls.crt"),
        "key": str(certs / "tls.key"),
        "stateDir": str(tmp_path / "state"),
        "bindingDir": str(tmp_path / "bindings"),
    }


def _bind(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    if path.exists():
        path.unlink()
    server.bind(str(path))
    server.listen(1)
    return server


def test_containerd_install_writes_each_runtime_directory(installer, tmp_path, monkeypatch):
    source = _source(tmp_path)
    binary = tmp_path / "bin"
    shared = tmp_path / "net.d"
    guest = tmp_path / "guest"
    egress = tmp_path / "egress"
    held = (_bind(tmp_path / "attestor-v0.0.42.sock"), _bind(tmp_path / "node-owner-v0.0.42.sock"))
    live = _bind(tmp_path / "containerd.sock")
    config = _config(tmp_path)
    monkeypatch.setattr(installer, "STATE_DIRS", (config["stateDir"], config["bindingDir"]))
    monkeypatch.setattr(
        installer,
        "PROBES",
        {f"unix://{tmp_path / 'containerd.sock'}": (str(shared), str(guest), str(egress))},
    )
    directories = installer.runtime_dirs()
    for directory in directories:
        installer.install(config, source, binary, directory, tmp_path / "certs")
    for directory in (shared, guest, egress):
        written = json.loads((directory / "10-ads-ptp.conflist").read_text())
        assert written["name"] == "ads-private"
        assert written["plugins"][0]["attestorSocket"] == config["attestorSocket"]
        assert "attestorConfig" not in written["plugins"][0]
    assert not (shared / "10-crio-bridge.conflist").exists()
    name = "ads-ptp"
    assert (binary / name).read_bytes() == (source / name).read_bytes()
    assert stat.S_IMODE((binary / name).stat().st_mode) == 0o755
    assert not (binary / "ads-ptp-attest").exists()
    assert not (binary / "ads-cri").exists()
    for item in (*held, live):
        item.close()


def test_missing_socket_does_not_write_conflist(installer, tmp_path, monkeypatch):
    source = _source(tmp_path)
    network = tmp_path / "net.d"
    network.mkdir()
    config = _config(tmp_path)
    monkeypatch.setattr(
        installer,
        "sockets_bound",
        lambda _config: (_ for _ in ()).throw(ValueError("unbound")),
    )
    with pytest.raises(ValueError, match="unbound"):
        installer.install(config, source, tmp_path / "bin", network)
    assert not (network / "10-ads-ptp.conflist").exists()


def test_discover_cri_socket_skips_symlinks_and_non_sockets(installer, tmp_path, monkeypatch):
    held = _bind(tmp_path / "live.sock")
    plain = tmp_path / "containerd.sock"
    plain.write_text("not a socket")
    link = tmp_path / "linked.sock"
    if link.exists():
        link.unlink()
    link.symlink_to(tmp_path / "live.sock")
    monkeypatch.setattr(
        installer,
        "PROBES",
        (f"unix://{plain}", f"unix://{link}", "unix:///missing/crio.sock"),
    )
    with pytest.raises(ValueError, match="exactly one"):
        installer.discover_cri_socket()
    # A single live real socket wins.
    monkeypatch.setattr(
        installer,
        "PROBES",
        (f"unix://{tmp_path / 'live.sock'}", "unix:///missing/crio.sock"),
    )
    assert installer.discover_cri_socket() == f"unix://{tmp_path / 'live.sock'}"
    held.close()


def test_discover_cri_socket_fails_when_two_sockets_live(installer, tmp_path, monkeypatch):
    first = _bind(tmp_path / "a.sock")
    second = _bind(tmp_path / "b.sock")
    monkeypatch.setattr(
        installer,
        "PROBES",
        (f"unix://{tmp_path / 'a.sock'}", f"unix://{tmp_path / 'b.sock'}"),
    )
    with pytest.raises(ValueError, match="exactly one live CRI socket"):
        installer.discover_cri_socket()
    for item in (first, second):
        item.close()


def test_crio_bridge_stays_disabled(installer, tmp_path, monkeypatch):
    network = tmp_path / "net.d.crio"
    network.mkdir()
    (network / "10-crio-bridge.conflist").write_text("{}\n")
    _bind(tmp_path / "crio.sock")
    monkeypatch.setattr(installer, "PROBES", {f"unix://{tmp_path / 'crio.sock'}": (str(network),)})
    with pytest.raises(ValueError, match="bridge"):
        installer.runtime_dirs()
    assert (network / "10-crio-bridge.conflist").is_file()
    assert not (network / "10-ads-ptp.conflist").exists()
