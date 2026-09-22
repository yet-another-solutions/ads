from __future__ import annotations

import base64
import importlib.machinery
import importlib.util
import json
from pathlib import Path
from uuid import uuid4

import pytest

SCRIPT = Path(__file__).parents[2] / "services/ads-ptp-tools/ads-ptp-canary"


@pytest.fixture
def canary(monkeypatch, tmp_path):
    loader = importlib.machinery.SourceFileLoader("ptp_canary", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    monkeypatch.setenv("POD_UID", str(uuid4()))
    monkeypatch.setenv("ATTACHMENT_GENERATION", str(uuid4()))
    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(module, "namespace_identity", lambda name: [1, 100])
    return module


@pytest.fixture
def config(canary):
    pod, generation = canary.identity()
    return {
        "pod_uid": pod,
        "generation": generation,
        "side": "guest",
        "local_private": "10.10.30.2/24",
        "peer_private": "10.10.30.1/24",
        "local_tunnel": "10.10.40.2/32",
        "peer_tunnel": "10.10.40.1/32",
        "transport_mtu": 1450,
        "peer_key": base64.b64encode(bytes(range(32))).decode(),
        "endpoint": "10.32.0.99:51820",
        "wireguard_port": 51820,
        "vxlan_port": 4789,
        "vni": 42,
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("pod_uid", str(uuid4())),
        ("generation", str(uuid4())),
        ("side", "host"),
        ("local_private", "127.0.0.1/24"),
        ("local_private", "10.10.30.0/24"),
        ("peer_private", "10.10.30.255/24"),
        ("local_tunnel", "10.10.40.2/24"),
        ("peer_tunnel", "10.10.30.1/32"),
        ("transport_mtu", True),
        ("transport_mtu", 685),
        ("vni", 0),
        ("peer_key", "bad"),
        ("endpoint", "1.2.3.4:12345"),
        ("endpoint", "service.example:51820"),
    ],
)
def test_invalid_topology_and_identity_fail_before_any_effect(canary, config, field, value):
    config[field] = value
    with pytest.raises((ValueError, TypeError)):
        canary.validate(config)


def test_exact_fields_and_egress_endpoint_learning(canary, config):
    assert canary.validate(config) == config
    with pytest.raises(ValueError):
        canary.validate({**config, "unknown": True})
    config["side"] = "egress"
    with pytest.raises(ValueError):
        canary.validate(config)
    config["endpoint"] = None
    assert canary.validate(config) == config


def test_setup_preserves_birthplace_and_no_routing_or_transport_bridge(canary, config, monkeypatch):
    root = canary.directory()
    root.mkdir()
    canary.private_file(
        root / "identity.json", json.dumps({k: config[k] for k in ("pod_uid", "generation")})
    )
    calls = []
    monkeypatch.setattr(canary, "run", lambda *args, **kw: calls.append((args, kw)) or "")
    result = canary.configure(config)
    private, mock = canary.ns_names()
    commands = [args for args, _ in calls]
    create = ("ip", "link", "add", "wg-private", "type", "wireguard")
    move = ("ip", "link", "set", "wg-private", "netns", private)
    assert commands.index(create) < commands.index(move)
    assert result["private_mtu"] == 1340
    assert result["wireguard_mtu"] == 1390
    assert result["socket_configured"] is True and result["tunnel_proven"] is False
    assert sum("master" in command for command in commands) == 2
    assert not any("nat" in command or "eth0" in command for command in commands)
    assert not any("default" in command and private in command for command in commands)
    assert any("default" in command and mock in command for command in commands)
    assert any("persistent-keepalive" in command and "25" in command for command in commands)
    assert "table bridge" in canary.firewall(config)
    assert "policy drop" in canary.firewall(config)
    assert not any("showconf" in command or "dump" in command for command in commands)
    with pytest.raises(ValueError):
        canary.configure(config)


def test_namespace_collision_never_deletes_foreign_namespace(canary, config, monkeypatch):
    root = canary.directory()
    root.mkdir()
    canary.private_file(
        root / "identity.json", json.dumps({k: config[k] for k in ("pod_uid", "generation")})
    )
    calls = []

    def fail(*args, **kwargs):
        calls.append(args)
        raise RuntimeError("exists")

    monkeypatch.setattr(canary, "run", fail)
    with pytest.raises(RuntimeError):
        canary.configure(config)
    assert calls == [("ip", "netns", "add", canary.ns_names()[0])]
    monkeypatch.setattr(
        canary, "run", lambda *args, **kw: json.dumps([{"name": canary.ns_names()[0]}])
    )
    with pytest.raises(RuntimeError, match="foreign"):
        canary.cleanup()


def test_cleanup_cannot_follow_another_generation_or_live_diagnostic(canary, config, monkeypatch):
    root = canary.directory()
    root.mkdir()
    canary.private_file(
        root / "identity.json", json.dumps({k: config[k] for k in ("pod_uid", "generation")})
    )
    private, mock = canary.ns_names()
    canary.save_namespaces({private: [1, 100], mock: [1, 100]})
    calls = []

    def fake(*args, **kwargs):
        calls.append(args)
        if args == ("ip", "-j", "netns", "list"):
            return json.dumps([{"name": private}, {"name": mock}])
        if args[:3] == ("ip", "netns", "pids"):
            return "4321"
        raise AssertionError("must not delete a busy namespace")

    monkeypatch.setattr(canary, "run", fake)
    with pytest.raises(RuntimeError, match="processes"):
        canary.cleanup()
    assert not any("delete" in command for command in calls)
    monkeypatch.setenv("ATTACHMENT_GENERATION", str(uuid4()))
    with pytest.raises(FileNotFoundError):
        canary.cleanup()


def test_cleanup_rejects_replaced_namespace_before_any_delete(canary, config, monkeypatch):
    root = canary.directory()
    root.mkdir()
    canary.private_file(
        root / "identity.json", json.dumps({k: config[k] for k in ("pod_uid", "generation")})
    )
    private, mock = canary.ns_names()
    canary.save_namespaces({private: [1, 100], mock: [1, 99]})
    calls = []

    def fake(*args, **kwargs):
        calls.append(args)
        return json.dumps([{"name": private}, {"name": mock}])

    monkeypatch.setattr(canary, "run", fake)
    with pytest.raises(RuntimeError, match="replaced"):
        canary.cleanup()
    assert calls == [("ip", "-j", "netns", "list")]


def test_cleanup_removes_only_owned_names_and_ephemeral_material(canary, config, monkeypatch):
    root = canary.directory()
    root.mkdir()
    canary.private_file(
        root / "identity.json", json.dumps({k: config[k] for k in ("pod_uid", "generation")})
    )
    canary.private_file(root / "key", "private")
    names = set(canary.ns_names())
    canary.save_namespaces(dict.fromkeys(names, [1, 100]))
    names.add("unrelated")

    def fake(*args, **kwargs):
        if args == ("ip", "-j", "netns", "list"):
            return json.dumps([{"name": name} for name in names])
        if args[:3] == ("ip", "netns", "pids"):
            return ""
        if args[:3] == ("ip", "netns", "delete"):
            names.remove(args[3])
            return ""
        raise AssertionError(args)

    monkeypatch.setattr(canary, "run", fake)
    assert canary.cleanup()["cleaned"] is True
    assert names == {"unrelated"}
    assert not root.exists()


def test_private_files_are_exclusive_bounded_and_nofollow(canary, tmp_path):
    path = tmp_path / "key"
    canary.private_file(path, "sensitive")
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        canary.private_file(path, "replacement")
    symlink = tmp_path / "symlink"
    symlink.symlink_to(path)
    with pytest.raises(OSError):
        canary.read_file(symlink)
    large = tmp_path / "large"
    large.write_text("x" * 65537)
    with pytest.raises(ValueError):
        canary.read_file(large)
