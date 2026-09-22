"""Guest handoff identity and fail-closed tests; real namespace moves run in CI."""

import copy
import importlib.machinery
import importlib.util
import json
import os
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "services/ads-sandbox-base/scripts/ads-sandbox-network"
loader = importlib.machinery.SourceFileLoader("sandbox_network", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
network = importlib.util.module_from_spec(spec)
loader.exec_module(network)
GENERATION = "0260e602-b582-440c-b0c3-85e8dcc7d4b5"
ENV = {
    "ADS_SANDBOX_NETWORK_MODE": "private",
    "ADS_ATTACHMENT_GENERATION": GENERATION,
    "ADS_PRIVATE_MTU": "1340",
}
CONFIG = network.configuration(ENV)
RECORD = {"id": "a" * 64, "pid": 42, "running": True, "network": "none", "contract": "nested-v1"}


def observation(attached=True):
    links = [{"ifname": "lo", "flags": ["UP"]}]
    addresses = [{"ifname": "lo", "addr_info": []}]
    routes = [{"dst": "127.0.0.0/8", "dev": "lo", "table": "local"}]
    if attached:
        links.append({"ifname": "eth0", "address": CONFIG["mac"], "mtu": 1340, "flags": ["UP"]})
        addresses.append(
            {
                "ifname": "eth0",
                "addr_info": [{"family": "inet", "local": "10.10.30.2", "prefixlen": 24}],
            }
        )
        routes += [
            {"dst": "10.10.30.0/24", "dev": "eth0"},
            {"dst": "default", "dev": "eth0", "gateway": "10.10.30.1"},
        ]
    return {"links": links, "addresses": addresses, "routes": routes, "ipv6": []}


def test_generation_mac_matches_cni_and_relay():
    assert CONFIG == {"generation": GENERATION, "mtu": 1340, "mac": "02:ab:d6:59:a0:dd"}


@pytest.mark.parametrize(
    "name,value",
    [
        ("ADS_SANDBOX_NETWORK_MODE", "none"),
        ("ADS_ATTACHMENT_GENERATION", ""),
        ("ADS_ATTACHMENT_GENERATION", GENERATION.upper()),
        ("ADS_PRIVATE_MTU", ""),
        ("ADS_PRIVATE_MTU", "1.5"),
        ("ADS_PRIVATE_MTU", "575"),
        ("ADS_PRIVATE_MTU", "65426"),
        ("ADS_PRIVATE_MTU", "١٣٤٠"),
    ],
)
def test_invalid_configuration_fails(name, value):
    with pytest.raises(ValueError):
        network.configuration({**ENV, name: value})


@pytest.mark.parametrize("attached", [True, False])
def test_expected_topology(attached):
    network.validate_network(observation(attached), CONFIG, attached)


@pytest.mark.parametrize(
    "change",
    [
        "extra",
        "missing",
        "duplicate",
        "lo-down",
        "mac",
        "mtu",
        "down",
        "master",
        "address",
        "prefix",
        "ipv6-address",
        "ipv6-route",
        "route",
        "gateway",
        "route-device",
    ],
)
def test_extra_path_or_wrong_identity_denied(change):
    value = observation()
    if change == "extra":
        value["links"].append({"ifname": "eth1", "flags": ["UP"]})
    elif change == "missing":
        value["addresses"].pop()
    elif change == "duplicate":
        value["links"].append(value["links"][0])
    elif change == "lo-down":
        value["links"][0]["flags"] = []
    elif change in ("mac", "mtu", "down", "master"):
        key, changed = {
            "mac": ("address", "02:00:00:00:00:00"),
            "mtu": ("mtu", 1500),
            "down": ("flags", []),
            "master": ("master", "br0"),
        }[change]
        value["links"][1][key] = changed
    elif change in ("address", "prefix"):
        key, changed = ("local", "10.200.0.1") if change == "address" else ("prefixlen", 16)
        value["addresses"][1]["addr_info"][0][key] = changed
    elif change == "ipv6-address":
        value["addresses"][1]["addr_info"].append({"family": "inet6", "local": "fe80::1"})
    elif change == "ipv6-route":
        value["ipv6"].append({"dst": "default", "dev": "eth0"})
    elif change == "route":
        value["routes"].append({"dst": "1.1.1.1", "dev": "eth0"})
    elif change == "gateway":
        value["routes"][2]["gateway"] = "10.200.0.1"
    else:
        value["routes"][2]["dev"] = "eth1"
    with pytest.raises(ValueError):
        network.validate_network(value, CONFIG, True)


def test_empty_target_rejects_nonloopback_route():
    value = observation(False)
    value["routes"].append({"dst": "default", "dev": "foreign"})
    with pytest.raises(ValueError):
        network.validate_network(value, CONFIG, False)


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", "a" * 63),
        ("pid", 1),
        ("pid", True),
        ("running", False),
        ("network", "host"),
        ("contract", "other"),
        ("unexpected", "field"),
    ],
)
def test_container_inspection_requires_exact_identity(monkeypatch, field, value):
    monkeypatch.setattr(network, "execute", lambda _: json.dumps({**RECORD, field: value}))
    with pytest.raises(ValueError):
        network.inspect_container()


def test_container_inspection_runs_only_trusted_rootless_helper(monkeypatch):
    execute = Mock(return_value=json.dumps(RECORD))
    monkeypatch.setattr(network, "execute", execute)
    assert network.inspect_container() == RECORD
    assert execute.call_args.args[0] == [
        "/usr/local/sbin/ads-sandbox-runtime",
        "podman",
        "inspect",
        "--format",
        network.INSPECT,
        "dev-sandbox",
    ]


@pytest.fixture
def target_tree(tmp_path, monkeypatch):
    proc = tmp_path / "proc"
    for base in ("self", "42"):
        (proc / base / "ns").mkdir(parents=True)
        for name in ("net", "user"):
            (proc / base / "ns" / name).touch()
    leaf = proc / "42"
    (leaf / "stat").write_text("42 (misleading) process name)) S " + "0 " * 18 + "123 0")
    (leaf / "status").write_text("Uid:\t1000 1000 1000 1000\nGid:\t1000 1000 1000 1000\n")
    for name in ("uid_map", "gid_map"):
        (leaf / name).write_text("0 1000 1\n1 100000 65536\n")
    (leaf / "cgroup").write_text(f"0::/ads-budget/podman/libpod-{RECORD['id']}\n")
    monkeypatch.setattr(network, "PROC", proc)
    monkeypatch.setattr(
        network.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=1000, pw_gid=1000)
    )
    original_read = Path.read_text

    def read(path, *args, **kwargs):
        if str(path) in ("/etc/subuid", "/etc/subgid"):
            return "podman:100000:65536\n"
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    read_fd, write_fd = os.pipe()
    monkeypatch.setattr(network.os, "pidfd_open", lambda _: os.dup(read_fd), raising=False)

    def ioctl(fd, operation, *args):
        if operation == network.NS_GET_NSTYPE:
            return network.CLONE_NEWNET
        if operation == network.NS_GET_USERNS:
            return os.open(leaf / "ns/user", os.O_RDONLY)
        assert operation == network.NS_GET_OWNER_UID
        args[0][0] = 1000
        return 0

    monkeypatch.setattr(network.fcntl, "ioctl", ioctl)
    monkeypatch.setattr(network, "inspect_container", lambda: copy.deepcopy(RECORD))
    yield leaf, write_fd
    os.close(read_fd)
    os.close(write_fd)


def test_pins_identity_and_parses_hostile_comm(target_tree):
    with ExitStack() as stack:
        target = network.Target(RECORD, stack)
        assert target.ticks == 123
        target.recheck()


@pytest.mark.parametrize(
    "change",
    ["exit", "ticks", "net", "user", "uid", "gid", "uid_map", "gid_map", "cgroup", "inspect"],
)
def test_target_change_is_denied(target_tree, monkeypatch, change):
    leaf, writer = target_tree
    with ExitStack() as stack:
        target = network.Target(RECORD, stack)
        if change == "exit":
            os.write(writer, b"x")
        elif change == "ticks":
            (leaf / "stat").write_text("42 (reused) S " + "0 " * 18 + "124 0")
        elif change in ("net", "user"):
            (leaf / "ns" / change).unlink()
            (leaf / "ns" / change).touch()
        elif change in ("uid", "gid"):
            status = (leaf / "status").read_text()
            (leaf / "status").write_text(
                status.replace(change.title() + ":\t1000", change.title() + ":\t0")
            )
        elif change in ("uid_map", "gid_map"):
            (leaf / change).write_text("0 0 4294967295\n")
        elif change == "cgroup":
            (leaf / "cgroup").write_text("0::/init\n")
        else:
            monkeypatch.setattr(network, "inspect_container", lambda: {**RECORD, "pid": 43})
        with pytest.raises(ValueError):
            target.recheck()


@pytest.mark.parametrize("bad_owner", ["uid", "namespace", "type"])
def test_namespace_owner_and_kind_required(target_tree, monkeypatch, bad_owner):
    original = network.fcntl.ioctl

    def ioctl(fd, operation, *args):
        if bad_owner == "uid" and operation == network.NS_GET_OWNER_UID:
            args[0][0] = 0
            return 0
        if bad_owner == "namespace" and operation == network.NS_GET_USERNS:
            return os.open(network.PROC / "self/ns/user", os.O_RDONLY)
        if bad_owner == "type" and operation == network.NS_GET_NSTYPE:
            return 0
        return original(fd, operation, *args)

    monkeypatch.setattr(network.fcntl, "ioctl", ioctl)
    with ExitStack() as stack, pytest.raises(ValueError):
        network.Target(RECORD, stack)


def test_transfer_uses_held_fd_and_only_trusted_network_operations(monkeypatch):
    observed = Mock(
        side_effect=[observation(), observation(False), observation(False), observation()]
    )
    monkeypatch.setattr(network, "inventory", observed)
    ip, execute = Mock(), Mock()
    monkeypatch.setattr(network, "ip", ip)
    monkeypatch.setattr(network, "execute", execute)
    target = SimpleNamespace(net=123, recheck=Mock(), check=Mock())
    network.transfer(CONFIG, target)
    assert target.recheck.call_count == 2
    assert ip.call_args_list[1].args == ("link", "set", "dev", "eth0", "netns", "/proc/self/fd/123")
    assert ip.call_args_list[1].kwargs == {"extra_fds": (123,)}
    assert all(call.kwargs == {"namespace": 123} for call in ip.call_args_list[2:])
    assert execute.call_args.args[0][0] == "/usr/sbin/sysctl"
    assert execute.call_args.args[1] == 123


def test_changed_target_prevents_first_network_effect(monkeypatch):
    monkeypatch.setattr(network, "inventory", Mock(side_effect=[observation(), observation(False)]))
    execute, ip = Mock(), Mock()
    monkeypatch.setattr(network, "execute", execute)
    monkeypatch.setattr(network, "ip", ip)
    target = SimpleNamespace(net=123, recheck=Mock(side_effect=ValueError("replaced")))
    with pytest.raises(ValueError, match="replaced"):
        network.transfer(CONFIG, target)
    execute.assert_not_called()
    ip.assert_not_called()


@pytest.mark.parametrize("fails", [True, False])
def test_attempt_is_one_shot_even_on_failure(tmp_path, monkeypatch, fails):
    path = tmp_path / "state"
    monkeypatch.setattr(network, "STATE", path)
    monkeypatch.setattr(network, "inspect_container", lambda: RECORD)
    monkeypatch.setattr(network, "Target", lambda *args: object())
    transfer = Mock(side_effect=ValueError("failed") if fails else None)
    monkeypatch.setattr(network, "transfer", transfer)
    if fails:
        with pytest.raises(ValueError):
            network.attach(CONFIG)
    else:
        network.attach(CONFIG)
    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert [record["state"] for record in records] == (
        ["started"] if fails else ["started", "complete"]
    )
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        network.attach(CONFIG)
    assert transfer.call_count == 1


def test_existing_symlink_never_followed(tmp_path, monkeypatch):
    target = tmp_path / "other"
    target.write_text("unchanged")
    path = tmp_path / "state"
    path.symlink_to(target)
    monkeypatch.setattr(network, "STATE", path)
    with pytest.raises(FileExistsError):
        network.attach(CONFIG)
    assert target.read_text() == "unchanged"


def test_command_uses_only_net_namespace_and_private_bounded_output(monkeypatch):
    def run(command, **kwargs):
        assert command == [
            "/usr/bin/nsenter",
            "--net=/proc/self/fd/8",
            "--",
            "/usr/sbin/ip",
            "-j",
            "link",
        ]
        assert kwargs["pass_fds"] == (8,)
        assert kwargs["env"] == network.ENV
        assert kwargs["timeout"] == 10
        kwargs["stdout"].write(b"[]")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(network.subprocess, "run", run)
    assert network.ip("-j", "link", namespace=8) == b"[]"


@pytest.mark.parametrize("output,code", [(b"x" * (network.LIMIT + 1), 0), (b"private error", 1)])
def test_command_failure_or_oversize_is_not_returned(monkeypatch, output, code):
    def run(command, **kwargs):
        kwargs["stdout"].write(output)
        return SimpleNamespace(returncode=code)

    monkeypatch.setattr(network.subprocess, "run", run)
    with pytest.raises(ValueError):
        network.ip("-j", "link")


def test_private_mode_handoff_precedes_trust_init_readiness():
    boot = SCRIPT.with_name("ads-sandbox-boot").read_text()
    assert boot.index("ads-sandbox-network preflight") < boot.index("ads-session-device-check")
    assert boot.index("podman_cmd start dev-sandbox") < boot.index("ads-sandbox-network attach")
    assert boot.index("ads-sandbox-network attach") < boot.index("ads-sandbox-trust certificate")
    assert boot.index("nameserver 10.10.30.1") < boot.index("ads-agent-init")
    assert "cap_sys_admin,cap_net_admin,cap_sys_ptrace" in boot
    assert "unsupported sandbox network mode" in boot
