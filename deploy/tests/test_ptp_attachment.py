from __future__ import annotations

import contextlib
import importlib.machinery
import importlib.util
import json
import os
from copy import deepcopy
from pathlib import Path
from uuid import uuid4

import pytest

SCRIPT = Path(__file__).parents[2] / "services/ads-ptp-tools/ads-ptp"


@pytest.fixture
def plugin():
    loader = importlib.machinery.SourceFileLoader("ptp_attachment", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@pytest.fixture
def inputs(plugin, tmp_path):
    for name in ("state", "bindings"):
        (tmp_path / name).mkdir(mode=0o700)
    config = {
        "cniVersion": "1.0.0",
        "type": "ads-ptp",
        "name": "ads-private",
        "stateDir": str(tmp_path / "state"),
        "bindingDir": str(tmp_path / "bindings"),
    }
    uid = str(uuid4())
    env = {
        "CNI_COMMAND": "ADD",
        "CNI_CONTAINERID": "a" * 64,
        "CNI_IFNAME": "eth0",
        "CNI_NETNS": "/run/netns/test-vm",
        "CNI_ARGS": "K8S_POD_UID=" + uid,
    }
    attestation = {
        "pod_uid": uid,
        "generation": str(uuid4()),
        "sandbox_id": str(uuid4()),
        "role": "guest",
        "ifname": "eth0",
        "network": "ads-private",
        "relay_pod_uid": str(uuid4()),
        "relay_runtime_id": "b" * 64,
        "private": {"path": "/run/netns/test-private", "identity": [1, 2]},
        "transport": {"path": "/run/netns/test-cni", "identity": [1, 3]},
        "mtu": 1340,
        "address": "10.10.30.2/24",
        "gateway": "10.10.30.1",
    }
    plugin.save_record(tmp_path / "bindings" / (uid + ".json"), attestation)
    return config, env, attestation


@pytest.mark.parametrize(
    "field,value",
    [
        ("CNI_CONTAINERID", "../target"),
        ("CNI_IFNAME", "eth0;ip"),
        ("CNI_IFNAME", "x" * 16),
        ("CNI_ARGS", "K8S_POD_UID=no"),
        ("CNI_ARGS", ""),
        ("CNI_NETNS", ""),
        ("CNI_COMMAND", "GC"),
    ],
)
def test_invalid_runtime_inputs(plugin, inputs, field, value):
    config, env, _ = inputs
    env[field] = value
    with pytest.raises(ValueError):
        plugin.request(config, env)


def test_del_accepts_missing_namespace_and_uid_and_repetition(plugin, inputs):
    config, env, _ = inputs
    env.update(CNI_COMMAND="DEL", CNI_NETNS="", CNI_ARGS="")
    assert plugin.perform(config, env) is None
    assert plugin.perform(config, env) is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("pod_uid", str(uuid4())),
        ("generation", "not-uuid"),
        ("sandbox_id", "not-uuid"),
        ("role", "host"),
        ("ifname", "other"),
        ("network", "foreign"),
        ("relay_runtime_id", "b"),
        ("mtu", True),
        ("mtu", 575),
        ("mtu", 65426),
        ("address", "::1/24"),
        ("address", "10.10.30.0/24"),
        ("address", "10.10.30.255/24"),
        ("address", "8.8.8.8/24"),
        ("address", "127.0.0.2/24"),
        ("address", "169.254.0.2/24"),
        ("address", "240.0.0.2/24"),
        ("address", "10.10.30.2/32"),
        ("gateway", "10.10.30.2"),
        ("gateway", "10.10.31.1"),
        ("gateway", "10.10.30.0"),
        ("gateway", "10.10.30.255"),
        ("private", {"path": "relative", "identity": [1, 2]}),
        ("private", {"path": "/run/netns/private", "identity": [True, 2]}),
    ],
)
def test_attestation_fails_closed(plugin, inputs, field, value):
    config, env, record = inputs
    record[field] = value
    with pytest.raises((ValueError, TypeError)):
        plugin.binding(record, plugin.request(config, env))


def test_exact_fields_and_private_transport_separation(plugin, inputs):
    config, env, record = inputs
    req = plugin.request(config, env)
    assert plugin.binding(record, req) == record
    with pytest.raises(ValueError):
        plugin.binding({**record, "extra": 1}, req)
    record["private"] = deepcopy(record["transport"])
    with pytest.raises(ValueError, match="ordinary transport"):
        plugin.binding(record, req)


def test_records_reject_symlink_permissions_duplicate_and_oversize(plugin, tmp_path):
    record = tmp_path / "record"
    plugin.save_record(record, {"safe": True})
    assert plugin.read_record(record) == {"safe": True}
    link = tmp_path / "link"
    link.symlink_to(record)
    with pytest.raises(OSError):
        plugin.read_record(link)
    record.chmod(0o644)
    with pytest.raises(ValueError):
        plugin.read_record(record)
    with pytest.raises(ValueError):
        plugin.decode('{"x":1,"x":2}')
    with pytest.raises(ValueError):
        plugin.decode(" " * 65537)
    with pytest.raises(ValueError):
        plugin.decode("[]")


def test_namespace_replacement_and_non_namespace_rejected(plugin, monkeypatch, tmp_path):
    path = tmp_path / "ns"
    path.touch()
    monkeypatch.setattr(plugin.fcntl, "ioctl", lambda *args: plugin.CLONE_NEWNET)
    with pytest.raises(ValueError, match="replaced"), plugin.namespace(path, [1, 1]):
        pass
    monkeypatch.setattr(plugin.fcntl, "ioctl", lambda *args: 123)
    with pytest.raises(ValueError, match="not a network"), plugin.namespace(path):
        pass
    with plugin.namespace(tmp_path / "gone", missing=True) as fd:
        assert fd is None


def test_result_adds_static_private_endpoint_and_preserves_egress_upstream(plugin, inputs):
    config, env, record = inputs
    req = plugin.request(config, env)
    value = plugin.result(req, record, "02:00:00:00:00:01", None)
    assert value["ips"] == [{"address": "10.10.30.2/24", "interface": 0, "gateway": "10.10.30.1"}]
    assert value["routes"] == [{"dst": "0.0.0.0/0", "gw": "10.10.30.1"}]
    assert value["dns"] == {"nameservers": ["10.10.30.1"]}
    previous = {
        "cniVersion": "1.0.0",
        "interfaces": [{"name": "upstream"}],
        "ips": [{"address": "10.200.1.2/32", "interface": 0}],
        "routes": [{"dst": "0.0.0.0/0", "gw": "10.200.1.1"}],
    }
    with pytest.raises(ValueError, match="guest"):
        plugin.result(req, record, "02:00:00:00:00:01", previous)
    record["role"] = "egress"
    with pytest.raises(ValueError, match="upstream gateway"):
        plugin.result(req, record, "02:00:00:00:00:01", previous)
    record.update(address="10.10.30.1/24", gateway=None)
    value = plugin.result(req, record, "02:00:00:00:00:01", previous)
    assert value["ips"] == previous["ips"] + [{"address": "10.10.30.1/24", "interface": 1}]
    assert value["routes"] == previous["routes"]
    assert len(previous["interfaces"]) == 1
    assert len(value["interfaces"]) == 2


@pytest.fixture
def kernel(plugin, inputs, monkeypatch):
    config, env, record = inputs
    req = plugin.request(config, env)
    state = Path(config["stateDir"]) / (req["key"] + ".json")
    paths = {
        env["CNI_NETNS"]: 10,
        record["private"]["path"]: 20,
        record["transport"]["path"]: 30,
        "/proc/self/ns/net": 40,
    }
    current = {
        10: {"lo": {"ifname": "lo"}},
        20: {
            "br-private": {
                "ifname": "br-private",
                "ifindex": 1,
                "mtu": 1340,
                "flags": ["UP"],
                "ifalias": plugin.bridge_identity(record),
                "linkinfo": {"info_kind": "bridge"},
            },
            "vxlan-private": {
                "ifname": "vxlan-private",
                "master": "br-private",
                "linkinfo": {"info_kind": "vxlan"},
            },
        },
    }
    calls = []

    @contextlib.contextmanager
    def namespace(path, expected=None, missing=False):
        fd = paths.get(str(path))
        if fd is None and not missing:
            raise FileNotFoundError(path)
        yield fd

    def execute(fd, *args, **kwargs):
        calls.append((fd, args))
        if args[:3] == ("ip", "-j", "address"):
            return json.dumps(
                [{"addr_info": [{"family": "inet", "local": "10.10.30.2", "prefixlen": 24}]}]
                if fd == 10
                else [{"addr_info": []}]
            )
        if args[:3] == ("ip", "-j", "route"):
            return json.dumps([{"gateway": "10.10.30.1", "dev": "eth0"}])
        if args[:3] == ("ip", "link", "add"):
            assert plugin.read_record(state)["indices"] is None
            marker = plugin.alias(req, record)
            for where, name, index in ((10, "eth0", 11), (20, "veth-local", 21)):
                current[where][name] = {
                    "ifname": name,
                    "ifindex": index,
                    "mtu": 1340,
                    "flags": ["UP"],
                    "group": plugin.link_group(marker),
                    "linkinfo": {"info_kind": "veth"},
                }
        if args[:3] == ("ip", "link", "set") and "alias" in args:
            current[fd][args[3]]["ifalias"] = args[-1]
        if "master" in args:
            current[20]["veth-local"]["master"] = "br-private"
        if args[:3] == ("ip", "link", "delete"):
            current[10].pop("eth0", None)
            current[20].pop("veth-local", None)
        return ""

    monkeypatch.setattr(plugin, "namespace", namespace)
    monkeypatch.setattr(plugin, "ns_identity", lambda fd: [1, fd])
    monkeypatch.setattr(plugin, "links", lambda fd: deepcopy(current[fd]))
    monkeypatch.setattr(plugin, "execute", execute)
    return req, record, state, current, paths, calls


def test_real_add_journal_check_and_idempotent_delete_with_fake_kernel(plugin, inputs, kernel):
    config, env, _ = inputs
    req, record, state, current, paths, calls = kernel
    output = plugin.perform(config, env)
    assert plugin.read_record(state)["indices"] == {"vm": 11, "peer": 21}
    config["prevResult"] = output
    env["CNI_COMMAND"] = "CHECK"
    assert plugin.perform(config, env) is None
    # A later chained plugin may add an unrelated route.
    config["prevResult"]["routes"].append({"dst": "198.18.0.0/24"})
    assert plugin.perform(config, env) is None
    env["CNI_COMMAND"] = "DEL"
    assert plugin.perform(config, env) is None
    assert plugin.perform(config, env) is None
    assert not state.exists()
    assert set(current[10]) == {"lo"}
    assert set(current[20]) == {"br-private", "vxlan-private"}
    address_calls = [(fd, args) for fd, args in calls if args[:3] == ("ip", "address", "add")]
    assert address_calls == [(10, ("ip", "address", "add", "10.10.30.2/24", "dev", "eth0"))]
    route_calls = [(fd, args) for fd, args in calls if args[:3] == ("ip", "route", "add")]
    assert route_calls == [
        (10, ("ip", "route", "add", "default", "via", "10.10.30.1", "dev", "eth0"))
    ]
    create = next(args for _, args in calls if args[:3] == ("ip", "link", "add"))
    assert create[-1] == "/proc/self/fd/20"


def test_partial_add_retains_intent_for_del(plugin, inputs, kernel, monkeypatch):
    config, env, _ = inputs
    *_, calls = kernel
    original = plugin.execute

    def fail_after_create(fd, *args, **kwargs):
        if "master" in args:
            raise RuntimeError("injected interruption")
        return original(fd, *args, **kwargs)

    monkeypatch.setattr(plugin, "execute", fail_after_create)
    with pytest.raises(RuntimeError):
        plugin.perform(config, env)
    state = kernel[2]
    assert plugin.read_record(state)["indices"] is None
    env["CNI_COMMAND"] = "DEL"
    assert plugin.perform(config, env) is None
    assert not state.exists()


@pytest.mark.parametrize("change", ["alias", "index", "group", "binding", "bridge", "other-nic"])
def test_replacement_or_foreign_resources_never_deleted(plugin, inputs, kernel, change):
    config, env, record = inputs
    req, _, state, current, paths, calls = kernel
    if change == "other-nic":
        current[10]["bypass"] = {"ifname": "bypass"}
        with pytest.raises(ValueError, match="another interface"):
            plugin.perform(config, env)
        assert not state.exists()
        return
    if change == "bridge":
        current[20]["br-private"]["ifalias"] = "foreign"
        with pytest.raises(ValueError, match="bridge identity"):
            plugin.perform(config, env)
        assert not state.exists()
        return
    plugin.perform(config, env)
    if change == "binding":
        record["generation"] = str(uuid4())
        plugin.save_record(Path(config["bindingDir"]) / (req["pod_uid"] + ".json"), record)
        env["CNI_COMMAND"] = "CHECK"
    else:
        field = {"alias": "ifalias", "index": "ifindex", "group": "group"}[change]
        current[20]["veth-local"][field] = "replacement"
        env["CNI_COMMAND"] = "DEL"
    with pytest.raises(ValueError):
        plugin.perform(config, env)
    assert "eth0" in current[10]
    assert not any("delete" in args for _, args in calls)


def test_del_uses_original_binding_when_relay_record_changes(plugin, inputs, kernel):
    config, env, record = inputs
    plugin.perform(config, env)
    record["private"]["path"] = "/some/replacement"
    plugin.save_record(Path(config["bindingDir"]) / (record["pod_uid"] + ".json"), record)
    env.update(CNI_COMMAND="DEL", CNI_NETNS="", CNI_ARGS="")
    assert plugin.perform(config, env) is None
    assert not kernel[2].exists()


def test_lock_and_missing_attestation_fail_before_kernel(plugin, inputs, monkeypatch):
    config, env, record = inputs
    path = Path(config["bindingDir"]) / (record["pod_uid"] + ".json")
    path.unlink()
    monkeypatch.setattr(plugin, "add", lambda *args: pytest.fail("must not create a link"))
    with pytest.raises(FileNotFoundError):
        plugin.perform(config, env)
    req = plugin.request(config, env)
    lock = Path(config["stateDir"]) / (req["key"] + ".lock")
    fd = os.open(lock, os.O_RDWR)
    try:
        plugin.fcntl.flock(fd, plugin.fcntl.LOCK_EX | plugin.fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):
            plugin.perform(config, env)
    finally:
        os.close(fd)


@pytest.mark.parametrize(
    "fault",
    [
        "same-namespace",
        "ipv6",
        "bridge-port",
        "bridge-address",
        "bridge-kind",
        "vxlan-kind",
        "bridge-down",
        "occupied-peer",
    ],
)
def test_preflight_security_failures_have_no_network_effect(
    plugin, inputs, kernel, monkeypatch, fault
):
    config, env, _ = inputs
    req, record, state, current, paths, calls = kernel
    if fault == "same-namespace":
        monkeypatch.setattr(plugin, "ns_identity", lambda fd: [1, 1])
    elif fault == "ipv6":

        def reject(fd):
            raise RuntimeError("IPv6 enabled")

        monkeypatch.setattr(plugin, "require_ipv4_only", reject)
    elif fault == "bridge-port":
        current[20]["bypass"] = {"master": "br-private"}
    elif fault == "bridge-address":
        monkeypatch.setattr(plugin, "execute", lambda *a, **kw: '[{"addr_info":[{}]}]')
        monkeypatch.setattr(plugin, "require_ipv4_only", lambda fd: None)
    elif fault == "bridge-kind":
        current[20]["br-private"]["linkinfo"]["info_kind"] = "veth"
    elif fault == "vxlan-kind":
        current[20]["vxlan-private"]["linkinfo"]["info_kind"] = "veth"
    elif fault == "bridge-down":
        current[20]["br-private"]["flags"] = []
    else:
        current[20]["veth-local"] = {"ifname": "veth-local"}
    with pytest.raises((ValueError, RuntimeError)):
        plugin.perform(config, env)
    assert not state.exists()
    assert "eth0" not in current[10]
    assert not any(args[:3] == ("ip", "link", "add") for _, args in calls)


@pytest.mark.parametrize("fault", ["missing-result", "mac", "down", "mtu", "missing-peer"])
def test_check_detects_missing_or_modified_own_attachment(plugin, inputs, kernel, fault):
    config, env, _ = inputs
    output = plugin.perform(config, env)
    config["prevResult"] = output
    env["CNI_COMMAND"] = "CHECK"
    if fault == "missing-result":
        config.pop("prevResult")
    elif fault == "mac":
        config["prevResult"]["interfaces"][-1]["mac"] = "02:ff:ff:ff:ff:ff"
    elif fault == "down":
        kernel[3][10]["eth0"]["flags"] = []
    elif fault == "mtu":
        kernel[3][10]["eth0"]["mtu"] += 1
    else:
        kernel[3][20].pop("veth-local")
    with pytest.raises(ValueError):
        plugin.perform(config, env)
    assert kernel[2].exists()


def test_directory_symlink_permissions_and_double_add_rejected(plugin, inputs, kernel, tmp_path):
    config, env, _ = inputs
    directory = tmp_path / "state"
    link = tmp_path / "linked-state"
    link.symlink_to(directory, target_is_directory=True)
    with pytest.raises(ValueError):
        plugin.private_directory(link)
    directory.chmod(0o755)
    with pytest.raises(ValueError):
        plugin.private_directory(directory)
    directory.chmod(0o700)
    plugin.perform(config, env)
    with pytest.raises(ValueError, match="already attempted"):
        plugin.perform(config, env)
    assert kernel[2].exists()


def test_foreign_uid_del_and_duplicate_cni_args_rejected(plugin, inputs, kernel):
    config, env, _ = inputs
    plugin.perform(config, env)
    env["CNI_COMMAND"] = "DEL"
    env["CNI_ARGS"] = "K8S_POD_UID=" + str(uuid4())
    with pytest.raises(ValueError, match="Pod UID changed"):
        plugin.perform(config, env)
    env["CNI_ARGS"] += ";" + env["CNI_ARGS"]
    with pytest.raises(ValueError, match="duplicate"):
        plugin.perform(config, env)
    assert "eth0" in kernel[3][10]


def test_ipv6_precondition_is_not_an_optimizable_assertion(plugin, monkeypatch):
    calls = []
    monkeypatch.setattr(plugin, "execute", lambda *args: calls.append(args))
    plugin.require_ipv4_only(10)
    assert calls[0][1:4] == ("python3", "-I", "-c")
    assert "sys.exit(" in calls[0][-1]
    assert "assert " not in calls[0][-1]


@pytest.mark.parametrize("fault", ["result-ip", "kernel-ip", "extra-ip", "default-route"])
def test_check_rejects_endpoint_drift(plugin, inputs, kernel, monkeypatch, fault):
    config, env, _ = inputs
    config["prevResult"] = plugin.perform(config, env)
    env["CNI_COMMAND"] = "CHECK"
    original = plugin.execute
    if fault == "result-ip":
        config["prevResult"]["ips"][-1]["address"] = "10.10.30.3/24"
    else:

        def changed(fd, *args, **kwargs):
            value = original(fd, *args, **kwargs)
            if fd == 10 and args[:3] == ("ip", "-j", "address"):
                result = json.loads(value)
                if fault == "kernel-ip":
                    result[0]["addr_info"][0]["local"] = "10.10.30.3"
                elif fault == "extra-ip":
                    result[0]["addr_info"].append(
                        {"family": "inet6", "local": "::1", "prefixlen": 128}
                    )
                return json.dumps(result)
            if args[:3] == ("ip", "-j", "route") and fault == "default-route":
                return '[{"gateway":"10.10.30.3","dev":"eth0"}]'
            return value

        monkeypatch.setattr(plugin, "execute", changed)
    with pytest.raises(ValueError):
        plugin.perform(config, env)
    assert kernel[2].exists()


@pytest.mark.parametrize("side", [10, 20])
def test_interrupted_alias_update_cleans_only_creation_tagged_links(
    plugin, inputs, kernel, monkeypatch, side
):
    config, env, _ = inputs
    original = plugin.execute

    def interrupted(fd, *args, **kwargs):
        if fd == side and "alias" in args:
            raise RuntimeError("interrupted before alias update")
        return original(fd, *args, **kwargs)

    monkeypatch.setattr(plugin, "execute", interrupted)
    with pytest.raises(RuntimeError):
        plugin.perform(config, env)
    assert plugin.read_record(kernel[2])["indices"] is None
    assert kernel[3][20]["veth-local"]["group"]
    env["CNI_COMMAND"] = "DEL"
    assert plugin.perform(config, env) is None
    assert not kernel[2].exists()
    assert "eth0" not in kernel[3][10]


def test_partial_add_does_not_delete_untagged_link(plugin, inputs, kernel, monkeypatch):
    config, env, _ = inputs
    original = plugin.execute

    def interrupted(fd, *args, **kwargs):
        if "alias" in args:
            raise RuntimeError("interrupted")
        return original(fd, *args, **kwargs)

    monkeypatch.setattr(plugin, "execute", interrupted)
    with pytest.raises(RuntimeError):
        plugin.perform(config, env)
    kernel[3][20]["veth-local"].pop("group")
    env["CNI_COMMAND"] = "DEL"
    with pytest.raises(ValueError):
        plugin.perform(config, env)
    assert "eth0" in kernel[3][10]
