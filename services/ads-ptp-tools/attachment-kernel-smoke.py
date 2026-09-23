"""GitHub CI: real private CNI effects, not Kata or node attestation proof."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import subprocess
from pathlib import Path
from uuid import uuid4


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


canary = load("canary", "/usr/local/bin/ads-ptp-canary")
plugin = load("attachment", "/usr/local/bin/ads-ptp")
generation = str(uuid4())
names = ["attach-" + role + "-" + generation for role in ("vm", "private", "transport")]
created = []
root = Path("/run/attachment-test")
root.mkdir(mode=0o700)
for child in ("bindings", "state"):
    (root / child).mkdir(mode=0o700)
uid, relay = str(uuid4()), str(uuid4())
env = {
    "CNI_COMMAND": "ADD",
    "CNI_CONTAINERID": "c" * 64,
    "CNI_IFNAME": "eth0",
    "CNI_NETNS": "/run/netns/" + names[0],
    "CNI_ARGS": "K8S_POD_UID=" + uid,
}
config = {
    "cniVersion": "1.0.0",
    "type": "ads-ptp",
    "name": "ads-private",
    "bindingDir": str(root / "bindings"),
    "stateDir": str(root / "state"),
}
try:
    for name in names:
        canary.run("ip", "netns", "add", name)
        created.append(name)
        canary.configure_namespace(name)
        canary.ns(name, "ip", "link", "set", "lo", "up")
    private = names[1]
    record = {
        "pod_uid": uid,
        "generation": generation,
        "sandbox_id": str(uuid4()),
        "role": "guest",
        "ifname": "eth0",
        "network": "ads-private",
        "relay_pod_uid": relay,
        "relay_runtime_id": "d" * 64,
        "mtu": 1340,
        "address": "10.10.30.2/24",
        "gateway": "10.10.30.1",
        "private": {
            "path": "/run/netns/" + private,
            "identity": canary.namespace_identity(private),
        },
        "transport": {
            "path": "/run/netns/" + names[2],
            "identity": canary.namespace_identity(names[2]),
        },
    }
    canary.ns(
        private,
        "ip",
        "link",
        "add",
        "br-private",
        "mtu",
        "1340",
        "type",
        "bridge",
    )
    canary.ns(private, "ip", "link", "set", "br-private", "alias", plugin.bridge_identity(record))
    canary.ns(private, "ip", "link", "set", "br-private", "up")
    canary.ns(private, "ip", "link", "add", "wg-private", "type", "wireguard")
    canary.ns(private, "ip", "address", "add", "198.18.0.1/32", "dev", "wg-private")
    canary.ns(private, "ip", "link", "set", "wg-private", "up")
    canary.ns(
        private,
        "ip",
        "link",
        "add",
        "vxlan-private",
        "mtu",
        "1340",
        "type",
        "vxlan",
        "id",
        "42",
        "dev",
        "wg-private",
        "local",
        "198.18.0.1",
        "remote",
        "198.18.0.2",
        "dstport",
        "4789",
        "nolearning",
    )
    canary.ns(private, "ip", "link", "set", "vxlan-private", "master", "br-private")
    canary.ns(private, "ip", "link", "set", "vxlan-private", "up")
    print("private bridge preflight: " + canary.ns(private, "ip", "-d", "-j", "link"), flush=True)
    plugin.save_record(root / "bindings" / (uid + ".json"), record)
    output = plugin.perform(config, env)
    assert output["ips"] == [{"interface": 0, "address": "10.10.30.2/24", "gateway": "10.10.30.1"}]
    assert output["routes"] == [{"dst": "0.0.0.0/0", "gw": "10.10.30.1"}]
    assert output["dns"] == {"nameservers": ["10.10.30.1"]}
    assert len(output["interfaces"]) == 1
    routes = json.loads(canary.ns(names[0], "ip", "-j", "route", "show", "default"))
    assert len(routes) == 1 and routes[0]["gateway"] == "10.10.30.1"
    assert routes[0]["dev"] == "eth0"
    addresses = json.loads(canary.ns(names[0], "ip", "-j", "address", "show", "dev", "eth0"))
    assert len(addresses) == 1 and len(addresses[0]["addr_info"]) == 1
    assert addresses[0]["addr_info"][0]["local"] == "10.10.30.2"
    config["prevResult"] = output
    env["CNI_COMMAND"] = "CHECK"
    assert plugin.perform(config, env) is None
    # A caller cannot override the trusted relay binding or delete a replacement.
    marker = plugin.alias(plugin.request(config, env), record)
    canary.ns(private, "ip", "link", "set", "veth-local", "alias", "replacement")
    env["CNI_COMMAND"] = "DEL"
    try:
        plugin.perform(config, env)
    except ValueError:
        pass
    else:
        raise AssertionError("replacement deletion accepted")
    assert json.loads(canary.ns(names[0], "ip", "-j", "link", "show", "eth0"))
    canary.ns(private, "ip", "link", "set", "veth-local", "alias", marker)
    assert plugin.perform(config, env) is None
    assert plugin.perform(config, env) is None
    assert json.loads(canary.ns(names[0], "ip", "-j", "link"))[0]["ifname"] == "lo"
    assert len(json.loads(canary.ns(names[0], "ip", "-j", "link"))) == 1
    # Linux ignores creation-time aliases; a crash before the explicit update
    # must retain the creation group and still permit fenced DEL.
    env["CNI_COMMAND"] = "ADD"
    config.pop("prevResult")
    execute = plugin.execute

    def interrupted(fd, *args, **kwargs):
        if "alias" in args:
            raise RuntimeError("injected interruption before alias update")
        return execute(fd, *args, **kwargs)

    plugin.execute = interrupted
    try:
        plugin.perform(config, env)
    except RuntimeError as error:
        assert str(error) == "injected interruption before alias update"
    else:
        raise AssertionError("injected failure was not reached")
    finally:
        plugin.execute = execute
    env["CNI_COMMAND"] = "DEL"
    assert plugin.perform(config, env) is None
    assert len(json.loads(canary.ns(names[0], "ip", "-j", "link"))) == 1
    # Missing runtime namespace after successful ADD remains an idempotent DEL.
    env["CNI_COMMAND"] = "ADD"
    output = plugin.perform(config, env)
    # Use the packaged node-root command against the same CNI state directory.
    # The fence deliberately does not stop or delete the existing interface.
    request = {
        "stateDir": config["stateDir"],
        **{key: record[key] for key in ("network", "sandbox_id", "generation")},
    }
    fenced = subprocess.run(
        ["ads-ptp-retire"],
        input=json.dumps(request),
        text=True,
        capture_output=True,
        check=True,
        timeout=5,
    )
    verdict = json.loads(fenced.stdout)
    assert verdict["attachment_admission_fenced"] and not verdict["runtime_release_proven"]
    assert json.loads(canary.ns(names[0], "ip", "-j", "link", "show", "eth0"))
    config["prevResult"] = output
    for command in ("ADD", "CHECK"):
        env["CNI_COMMAND"] = command
        try:
            plugin.perform(config, env)
        except ValueError as error:
            assert str(error) == "attachment generation retired"
        else:
            raise AssertionError("retired admission succeeded")
    canary.run("ip", "netns", "delete", names[0])
    created.remove(names[0])
    env.update(CNI_COMMAND="DEL", CNI_NETNS="", CNI_ARGS="")
    assert plugin.perform(config, env) is None
    assert plugin.perform(config, env) is None
    # DEL removes the attachment journal, never its durable generation fence.
    assert list((root / "state").glob("*.json")) == [
        root / "state" / ("retired-" + generation + ".json")
    ]
finally:
    for name in reversed(created):
        canary.run("ip", "netns", "delete", name)
assert not json.loads(canary.run("ip", "-j", "netns", "list"))
print(
    json.dumps(
        {
            "real_private_cni_add_check_del": True,
            "static_private_endpoint_no_cluster_ipam": True,
            "replacement_cleanup_refused": True,
            "interrupted_alias_update_cleanup": True,
            "missing_namespace_del_idempotent": True,
            "persistent_generation_admission_fence": True,
            "fence_is_not_runtime_release": True,
            "node_attestation_and_kata_handoff_proven": False,
        }
    )
)
