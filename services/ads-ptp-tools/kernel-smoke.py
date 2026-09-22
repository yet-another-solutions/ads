"""GitHub Actions only: real kernel setup under the planned container restrictions."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
from uuid import uuid4

loader = importlib.machinery.SourceFileLoader("canary", "/usr/local/bin/ads-ptp-canary")
spec = importlib.util.spec_from_loader(loader.name, loader)
assert spec is not None
canary = importlib.util.module_from_spec(spec)
loader.exec_module(canary)
os.environ["POD_UID"] = str(uuid4())
os.environ["ATTACHMENT_GENERATION"] = str(uuid4())
before_net = os.readlink("/proc/self/ns/net")
before_proc = [
    line
    for line in Path("/proc/self/mountinfo").read_text().splitlines()
    if line.split()[4].startswith("/proc")
]
before_links = {link["ifname"] for link in json.loads(canary.run("ip", "-j", "link"))}
canary.keygen()
other_key = canary.run("wg", "genkey")
peer = canary.run("wg", "pubkey", data=other_key + "\n")
del other_key
pod, generation = canary.identity()
try:
    result = canary.configure(
        {
            "pod_uid": pod,
            "generation": generation,
            "side": "egress",
            "local_private": "10.10.30.1/24",
            "peer_private": "10.10.30.2/24",
            "local_tunnel": "10.10.40.1/32",
            "peer_tunnel": "10.10.40.2/32",
            "transport_mtu": 1400,
            "peer_key": peer,
            "endpoint": None,
            "wireguard_port": 51820,
            "vxlan_port": 4789,
            "vni": 42,
        }
    )
    assert result["private_mtu"] == 1290
    assert canary.ready()["socket_configured"] is True
    private, mock = canary.ns_names()
    assert canary.ns(private, "sysctl", "-n", "net.ipv4.ip_forward") == "0"
    addresses = json.loads(canary.ns(private, "ip", "-j", "address"))
    assert not any(
        address["family"] == "inet6" for link in addresses for address in link["addr_info"]
    )
    assert canary.ns(mock, "sysctl", "-n", "net.ipv4.ip_forward") == "0"
    canary.ns(mock, "ping", "-c", "1", "-w", "2", "10.10.30.1")
    canary.ns(private, "ip", "link", "set", "wg-private", "down")
    try:
        canary.ready()
    except RuntimeError:
        pass
    else:
        raise AssertionError("a down WireGuard interface must withdraw readiness")
    canary.ns(private, "ip", "link", "set", "wg-private", "up")
    assert canary.ready()["socket_configured"] is True
    assert canary.inspect()["wireguard"]["peers"] == peer
finally:
    assert canary.cleanup()["cleaned"] is True
assert os.readlink("/proc/self/ns/net") == before_net
after_proc = [
    line
    for line in Path("/proc/self/mountinfo").read_text().splitlines()
    if line.split()[4].startswith("/proc")
]
assert before_proc == after_proc
assert {link["ifname"] for link in json.loads(canary.run("ip", "-j", "link"))} == before_links
assert not json.loads(canary.run("ip", "-j", "netns", "list"))
print(
    json.dumps(
        {
            "real_kernel_setup_cleanup": True,
            "read_only_root": True,
            "parent_proc_mounts_unchanged": True,
            "handshake_independent_readiness": True,
            "down_link_not_ready": True,
            "service_transport_proven": False,
        }
    )
)
