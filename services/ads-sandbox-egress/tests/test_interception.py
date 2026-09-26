import ipaddress
import json
import socket
import struct
from dataclasses import replace
from types import SimpleNamespace

import pytest

from ads_sandbox_egress import interception as module
from ads_sandbox_egress.interception import KernelBoundary, Network, original_destination, rules
from ads_sandbox_egress.policy import RequestDenied


@pytest.fixture
def network():
    return Network(
        "eth1",
        "eth0",
        ipaddress.IPv4Interface("10.10.30.1/24"),
        ipaddress.IPv4Address("10.10.30.2"),
        ipaddress.IPv4Address("10.20.0.3"),
        8443,
        15001,
        15002,
        1390,
        "02:01:02:03:04:05",
    )


@pytest.mark.parametrize(
    "change",
    [
        {"private_interface": "eth1; accept"},
        {"private_interface": "eth0"},
        {"upstream_interface": "lo"},
        {"control_address": ipaddress.IPv4Address("0.0.0.0")},
        {"guest_address": ipaddress.IPv4Address("10.20.0.2")},
        {"proxy_port": 53},
        {"crl_port": True},
        {"mac": "ff:ff:ff:ff:ff:ff"},
        {"mtu": 100},
    ],
)
def test_network_requires_complete_distinct_safe_inputs(network, change):
    with pytest.raises(ValueError):
        replace(network, **change)


def test_rules_terminate_instead_of_forward(network):
    text = rules(network)
    assert text.startswith("\ncreate table inet ads_egress\n")
    assert "hook forward priority -300; policy drop" in text
    assert "masquerade" not in text and "snat" not in text and "dnat" not in text
    assert 'iifname "eth1" ip saddr 10.10.30.2 tcp redirect to :15001' in text
    assert text.index("tcp dport 15002 return") < text.index("tcp redirect to :15001")
    assert not any("forward" in line and "accept" in line for line in text.splitlines())


@pytest.mark.parametrize(
    "defect", ["none", "mac", "mtu", "down", "extra", "bridge", "address", "control", "rules"]
)
def test_boundary_checks_observed_attachment_and_exact_owned_rules(network, monkeypatch, defect):
    boundary = KernelBoundary(network)
    boundary._fence = module._fingerprint({"nftables": [{"rule": {"expr": ["drop"]}}]})
    links = [
        {"ifname": "lo"},
        {"ifname": "eth0"},
        {"ifname": "eth1", "address": network.mac, "mtu": network.mtu, "flags": ["UP"]},
    ]
    addresses = [
        {
            "ifname": "eth0",
            "addr_info": [{"family": "inet", "local": str(network.control_address)}],
        },
        {
            "ifname": "eth1",
            "addr_info": [{"family": "inet", "local": "10.10.30.1", "prefixlen": 24}],
        },
    ]
    if defect in ("mac", "mtu", "down"):
        links[2][{"mac": "address", "mtu": "mtu", "down": "flags"}[defect]] = "wrong"
    if defect == "extra":
        links.append({"ifname": "escape"})
    if defect == "bridge":
        links[2]["master"] = "br0"
    if defect == "address":
        addresses[1]["addr_info"].append({"family": "inet6", "local": "::1"})
    if defect == "control":
        addresses[0]["addr_info"] = []
    fence = {
        "nftables": [{"rule": {"expr": ["accept" if defect == "rules" else "drop"], "handle": 12}}]
    }

    def command(*args, **kwargs):
        return json.dumps(
            links
            if args == ("ip", "-j", "-d", "link")
            else addresses
            if args == ("ip", "-j", "address")
            else fence
        ).encode()

    monkeypatch.setattr(module, "command", command)
    monkeypatch.setattr(boundary, "_forwarding", lambda: None)
    if defect in ("extra", "bridge"):
        with pytest.raises(RuntimeError):
            boundary.check()
    else:
        assert boundary.check() is (defect == "none")


@pytest.mark.parametrize("defect", ["none", "peer", "local", "family", "short", "sockfamily"])
def test_original_destination_comes_only_from_kernel_socket(network, defect):
    # Explicit external kernel boundary; not a kernel REDIRECT proof.
    value = (
        struct.pack("=H", socket.AF_INET6 if defect == "family" else socket.AF_INET)
        + struct.pack("!H", 4443)
        + ipaddress.IPv4Address("1.1.1.1").packed
        + b"\0" * 8
    )
    observations = []

    def getsockopt(*args):
        observations.append(args)
        return value[:8] if defect == "short" else value

    fields = {
        "peername": ("10.10.30.8" if defect == "peer" else "10.10.30.2", 50000),
        "sockname": ("0.0.0.0" if defect == "local" else "10.10.30.1", 15001),
        "socket": SimpleNamespace(
            family=socket.AF_INET6 if defect == "sockfamily" else socket.AF_INET,
            getsockopt=getsockopt,
        ),
    }
    writer = SimpleNamespace(get_extra_info=lambda name: fields[name])
    if defect == "none":
        assert original_destination(writer, network) == (ipaddress.IPv4Address("1.1.1.1"), 4443)
        assert observations == [(socket.SOL_IP, 80, 16)]
    else:
        with pytest.raises(RequestDenied):
            original_destination(writer, network)


def test_cancelled_checks_share_one_owned_worker(network):
    import asyncio
    import threading
    from unittest.mock import AsyncMock

    from ads_sandbox_egress.interception import Interception

    started, release = threading.Event(), threading.Event()
    calls = []

    def check():
        calls.append(1)
        started.set()
        assert release.wait(2)
        return True

    async def run():
        interception = Interception(
            SimpleNamespace(network=network, check=check),
            SimpleNamespace(close=AsyncMock()),
        )
        first = asyncio.create_task(interception.check())
        try:
            async with asyncio.timeout(1):
                while not started.is_set():
                    await asyncio.sleep(0.001)
            first.cancel()
            with pytest.raises(asyncio.CancelledError):
                await first
            second = asyncio.create_task(interception.check())
            await asyncio.sleep(0)
            assert len(calls) == 1
            release.set()
            assert await second
        finally:
            release.set()
            await interception.close()
        assert interception._checking is None and calls == [1]

    asyncio.run(run())
