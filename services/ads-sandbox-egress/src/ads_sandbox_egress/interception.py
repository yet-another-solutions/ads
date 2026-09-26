"""IPv4 guest-local REDIRECT admission, never private-to-upstream forwarding.

The input/output/forward fence precedes listener creation. Shutdown leaves the
fence in place; closing a listener cannot expose a routing fallback. The sole
NAT operation terminates private traffic locally and preserves SO_ORIGINAL_DST.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import re
import socket
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ads_sandbox_egress.connections import Connections
from ads_sandbox_egress.policy import RequestDenied
from ads_sandbox_egress.streams import OwnedStream

_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"}


@dataclass(frozen=True, slots=True)
class Network:
    private_interface: str
    upstream_interface: str
    private_address: ipaddress.IPv4Interface
    guest_address: ipaddress.IPv4Address
    control_address: ipaddress.IPv4Address
    control_port: int
    proxy_port: int
    crl_port: int
    mtu: int
    mac: str

    def __post_init__(self) -> None:
        if (
            not all(
                re.fullmatch(r"[a-zA-Z0-9_-]{1,15}", value)
                for value in (self.private_interface, self.upstream_interface)
            )
            or self.private_interface in ("lo", self.upstream_interface)
            or self.upstream_interface == "lo"
            or not isinstance(self.private_address, ipaddress.IPv4Interface)
            or not isinstance(self.guest_address, ipaddress.IPv4Address)
            or not isinstance(self.control_address, ipaddress.IPv4Address)
            or self.guest_address not in self.private_address.network
            or self.guest_address == self.private_address.ip
            or self.control_address in self.private_address.network
            or self.control_address.is_unspecified
            or self.control_address.is_multicast
            or self.control_address.is_loopback
            or type(self.mtu) is not int
            or not 576 <= self.mtu <= 65425
            or not re.fullmatch(r"02(?::[0-9a-f]{2}){5}", self.mac)
            or not all(
                type(port) is int and 1 <= port <= 65535
                for port in (self.control_port, self.proxy_port, self.crl_port)
            )
            or len({53, self.control_port, self.proxy_port, self.crl_port}) != 4
        ):
            raise ValueError("complete distinct trusted interception inputs required")


def rules(network: Network) -> str:
    """No untrusted bytes are interpolated; Network validates every token."""
    private, upstream = network.private_interface, network.upstream_interface
    guest, local = network.guest_address, network.private_address.ip
    incoming = f'add rule inet ads_egress input iifname "{private}" ip saddr {guest}'
    outgoing = f'add rule inet ads_egress output oifname "{private}" ip daddr {guest}'
    terminate = f'add rule inet ads_egress terminate iifname "{private}" ip saddr {guest}'
    control = f'add rule inet ads_egress input iifname "{upstream}"'
    return f"""
create table inet ads_egress
add chain inet ads_egress forward {{ type filter hook forward priority -300; policy drop; }}
add chain inet ads_egress input {{ type filter hook input priority -300; policy drop; }}
add chain inet ads_egress output {{ type filter hook output priority 0; policy drop; }}
add chain inet ads_egress terminate {{ type nat hook prerouting priority -100; policy accept; }}
add rule inet ads_egress input iifname "lo" accept
add rule inet ads_egress input iifname "{upstream}" ct state established,related accept
{control} ip daddr {network.control_address} tcp dport {network.control_port} accept
{incoming} ip daddr {local} udp dport 53 accept
{incoming} ip daddr {local} tcp dport {{ 53, {network.proxy_port}, {network.crl_port} }} accept
add rule inet ads_egress output oifname "lo" accept
add rule inet ads_egress output oifname "{upstream}" accept
{outgoing} ct state established,related accept
{terminate} ip daddr {local} tcp dport {network.crl_port} return
{terminate} udp dport 53 redirect to :53
{terminate} tcp dport 53 redirect to :53
{terminate} tcp redirect to :{network.proxy_port}
"""


def command(*arguments: str, input_bytes: bytes | None = None) -> bytes:
    result = subprocess.run(
        arguments, input=input_bytes, capture_output=True, timeout=2, env=_ENV, check=False
    )
    if result.returncode or len(result.stdout) > 1048576 or len(result.stderr) > 65536:
        raise RuntimeError("bounded guest network operation failed")
    return result.stdout


def _fingerprint(value: Any) -> str:
    """Ignore only volatile kernel rule handles and packet/byte counters."""

    def canonical(item: Any) -> Any:
        if isinstance(item, dict):
            return {
                key: canonical(child)
                for key, child in item.items()
                if key not in ("handle", "metainfo")
                and not (key in ("packets", "bytes") and isinstance(child, int))
            }
        if isinstance(item, list):
            return [
                canonical(child)
                for child in item
                if not (isinstance(child, dict) and set(child) == {"metainfo"})
            ]
        return item

    return hashlib.sha256(json.dumps(canonical(value), sort_keys=True).encode()).hexdigest()


class KernelBoundary:
    def __init__(self, network: Network) -> None:
        self.network = network
        self._fence: str | None = None

    def _links(self) -> dict[str, Any]:
        values = json.loads(command("ip", "-j", "-d", "link"))
        if not isinstance(values, list):
            raise RuntimeError("invalid link inventory")
        links = {value["ifname"]: value for value in values}
        if len(links) != len(values) or set(links) != {
            "lo",
            self.network.private_interface,
            self.network.upstream_interface,
        }:
            raise RuntimeError("unexpected guest interface inventory")
        if any("master" in value for value in links.values()):
            raise RuntimeError("guest must not bridge interfaces")
        return links

    def _forwarding(self) -> None:
        if Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() != "0":
            raise RuntimeError("guest IP forwarding is enabled")
        if Path("/proc/sys/net/ipv6/conf/all/forwarding").exists() and (
            Path("/proc/sys/net/ipv6/conf/all/forwarding").read_text().strip() != "0"
        ):
            raise RuntimeError("guest IPv6 forwarding is enabled")

    def establish(self) -> None:
        if self._fence is not None:
            raise RuntimeError("network boundary already initialized")
        self._forwarding()
        links = self._links()
        private = links[self.network.private_interface]
        if (
            private.get("address") != self.network.mac
            or private.get("mtu") != self.network.mtu
            or "UP" not in private.get("flags", ())
        ):
            raise RuntimeError("private attachment MAC differs")
        # create-table atomically refuses an existing/foreign table. Never
        # flush another owner's rules or take its observed state as our proof.
        command("nft", "-f", "-", input_bytes=rules(self.network).encode())
        self._fence = _fingerprint(
            json.loads(command("nft", "-j", "list", "table", "inet", "ads_egress"))
        )
        if Path("/proc/sys/net/ipv6").exists():
            command(
                "sysctl",
                "-q",
                "-w",
                "net.ipv6.conf.all.disable_ipv6=1",
                "net.ipv6.conf.default.disable_ipv6=1",
            )
        # The existing attachment owns address/MTU/MAC installation. Consume
        # its exact contract instead of repairing a mismatched attachment.
        if not self.check():
            raise RuntimeError("guest boundary verification failed")

    def check(self) -> bool:
        self._forwarding()
        links = self._links()
        private = links[self.network.private_interface]
        if (
            self._fence is None
            or private.get("address") != self.network.mac
            or private.get("mtu") != self.network.mtu
            or "UP" not in private.get("flags", ())
        ):
            return False
        addresses = json.loads(command("ip", "-j", "address"))
        by_name = {value["ifname"]: value["addr_info"] for value in addresses}
        own = by_name.get(self.network.private_interface)
        if (
            not isinstance(own, list)
            or len(own) != 1
            or (own[0].get("family"), own[0].get("local"), own[0].get("prefixlen"))
            != (
                "inet",
                str(self.network.private_address.ip),
                self.network.private_address.network.prefixlen,
            )
        ):
            return False
        if not any(
            value.get("family") == "inet"
            and value.get("local") == str(self.network.control_address)
            for value in by_name.get(self.network.upstream_interface, ())
        ):
            return False
        return self._fence == _fingerprint(
            json.loads(command("nft", "-j", "list", "table", "inet", "ads_egress"))
        )


def original_destination(
    writer: asyncio.StreamWriter, network: Network
) -> tuple[ipaddress.IPv4Address, int]:
    peer, local = writer.get_extra_info("peername"), writer.get_extra_info("sockname")
    if (
        not peer
        or not local
        or peer[0] != str(network.guest_address)
        or local[:2] != (str(network.private_address.ip), network.proxy_port)
    ):
        raise RequestDenied("unadmitted_intercept_socket")
    sock = writer.get_extra_info("socket")
    if sock is None or sock.family != socket.AF_INET:
        raise RequestDenied("invalid_intercept_socket")
    value = sock.getsockopt(socket.SOL_IP, 80, 16)  # Linux SO_ORIGINAL_DST
    if len(value) != 16 or struct.unpack_from("=H", value)[0] != socket.AF_INET:
        raise RequestDenied("missing_original_destination")
    return ipaddress.IPv4Address(value[4:8]), struct.unpack_from("!H", value, 2)[0]


class Interception:
    def __init__(self, boundary: KernelBoundary, connections: Connections) -> None:
        self.boundary, self.connections = boundary, connections
        self.listener: asyncio.Server | None = None
        self._checking: asyncio.Task[bool] | None = None

    async def check(self) -> bool:
        # Cancellation of a caller does not cancel a running blocking operation.
        # Reuse the single owned worker until completion instead of spawning an
        # unbounded thread per timed-out ping. Retrieve every result/exception.
        if self._checking is None:
            self._checking = asyncio.create_task(asyncio.to_thread(self.boundary.check))
        task = self._checking
        try:
            return await asyncio.shield(task)
        finally:
            if task.done() and self._checking is task:
                self._checking = None

    def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            address, port = original_destination(writer, self.boundary.network)
            self.connections.accept(reader, writer, address, port)
        except Exception:
            OwnedStream.tcp(reader, writer).abort()

    async def start(self) -> None:
        if self.listener is not None or not await self.check():
            raise RuntimeError("verified guest boundary required before accepting")
        network = self.boundary.network
        self.listener = await asyncio.start_server(
            self._accept,
            str(network.private_address.ip),
            network.proxy_port,
            family=socket.AF_INET,
            limit=65536,
            backlog=128,
        )

    async def close(self) -> None:
        if self.listener is not None:
            self.listener.close()
            await self.listener.wait_closed()
            self.listener = None
        await self.connections.close()
        if self._checking is not None:
            try:
                await asyncio.shield(self._checking)
            finally:
                self._checking = None
        # Deliberately retain the DROP fence and local termination rules.
