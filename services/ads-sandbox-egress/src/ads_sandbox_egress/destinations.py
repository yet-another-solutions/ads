"""One versioned destination boundary for DNS records and proxy endpoints."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from ads_sandbox_egress.policy import RequestDenied, canonical_host

Address = ipaddress.IPv4Address | ipaddress.IPv6Address
Network = ipaddress.IPv4Network | ipaddress.IPv6Network
CLASSIFIER_VERSION = "iana-special-2025-10-09/ads-v1"
# Full registry coverage, aggregated only where a parent is itself excluded.
# https://www.iana.org/assignments/iana-ipv4-special-registry/
# https://www.iana.org/assignments/iana-ipv6-special-registry/
# Retrieved 2026-09-25. Globally-reachable exceptions remain prohibited.
SPECIAL_PREFIXES = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.31.196.0/24",
    "192.52.193.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "192.175.48.0/24",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::/128",
    "::1/128",
    "::ffff:0:0/96",
    "64:ff9b::/96",
    "64:ff9b:1::/48",
    "100::/64",
    "100:0:0:1::/64",
    "2001::/23",
    "2001:db8::/32",
    "2002::/16",
    "2620:4f:8000::/48",
    "3fff::/20",
    "5f00::/16",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
)
_SPECIAL = tuple(ipaddress.ip_network(value) for value in SPECIAL_PREFIXES)
_V6_CANDIDATE = ipaddress.IPv6Network("2000::/3")


def parse_address(value: str, *, socket_peer: bool = False) -> Address:
    if not isinstance(value, str) or "%" in value:
        raise RequestDenied("malformed_address")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise RequestDenied("malformed_address") from None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        if not socket_peer:
            raise RequestDenied("mapped_dns_address")
        return address.ipv4_mapped
    return address


@dataclass(frozen=True, slots=True)
class DestinationBoundary:
    infrastructure: tuple[Network, ...]
    translations: tuple[Network, ...]
    inventory_version: str

    def __post_init__(self) -> None:
        if (
            not self.infrastructure
            or not self.inventory_version
            or len(self.inventory_version) > 128
            or len(self.infrastructure) + len(self.translations) > 4096
            or not all(
                isinstance(item, (ipaddress.IPv4Network, ipaddress.IPv6Network))
                for item in (*self.infrastructure, *self.translations)
            )
        ):
            raise ValueError("valid nonempty trusted infrastructure inventory required")

    def require_public(self, value: str, *, socket_peer: bool = False) -> Address:
        address = parse_address(value, socket_peer=socket_peer)
        for reason, prefixes in (
            ("translation", self.translations),
            ("infrastructure", self.infrastructure),
            ("special_purpose", _SPECIAL),
        ):
            if any(address.version == prefix.version and address in prefix for prefix in prefixes):
                raise RequestDenied(reason)
        if isinstance(address, ipaddress.IPv6Address) and address not in _V6_CANDIDATE:
            raise RequestDenied("unsupported_address_family_range")
        return address

    def require_peer(self, expected: Address, actual: str) -> None:
        if self.require_public(actual, socket_peer=True) != expected:
            raise RequestDenied("upstream_peer_changed")


def dns_name(value: str) -> str:
    # DNSSEC dependency lookups may legitimately address the root.
    return "." if value == "." else canonical_host(value)


@dataclass(frozen=True, slots=True)
class ResolverBoundary:
    upstreams: tuple[Address, ...]
    zones: frozenset[str]
    exact_names: frozenset[str]
    addresses: DestinationBoundary

    @classmethod
    def discover(
        cls,
        resolv_conf: str,
        namespace: str,
        addresses: DestinationBoundary,
        *,
        upstreams: tuple[str, ...] = (),
        zones: tuple[str, ...] = (),
        exact_names: tuple[str, ...] = (),
    ) -> ResolverBoundary:
        if len(resolv_conf) > 65536 or not namespace:
            raise ValueError("bounded trusted resolver configuration required")
        discovered: list[str] = []
        discovered_zones: set[str] = set()
        bases: set[str] = set()
        for line in resolv_conf.splitlines():
            fields = line.split("#", 1)[0].split(";", 1)[0].split()
            if not fields:
                continue
            if fields[0] == "nameserver":
                if len(fields) != 2:
                    raise ValueError("invalid nameserver entry")
                discovered.append(fields[1])
            elif fields[0] in ("search", "domain"):
                if len(fields) < 2 or fields[0] == "domain" and len(fields) != 2:
                    raise ValueError("invalid infrastructure suffix entry")
                for field in fields[1:]:
                    name = dns_name(field)
                    discovered_zones.add(name)
                    for prefix in ("svc.", namespace.lower() + ".svc."):
                        if name.startswith(prefix):
                            bases.add(dns_name(name[len(prefix) :]))
        if len(bases) > 1:
            raise ValueError("inconsistent cluster-domain evidence")
        effective_zones = frozenset((*discovered_zones, *bases, *(dns_name(z) for z in zones)))
        if not effective_zones or "." in effective_zones:
            raise ValueError("nonempty infrastructure inventory without root wildcard required")
        selected = tuple(dict.fromkeys(parse_address(v) for v in (upstreams or tuple(discovered))))
        if not selected or len(selected) > 16:
            raise ValueError("bounded nonempty upstream list required")
        if any(a.is_unspecified or a.is_multicast for a in selected):
            raise ValueError("invalid resolver address")
        return cls(
            selected, effective_zones, frozenset(dns_name(n) for n in exact_names), addresses
        )

    def check_name(self, value: str) -> str:
        name = dns_name(value)
        if name in self.exact_names or any(
            name == zone or name.endswith("." + zone) for zone in self.zones
        ):
            raise RequestDenied("infrastructure_name")
        reverse: str | None = None
        if name.endswith(".in-addr.arpa"):
            labels = name.removesuffix(".in-addr.arpa").split(".")
            if len(labels) == 4:
                reverse = ".".join(reversed(labels))
        elif name.endswith(".ip6.arpa"):
            labels = name.removesuffix(".ip6.arpa").split(".")
            if len(labels) == 32 and all(len(v) == 1 and v in "0123456789abcdef" for v in labels):
                digits = "".join(reversed(labels))
                reverse = ":".join(digits[i : i + 4] for i in range(0, 32, 4))
        if reverse is not None:
            self.addresses.require_public(reverse)
        return name
