"""Pure per-request policy. A positive result is NOT destination authorization.

Callers must separately enforce framing, original destination, DNS membership,
TLS/HTTP identity and supported protocol mechanics before sending HTTP bytes.
The path argument is already-normalized NGINX output, never a raw-path fallback.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

import msgspec

from ads_commons.egress import ProjectEgressSnapshot, UpgradeTarget

_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)


class RequestDenied(Exception):
    """Internal reason only; protocol handlers reset, never serialize this."""


def canonical_host(value: str) -> str:
    """ASCII A-label wire names; no implicit Unicode, search or reverse DNS."""
    if not value or not value.isascii() or "%" in value:
        raise RequestDenied("invalid_host")
    value = value.lower()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    value = value.removesuffix(".")
    if len(value) > 253 or not all(_LABEL.fullmatch(label) for label in value.split(".")):
        raise RequestDenied("invalid_host")
    # Do not reinterpret malformed/ambiguous numeric IPv4 as a DNS name.
    if all(char in "0123456789." for char in value):
        raise RequestDenied("ambiguous_address")
    return value


@dataclass(frozen=True, slots=True)
class Authority:
    host: str
    port: int


def authority(value: str, default_port: int) -> Authority | None:
    """Empty authority is distinct from a missing required protocol field."""
    if value == "":
        return None
    if any(char.isspace() for char in value) or any(char in value for char in "/\\@?#"):
        raise RequestDenied("invalid_authority")
    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            raise RequestDenied("invalid_authority")
        host, suffix = value[1:end], value[end + 1 :]
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            raise RequestDenied("invalid_authority") from None
    else:
        if value.count(":") > 1:
            raise RequestDenied("unbracketed_ipv6")
        host, sep, port = value.partition(":")
        suffix = sep + port
    if suffix and (
        not suffix.startswith(":") or not suffix[1:].isascii() or not suffix[1:].isdigit()
    ):
        raise RequestDenied("invalid_port")
    port_number = int(suffix[1:]) if suffix else default_port
    if not 1 <= port_number <= 65535:
        raise RequestDenied("invalid_port")
    return Authority(canonical_host(host), port_number)


def consistent_identity(
    authorities: tuple[Authority | None, ...], tls_name: str | None
) -> tuple[str, ...]:
    """Adapters supply EVERY applicable authority, including empty values."""
    if authorities and any(item != authorities[0] for item in authorities):
        raise RequestDenied("conflicting_authorities")
    host = authorities[0].host if authorities and authorities[0] is not None else None
    tls = canonical_host(tls_name) if tls_name is not None else None
    if tls is not None and host is not None and tls != host:
        raise RequestDenied("tls_http_identity_mismatch")
    return tuple(dict.fromkeys(name for name in (tls, host) if name is not None))


def domain_matches(pattern: str, name: str) -> bool:
    if pattern == "*":
        return True
    if pattern.startswith("*."):
        return name.partition(".")[2] == pattern[2:] and "." in name
    return name == pattern


def ant_matches(pattern: bytes, path: bytes, *, insensitive: bool = False) -> bool:
    """Byte-oriented Ant subset, no regex/variables/escaping extensions.

    ** consumes whole segments; * and ? never consume a slash. ASCII lowercasing
    leaves opaque non-ASCII bytes untouched. Bounded dynamic programming avoids
    recursive/backtracking regex denial of service.
    """
    if not path.startswith(b"/") or not pattern.startswith(b"/"):
        return False
    if len(path) > 8192 or len(pattern) > 8192 or b"\0" in path:
        raise RequestDenied("path_limit")
    if insensitive:
        pattern, path = pattern.lower(), path.lower()
    patterns, parts = pattern.split(b"/"), path.split(b"/")
    work = 0

    def segment(glob: bytes, value: bytes) -> bool:
        nonlocal work
        previous = [True] + [False] * len(value)
        for char in glob:
            work += len(value) + 1
            if work > 1_000_000:
                raise RequestDenied("path_match_limit")
            current = [previous[0] and char == ord("*")] + [False] * len(value)
            for j, actual in enumerate(value, 1):
                current[j] = (
                    previous[j] or current[j - 1]
                    if char == ord("*")
                    else previous[j - 1] and char in (ord("?"), actual)
                )
            previous = current
        return previous[-1]

    reachable = {0}
    for glob in patterns:
        if glob == b"**":
            reachable = set(range(min(reachable), len(parts) + 1)) if reachable else set()
        else:
            reachable = {
                index + 1
                for index in reachable
                if index < len(parts) and segment(glob, parts[index])
            }
        if not reachable:
            return False
    return len(parts) in reachable


@dataclass(frozen=True, slots=True)
class PolicyRequest:
    names: tuple[str, ...]
    port: int
    protocol: str
    sub_protocol: str
    method: str
    normalized_path: bytes
    upgrade: UpgradeTarget | None = None


def permitted(snapshot: ProjectEgressSnapshot | None, request: PolicyRequest) -> bool:
    """Evaluate one immutable snapshot for this authorization event only."""
    if snapshot is None:
        return False
    if (
        request.protocol not in ("http", "https")
        or request.sub_protocol not in ("http/1.1", "http/2", "websocket")
        or not 1 <= request.port <= 65535
        or request.upgrade not in (None, "http/2", "websocket")
        or (
            request.method == "CONNECT"
            and not (request.sub_protocol == "http/2" and request.upgrade == "websocket")
        )
    ):
        return False
    names = tuple(canonical_host(name) for name in request.names)
    if len(set(names)) > 1:
        return False
    settings = snapshot.settings
    whitelist = settings.mode == "whitelist"
    for rule in settings.rules:
        options = rule.protocol_settings
        if (
            rule.port != request.port
            or rule.protocol != request.protocol
            or rule.sub_protocol not in ("any", request.sub_protocol)
            or options.method not in ("any", request.method)
        ):
            continue
        if options.paths and not any(
            ant_matches(
                item.pattern.encode("utf-8"),
                request.normalized_path,
                insensitive=(
                    not whitelist
                    if item.case_insensitive is msgspec.UNSET
                    else item.case_insensitive
                ),
            )
            for item in options.paths
        ):
            continue
        if request.upgrade is not None and not (
            options.upgrades == "any"
            or isinstance(options.upgrades, tuple)
            and request.upgrade in options.upgrades
        ):
            continue
        if rule.domain == "*":
            return whitelist
        if not names:
            if not whitelist:
                return False  # Otherwise-applicable named blacklist is unknown.
            continue
        matches = [domain_matches(rule.domain, name) for name in names]
        if all(matches) if whitelist else any(matches):
            return whitelist
    return not whitelist
