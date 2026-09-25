"""Request identity, membership, normalization and atomic policy authorization.

Connection inputs come from interception/TLS ownership, never request headers.
Normalization changes only the matching path. The immutable original request
is retained for wire serialization; DNS results never choose a new endpoint.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Literal

import h11

from ads_commons.egress import UpgradeTarget
from ads_sandbox_egress.configuration import PolicyStore
from ads_sandbox_egress.destinations import Address
from ads_sandbox_egress.framing import Headers, forwarding_headers, validate_headers
from ads_sandbox_egress.membership import ConnectionMembership
from ads_sandbox_egress.normalization import Normalizer
from ads_sandbox_egress.policy import (
    Authority,
    PolicyRequest,
    RequestDenied,
    authority,
    canonical_host,
    consistent_identity,
    permitted,
)

_TOKEN = re.compile(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_ABSOLUTE = re.compile(rb"(https?)://([^/?#]*)([^#]*)")


@dataclass(frozen=True, slots=True)
class ConnectionTarget:
    address: Address
    port: int
    secure: bool
    tls_name: str | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.address, (ipaddress.IPv4Address, ipaddress.IPv6Address))
            or type(self.port) is not int
            or not 1 <= self.port <= 65535
            or type(self.secure) is not bool
            or self.tls_name is not None
            and (not self.secure or canonical_host(self.tls_name) != self.tls_name)
        ):
            raise ValueError("immutable original destination and TLS identity required")

    @property
    def protocol(self) -> str:
        return "https" if self.secure else "http"

    @property
    def default_port(self) -> int:
        return 443 if self.secure else 80


def _authority(value: bytes, target: ConnectionTarget) -> Authority | None:
    try:
        return authority(value.decode("ascii"), target.default_port)
    except UnicodeError:
        raise RequestDenied("non_ascii_authority") from None


@dataclass(frozen=True, slots=True)
class RequestHead:
    method: bytes
    target: bytes
    headers: Headers
    authorities: tuple[Authority | None, ...]
    sub_protocol: Literal["http/1.1", "http/2"]
    upgrade: UpgradeTarget | None = None

    @classmethod
    def http1(cls, request: h11.Request, connection: ConnectionTarget) -> RequestHead:
        headers = validate_headers(tuple(request.headers))
        hosts = [value for name, value in headers if name == b"host"]
        if (
            request.http_version != b"1.1"
            or len(hosts) != 1
            or not _TOKEN.fullmatch(request.method)
        ):
            raise RequestDenied("http1_request_profile")
        authorities = [_authority(hosts[0], connection)]
        target = request.target
        if not target or len(target) > 8192 or any(char <= 32 or char == 127 for char in target):
            raise RequestDenied("invalid_request_target")
        if request.method == b"CONNECT":
            raise RequestDenied("generic_connect")
        if not target.startswith(b"/"):
            absolute = _ABSOLUTE.fullmatch(target)
            if absolute is None or absolute[1].decode("ascii") != connection.protocol:
                raise RequestDenied("unsupported_request_target")
            authorities.append(_authority(absolute[2], connection))
        elif b"#" in target:
            raise RequestDenied("fragment_in_request_target")
        # Validate dangerous Connection nominations before invoking any helper.
        forwarding_headers(headers)
        tokens: set[bytes] = set()
        for name, value in headers:
            if name == b"connection":
                tokens.update(item.strip().lower() for item in value.split(b","))
        upgrades = [value.lower() for name, value in headers if name == b"upgrade"]
        settings = [value for name, value in headers if name == b"http2-settings"]
        upgrade: UpgradeTarget | None = None
        if upgrades or b"upgrade" in tokens:
            if len(upgrades) != 1 or b"upgrade" not in tokens:
                raise RequestDenied("invalid_upgrade")
            if upgrades[0] == b"websocket" and not settings:
                upgrade = "websocket"
            elif (
                upgrades[0] == b"h2c"
                and len(settings) == 1
                and b"http2-settings" in tokens
                and not connection.secure
            ):
                upgrade = "http/2"
            else:
                raise RequestDenied("unsupported_upgrade")
        elif settings:
            raise RequestDenied("unexpected_upgrade_settings")
        return cls(request.method, target, headers, tuple(authorities), "http/1.1", upgrade)

    @classmethod
    def http2(cls, values: Headers, connection: ConnectionTarget) -> RequestHead:
        # HTTP2Connection already performs the complete message/profile gate;
        # repeat security-relevant identities at this service boundary.
        headers = validate_headers(values, h2=True)
        pseudo = {name: value for name, value in headers if name.startswith(b":")}
        if (
            not {b":method", b":scheme", b":path"} <= pseudo.keys()
            or set(pseudo) - {b":method", b":scheme", b":path", b":authority", b":protocol"}
            or not _TOKEN.fullmatch(pseudo[b":method"])
            or pseudo[b":scheme"] != connection.protocol.encode("ascii")
            or not pseudo[b":path"].startswith(b"/")
            or len(pseudo[b":path"]) > 8192
            or b"#" in pseudo[b":path"]
            or any(char <= 32 or char == 127 for char in pseudo[b":path"])
            or sum(name == b"host" for name, _ in headers) > 1
        ):
            raise RequestDenied("http2_request_identity")
        upgrade: UpgradeTarget | None = None
        if pseudo[b":method"] == b"CONNECT":
            if pseudo.get(b":protocol") != b"websocket" or not pseudo.get(b":authority"):
                raise RequestDenied("generic_connect")
            upgrade = "websocket"
        elif b":protocol" in pseudo:
            raise RequestDenied("unexpected_protocol")
        authorities = tuple(
            _authority(value, connection)
            for name, value in headers
            if name in (b":authority", b"host")
        )
        return cls(pseudo[b":method"], pseudo[b":path"], headers, authorities, "http/2", upgrade)

    def normalization_headers(self) -> Headers:
        if self.sub_protocol == "http/1.1":
            return self.headers
        regular = tuple((name, value) for name, value in self.headers if not name.startswith(b":"))
        if not any(name == b"host" for name, _ in regular):
            value = next((value for name, value in self.headers if name == b":authority"), b"")
            regular = ((b"host", value),) + regular
        return regular

    @property
    def normalization_method(self) -> bytes:
        # Explicitly approved helper-only adapter. CONNECT /path cannot reach
        # this NGINX build's URI handler. Only the private no-body envelope uses
        # GET; immutable head, policy method and upstream wire stay CONNECT.
        if (
            self.sub_protocol == "http/2"
            and self.upgrade == "websocket"
            and self.method == b"CONNECT"
        ):
            return b"GET"
        return self.method


@dataclass(frozen=True, slots=True)
class AuthorizedRequest:
    head: RequestHead
    policy_revision: int
    normalized_path: bytes


class RequestAuthorizer:
    def __init__(
        self,
        connection: ConnectionTarget,
        policies: PolicyStore,
        membership: ConnectionMembership,
        normalizer: Normalizer,
    ) -> None:
        self.connection, self.policies = connection, policies
        self.membership, self.normalizer = membership, normalizer

    async def authorize(self, head: RequestHead) -> AuthorizedRequest:
        target = self.connection
        self.membership.boundary.require_public(str(target.address))
        names = consistent_identity(head.authorities, target.tls_name)
        selected = head.authorities[0] if head.authorities else None
        authority_port = selected.port if selected is not None else target.default_port
        membership_name: str | None = None
        if names:
            name = names[0]
            try:
                literal = ipaddress.ip_address(name)
            except ValueError:
                membership_name = name
            else:
                if literal != target.address or authority_port != target.port:
                    raise RequestDenied("literal_destination_mismatch")
        elif authority_port != target.port:
            raise RequestDenied("unnamed_destination_port")
        normalized = await self.normalizer.normalize(
            head.normalization_method, head.target, head.normalization_headers()
        )
        if membership_name is not None:
            # Fresh DNS evidence is acquired AFTER the potentially slow helper,
            # immediately before the final no-await authorization decision.
            await self.membership.require(
                membership_name, target.address, target.port, authority_port
            )
        # No await between capturing this current revision and the decision.
        # A still-pending DNS/helper operation is NOT an authorized active flow.
        snapshot = self.policies.capture()
        if not self.policies.accepting or not permitted(
            snapshot,
            PolicyRequest(
                names,
                target.port,
                target.protocol,
                head.sub_protocol,
                head.method.decode("ascii"),
                normalized,
                head.upgrade,
            ),
        ):
            raise RequestDenied("request_policy")
        assert snapshot is not None
        return AuthorizedRequest(head, snapshot.revision, normalized)
