"""Immutable manager inputs. Parse and validate completely before runtime effects."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

import dns.dnssec
import dns.name
import dns.rrset
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

from ads_commons.egress_trust import public_certificates
from ads_sandbox_egress.configuration import PairIdentity
from ads_sandbox_egress.custody import Devices
from ads_sandbox_egress.destinations import DestinationBoundary, ResolverBoundary
from ads_sandbox_egress.identity_store import StateIdentity
from ads_sandbox_egress.interception import Network
from ads_sandbox_egress.policy import canonical_host

PREFIX = "ADS_SANDBOX_EGRESS_"


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate trusted configuration key")
        result[name] = value
    return result


def https_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or any(ord(char) <= 32 for char in value)
        or len(value) > 2048
    ):
        raise ValueError("credential-free trusted HTTPS endpoint required")
    _ = parsed.port
    return value


@dataclass(frozen=True, slots=True)
class Enforcement:
    destinations: DestinationBoundary
    resolver: ResolverBoundary
    anchors: dict[dns.name.Name, dns.rrset.RRset]
    ech_public_name: str


def enforcement(value: str, *, namespace: str, resolver: str, resolv_conf: str) -> Enforcement:
    if not 1 <= len(value) <= 65536:
        raise ValueError("bounded trusted enforcement configuration required")
    raw = json.loads(value, object_pairs_hook=unique_object)
    if (
        not isinstance(raw, dict)
        or set(raw)
        != {
            "format",
            "infrastructure",
            "translations",
            "inventory_version",
            "zones",
            "exact_names",
            "anchors",
            "ech_public_name",
        }
        or type(raw["format"]) is not int
        or raw["format"] != 1
    ):
        raise ValueError("complete versioned enforcement configuration required")
    for name in ("infrastructure", "translations", "zones", "exact_names"):
        if (
            not isinstance(raw[name], list)
            or len(raw[name]) > 4096
            or any(not isinstance(item, str) or not 1 <= len(item) <= 253 for item in raw[name])
        ):
            raise ValueError("bounded enforcement lists required")
    if not isinstance(raw["inventory_version"], str):
        raise ValueError("explicit inventory version required")
    boundary = DestinationBoundary(
        tuple(ipaddress.ip_network(item, strict=True) for item in raw["infrastructure"]),
        tuple(ipaddress.ip_network(item, strict=True) for item in raw["translations"]),
        raw["inventory_version"],
    )
    rb = ResolverBoundary.discover(
        resolv_conf,
        namespace,
        boundary,
        upstreams=(resolver,),
        zones=tuple(raw["zones"]),
        exact_names=tuple(raw["exact_names"]),
    )
    anchors = {}
    if not isinstance(raw["anchors"], list) or not 1 <= len(raw["anchors"]) <= 64:
        raise ValueError("explicit upstream DNSSEC anchors required")
    for entry in raw["anchors"]:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"name", "keys"}
            or not isinstance(entry["name"], str)
            or not entry["name"].endswith(".")
            or not isinstance(entry["keys"], list)
            or not 1 <= len(entry["keys"]) <= 16
            or any(not isinstance(key, str) or len(key) > 8192 for key in entry["keys"])
        ):
            raise ValueError("bounded complete upstream anchor required")
        owner = dns.name.from_text(entry["name"]).canonicalize()
        if owner in anchors:
            raise ValueError("duplicate upstream anchor")
        records = dns.rrset.from_text_list(owner, 3600, "IN", "DNSKEY", entry["keys"])
        if len(records) != len(entry["keys"]) or any(
            key.protocol != 3
            or key.flags & 256 == 0
            or key.flags & 128
            or not dns.dnssec.default_policy.ok_to_validate(key)
            for key in records
        ):
            raise ValueError("ineligible upstream DNSSEC anchor")
        anchors[owner] = records
    if dns.name.root not in anchors:
        raise ValueError("independent upstream root anchor required")
    if not isinstance(raw["ech_public_name"], str):
        raise ValueError("explicit ECH public name required")
    public_name = canonical_host(raw["ech_public_name"])
    try:
        ipaddress.ip_address(public_name)
    except ValueError:
        pass
    else:
        raise ValueError("ECH public name must be a DNS name")
    rb.check_name(public_name)
    return Enforcement(boundary, rb, anchors, public_name)


@dataclass(frozen=True, slots=True)
class Settings:
    pair: PairIdentity
    devices: Devices
    network: Network
    enforcement: Enforcement
    pod_uid: UUID
    wrapping_key: bytes = field(repr=False)
    tls_certificate: bytes = field(repr=False)
    tls_key: bytes = field(repr=False)
    issuer: str
    discovery: str
    ca_bundle: bytes = field(repr=False)


def load_settings(
    environment: Mapping[str, str] | None = None, *, resolv_conf: str | None = None
) -> Settings:
    env = os.environ if environment is None else environment

    def required(name: str, maximum: int = 65536) -> str:
        value = env.get(PREFIX + name, "")
        if not isinstance(value, str) or not 1 <= len(value) <= maximum:
            raise ValueError("required bounded manager input: " + name)
        return value

    def identifier(name: str) -> UUID:
        value = required(name, 36)
        parsed = UUID(value)
        if str(parsed) != value:
            raise ValueError("canonical UUID required: " + name)
        return parsed

    def integer(name: str) -> int:
        value = required(name, 20)
        if not re.fullmatch(r"[1-9][0-9]*", value):
            raise ValueError("positive canonical integer required: " + name)
        return int(value)

    try:
        identity = StateIdentity(
            identifier("SESSION_ID"),
            identifier("SANDBOX_ID"),
            identifier("PROJECT_ID"),
            identifier("STATE_ID"),
            str(identifier("STATE_PVC_UID")),
            str(identifier("WRAPPING_CUSTODY_UID")),
            required("WRAPPING_KEY_SHA256", 64),
        )
        generation = identifier("ATTACHMENT_GENERATION")
        devices = Devices(
            Path(required("STATE_DEVICE")),
            Path(required("CA_PUBLIC_DEVICE")),
            Path(required("CA_PRIVATE_DEVICE")),
            integer("STATE_BYTES"),
            identity,
            identifier("CA_ATTEMPT"),
            generation,
            identifier("CREATOR_GENERATION"),
        )
        key = base64.b64decode(required("WRAPPING_KEY_B64", 44), validate=True)
        if len(key) != 32 or hashlib.sha256(key).hexdigest() != identity.wrapping_fingerprint:
            raise ValueError("wrapping custody mismatch")
        if required("KEYCLOAK_AUDIENCE", 64) != "ads-sandbox-egress":
            raise ValueError("unexpected control audience")
        namespace = required("NAMESPACE", 63)
        if not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?", namespace):
            raise ValueError("canonical namespace required")
        address = ipaddress.IPv4Address(required("BIND_HOST", 15))
        mac = "02:" + ":".join(
            f"{byte:02x}" for byte in hashlib.sha256(f"{generation}/egress".encode()).digest()[:5]
        )
        network = Network(
            required("PRIVATE_INTERFACE", 15),
            required("UPSTREAM_INTERFACE", 15),
            ipaddress.IPv4Interface("10.10.30.1/24"),
            ipaddress.IPv4Address("10.10.30.2"),
            address,
            integer("PORT"),
            15001,
            15002,
            integer("PRIVATE_MTU"),
            mac,
        )
        if (network.private_interface, network.upstream_interface) != ("eth1", "eth0"):
            raise ValueError("attachment role contract differs")
        upstream = ipaddress.IPv4Address(required("RESOLVER_IPV4", 15))
        if upstream.is_unspecified or upstream.is_multicast or upstream.is_loopback:
            raise ValueError("invalid trusted resolver")
        config = enforcement(
            required("ENFORCEMENT"),
            namespace=namespace,
            resolver=str(upstream),
            resolv_conf=Path("/etc/resolv.conf").read_text()
            if resolv_conf is None
            else resolv_conf,
        )
        issuer, discovery = (
            https_url(required("KEYCLOAK_ISSUER")),
            https_url(required("KEYCLOAK_WELL_KNOWN_URL")),
        )
        cert, private = required("TLS_CERT_PEM").encode(), required("TLS_KEY_PEM").encode()
        chain = public_certificates(cert)
        if len(chain) > 16:
            raise ValueError("control certificate chain limit")
        secret = serialization.load_pem_private_key(private, password=None)
        leaf = chain[0]
        spki = serialization.PublicFormat.SubjectPublicKeyInfo
        if leaf.public_key().public_bytes(serialization.Encoding.DER, spki) != (
            secret.public_key().public_bytes(serialization.Encoding.DER, spki)
        ):
            raise ValueError("control TLS key mismatch")
        if not leaf.not_valid_before_utc <= datetime.now(UTC) < leaf.not_valid_after_utc:
            raise ValueError("control certificate not current")
        try:
            if (
                ExtendedKeyUsageOID.SERVER_AUTH
                not in leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            ):
                raise ValueError("control certificate is not server-auth")
        except x509.ExtensionNotFound:
            pass
        ca = env.get(PREFIX + "TLS_CA_PEM", "").encode()
        if len(ca) > 1048576:
            raise ValueError("control CA bundle limit")
        public_certificates(ca, optional=True)
        return Settings(
            PairIdentity(
                identity.project_id, identity.sandbox_id, identifier("IPC_SERVICE_SUBJECT")
            ),
            devices,
            network,
            config,
            identifier("POD_UID"),
            key,
            cert,
            private,
            issuer,
            discovery,
            ca,
        )
    except Exception:
        # Never echo values or parser exceptions that might contain credentials.
        raise ValueError("invalid egress manager configuration") from None
