"""Trusted paired runtime construction, never a caller-supplied Pod manifest."""

from __future__ import annotations

import base64
import re
from copy import deepcopy
from dataclasses import dataclass
from ipaddress import IPv4Address
from uuid import UUID

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_objects import (
    RELAY_HEALTH_PORT,
    WIREGUARD_PORT,
    PairBinding,
    compute_identity,
    pair_name,
    placement,
)
from ads_sandbox_manager.session_objects import guest_deployment


@dataclass(frozen=True, slots=True)
class PrivateGuestRuntime:
    """Platform inputs matching the installed, verified node CNI/attestor."""

    runtime_class: str
    transport_mtu: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.runtime_class, str)
            or len(self.runtime_class) > 63
            or not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?", self.runtime_class)
        ):
            raise ValueError("private guest requires an explicit DNS-label RuntimeClass")
        if type(self.transport_mtu) is not int or not 686 <= self.transport_mtu <= 65535:
            raise ValueError("private guest requires the observed IPv4 transport MTU")


def private_guest_pod(
    settings: Settings,
    pair: PairBinding,
    pvc_id: UUID,
    ca_attempt: UUID,
    runtime: PrivateGuestRuntime,
) -> Object:
    """Build only the guest member, without API I/O or readiness assertions.

    The lifecycle caller must commit immutable inputs and verify exact workspace
    and public-CA consumer ownership before creation. This constructor is not
    that authority and cannot bypass the pair ledger or release prerequisites.
    """
    if not isinstance(pvc_id, UUID) or not isinstance(ca_attempt, UUID):
        raise ValueError("committed workspace and CA identities are required")
    config = settings.session_objects
    if config is None:
        raise ValueError("guest session settings are required")
    if runtime.runtime_class == config.guest_runtime_class:
        raise ValueError("paired guest requires a distinct private-only RuntimeClass")
    # Reuse the established budget, immutable entrypoint, block devices and
    # trust contract. No Deployment is emitted or submitted to Kubernetes.
    legacy = guest_deployment(
        settings, pair.session_id, pair.sandbox_id, settings.golden_version, pvc_id, ca_attempt
    )
    spec = legacy["spec"]["template"]["spec"]
    spec.update(
        runtimeClassName=runtime.runtime_class,
        restartPolicy="Never",
        terminationGracePeriodSeconds=30,
        dnsConfig={"nameservers": ["10.10.30.1"]},
        **placement(pair, "guest"),
    )
    container = spec["containers"][0]
    container["env"].extend(
        [
            {"name": "ADS_SANDBOX_NETWORK_MODE", "value": "private"},
            {"name": "ADS_SANDBOX_ID", "value": str(pair.sandbox_id)},
            {"name": "ADS_ATTACHMENT_GENERATION", "value": str(pair.generation)},
            {"name": "ADS_PRIVATE_MTU", "value": str(runtime.transport_mtu - 110)},
        ]
    )
    container["securityContext"]["runAsGroup"] = 0
    container["securityContext"]["capabilities"]["add"] = ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"]
    return {**compute_identity(settings, pair, "guest"), "spec": spec}


@dataclass(frozen=True, slots=True)
class RelayRuntime:
    """Trusted nonsecret deployment inputs, never WireGuard/TLS key material."""

    image: str
    tls_secret: str
    transport_mtu: int
    packet_rate: int = 10000
    cpu_millis: int = 1000
    memory_mib: int = 256
    startup_seconds: int = 90

    def __post_init__(self) -> None:
        if not isinstance(self.image, str) or not re.fullmatch(
            r"[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}", self.image
        ):
            raise ValueError("relay image must be an explicit immutable digest reference")
        if (
            not isinstance(self.tls_secret, str)
            or len(self.tls_secret) > 253
            or not all(
                len(label) <= 63 and re.fullmatch(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?", label)
                for label in self.tls_secret.split(".")
            )
        ):
            raise ValueError("relay TLS Secret reference must be a DNS subdomain")
        for value, minimum, maximum in (
            (self.transport_mtu, 686, 65535),
            (self.packet_rate, 100, 100000),
            (self.cpu_millis, 1, 64000),
            (self.memory_mib, 32, 65536),
            (self.startup_seconds, 15, 300),
        ):
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError("relay platform input outside supported bounds")


def relay_input_name(pair: PairBinding, role: str) -> str:
    if role not in ("guest-relay", "egress-relay"):
        raise ValueError("invalid relay role")
    return f"{pair_name(pair, role)}.{pair.generation}"


def relay_configuration(
    pair: PairBinding,
    role: str,
    pod_uid: UUID,
    peer_key: str,
    runtime: RelayRuntime,
    service_ipv4: str | None = None,
) -> Object:
    """Nonsecret payload for protected immutable delivery after Pod UID capture.

    This does not create a Secret, generate a key, infer Service ownership or
    authorize publication. Its caller must verify exact recorded API identities.
    """
    relay_input_name(pair, role)
    if not isinstance(pod_uid, UUID):
        raise ValueError("observed canonical relay Pod UID is required")
    try:
        raw = base64.b64decode(peer_key, validate=True)
    except (TypeError, ValueError):
        raise ValueError("invalid relay peer public key") from None
    if (
        not isinstance(peer_key, str)
        or len(raw) != 32
        or not any(raw)
        or (base64.b64encode(raw).decode() != peer_key)
    ):
        raise ValueError("invalid relay peer public key")
    guest = role == "guest-relay"
    endpoint = None
    if guest:
        try:
            address = IPv4Address(service_ipv4)
        except (TypeError, ValueError):
            raise ValueError("observed numeric egress relay Service IPv4 is required") from None
        if str(address) != service_ipv4 or (
            address.is_unspecified
            or address.is_multicast
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
        ):
            raise ValueError("invalid relay Service IPv4")
        endpoint = f"{address}:{WIREGUARD_PORT}"
    elif service_ipv4 is not None:
        raise ValueError("egress relay must learn its authenticated peer endpoint")
    local, remote = ("2", "1") if guest else ("1", "2")
    return {
        "pod_uid": str(pod_uid),
        "generation": str(pair.generation),
        "sandbox_id": str(pair.sandbox_id),
        "side": "guest" if guest else "egress",
        "local_private": f"10.10.30.{local}/24",
        "peer_private": f"10.10.30.{remote}/24",
        "local_tunnel": f"10.10.40.{local}/32",
        "peer_tunnel": f"10.10.40.{remote}/32",
        "transport_mtu": runtime.transport_mtu,
        "peer_key": peer_key,
        "endpoint": endpoint,
        "wireguard_port": WIREGUARD_PORT,
        "vxlan_port": 4789,
        "vni": 42,
        "packet_rate": runtime.packet_rate,
    }


def relay_pod(settings: Settings, pair: PairBinding, role: str, runtime: RelayRuntime) -> Object:
    """Fixed ordinary-runtime Pod; required inputs hold startup until delivered."""
    inputs = relay_input_name(pair, role)
    if inputs == runtime.tls_secret:
        raise ValueError("relay transport inputs and TLS identity must be separate")
    resources = {"cpu": f"{runtime.cpu_millis}m", "memory": f"{runtime.memory_mib}Mi"}
    return {
        **compute_identity(settings, pair, role),
        "spec": {
            **placement(pair, role),
            "automountServiceAccountToken": False,
            "enableServiceLinks": False,
            "restartPolicy": "Always",
            "terminationGracePeriodSeconds": 30,
            "nodeSelector": deepcopy(settings.node_selector),
            "tolerations": deepcopy(settings.tolerations),
            "imagePullSecrets": [{"name": name} for name in settings.image_pull_secrets],
            "containers": [
                {
                    "name": "relay",
                    "image": runtime.image,
                    "imagePullPolicy": "IfNotPresent",
                    "command": [
                        "python",
                        "/usr/local/bin/ads-ptp-relay",
                        "--config",
                        "/inputs/config.json",
                        "--key",
                        "/inputs/wg.key",
                        "--cert",
                        "/inputs/tls.crt",
                        "--tls-key",
                        "/inputs/tls.key",
                        "--state",
                        "/run/relay-state",
                        "--port",
                        str(RELAY_HEALTH_PORT),
                    ],
                    "env": [
                        {
                            "name": "POD_UID",
                            "valueFrom": {
                                "fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.uid"}
                            },
                        },
                        {"name": "ATTACHMENT_GENERATION", "value": str(pair.generation)},
                    ],
                    "securityContext": {
                        "runAsUser": 0,
                        "runAsGroup": 0,
                        "privileged": False,
                        "readOnlyRootFilesystem": True,
                        "allowPrivilegeEscalation": False,
                        "capabilities": {
                            "drop": ["ALL"],
                            "add": ["SYS_ADMIN", "NET_ADMIN", "NET_RAW"],
                        },
                        "seccompProfile": {"type": "Unconfined"},
                        "appArmorProfile": {"type": "Unconfined"},
                    },
                    "resources": {"requests": dict(resources), "limits": dict(resources)},
                    "ports": [
                        {"name": "https", "containerPort": RELAY_HEALTH_PORT, "protocol": "TCP"},
                        {"name": "wireguard", "containerPort": WIREGUARD_PORT, "protocol": "UDP"},
                    ],
                    "livenessProbe": {
                        "httpGet": {"path": "/health", "port": "https", "scheme": "HTTPS"},
                        "initialDelaySeconds": runtime.startup_seconds,
                        "periodSeconds": 10,
                        "timeoutSeconds": 7,
                        "failureThreshold": 3,
                    },
                    "volumeMounts": [
                        {"name": "run", "mountPath": "/run"},
                        {"name": "tmp", "mountPath": "/tmp"},
                        *[
                            {
                                "name": volume,
                                "mountPath": f"/inputs/{key}",
                                "subPath": key,
                                "readOnly": True,
                            }
                            for volume, keys in (
                                ("config", ("config.json", "wg.key")),
                                ("tls", ("tls.crt", "tls.key")),
                            )
                            for key in keys
                        ],
                    ],
                }
            ],
            "volumes": [
                {"name": "run", "emptyDir": {"medium": "Memory", "sizeLimit": "32Mi"}},
                {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "16Mi"}},
                *[
                    {
                        "name": volume,
                        "secret": {
                            "secretName": name,
                            "defaultMode": 0o400,
                            "optional": False,
                            "items": [{"key": key, "path": key} for key in keys],
                        },
                    }
                    for volume, name, keys in (
                        ("config", inputs, ("config.json", "wg.key")),
                        ("tls", runtime.tls_secret, ("tls.crt", "tls.key")),
                    )
                ],
            ],
        },
    }
