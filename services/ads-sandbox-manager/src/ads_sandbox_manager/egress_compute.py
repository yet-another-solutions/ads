"""Fixed egress VM specification, not publication, bootstrap or readiness."""

from __future__ import annotations

import re
from copy import deepcopy
from dataclasses import dataclass
from ipaddress import IPv4Address
from urllib.parse import urlsplit
from uuid import UUID

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.egress_state_objects import identity
from ads_sandbox_manager.egress_state_store import EgressState, validate
from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_objects import CONTROL_PORT, PairBinding, compute_identity, placement
from ads_sandbox_manager.session_objects import ca_consumer_name


@dataclass(frozen=True, slots=True)
class EgressRuntime:
    """Trusted platform inputs only; no inline credentials or arbitrary Pod spec."""

    image: str
    runtime_class: str
    tls_secret: str
    transport_mtu: int
    cpu_millis: int
    memory_mib: int
    resolver_ipv4: str
    keycloak_issuer: str
    keycloak_well_known_url: str
    ipc_service_subject: UUID
    enforcement_configmap: str

    def __post_init__(self) -> None:
        if not isinstance(self.image, str) or not re.fullmatch(
            r"[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}", self.image
        ):
            raise ValueError("egress image must be an explicit immutable digest reference")
        if (
            not isinstance(self.runtime_class, str)
            or len(self.runtime_class) > 63
            or not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?", self.runtime_class)
        ):
            raise ValueError("egress requires an explicit DNS-label RuntimeClass")
        if (
            not isinstance(self.tls_secret, str)
            or len(self.tls_secret) > 253
            or not all(
                len(part) <= 63 and re.fullmatch(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?", part)
                for part in self.tls_secret.split(".")
            )
        ):
            raise ValueError("egress TLS reference must be a DNS subdomain")
        for value, minimum, maximum in (
            (self.transport_mtu, 686, 65535),
            (self.cpu_millis, 1, 64000),
            (self.memory_mib, 128, 65536),
        ):
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError("egress platform input outside supported bounds")
        try:
            address = IPv4Address(self.resolver_ipv4)
        except (TypeError, ValueError):
            raise ValueError("explicit numeric egress resolver IPv4 required") from None
        if str(address) != self.resolver_ipv4 or (
            address.is_unspecified
            or address.is_multicast
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
        ):
            raise ValueError("invalid egress resolver IPv4")
        for endpoint in (self.keycloak_issuer, self.keycloak_well_known_url):
            if not isinstance(endpoint, str):
                raise ValueError("trusted HTTPS Keycloak endpoints required")
            try:
                parsed = urlsplit(endpoint)
                invalid = (
                    parsed.scheme != "https"
                    or not parsed.hostname
                    or parsed.username is not None
                    or parsed.password is not None
                    or parsed.query
                    or parsed.fragment
                    or any(char.isspace() for char in endpoint)
                )
                _ = parsed.port  # Reject malformed/invalid ports too.
            except ValueError:
                raise ValueError("trusted HTTPS Keycloak endpoints required") from None
            if invalid:
                raise ValueError("trusted HTTPS Keycloak endpoints required")
        if not isinstance(self.ipc_service_subject, UUID):
            raise ValueError("trusted IPC native service subject required")
        if not isinstance(self.enforcement_configmap, str) or not re.fullmatch(
            r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?", self.enforcement_configmap
        ):
            raise ValueError("explicit enforcement ConfigMap required")


def _secret(name: str, secret: str, key: str) -> Object:
    return {
        "name": "ADS_SANDBOX_EGRESS_" + name,
        "valueFrom": {"secretKeyRef": {"name": secret, "key": key, "optional": False}},
    }


def egress_pod(
    settings: Settings,
    pair: PairBinding,
    ca_attempt: UUID,
    state: EgressState,
    runtime: EgressRuntime,
    *,
    retained_from: UUID | None = None,
) -> Object:
    """Constructor only: lifecycle must verify exact control/volume identities.

    No API call, key generation, guest input, fake health or adoption permission.
    The eventual egress runtime must validate bootstrap inputs and the wrapping
    key fingerprint, preload TLS, mount existing state safely, and supply real
    enforcement health before an IPC can admit execution.
    """
    validate(state)
    if not isinstance(ca_attempt, UUID) or settings.ca is None:
        raise ValueError("committed egress CA attempt and configuration required")
    config = settings.session_objects
    if config is None or runtime.runtime_class == config.guest_runtime_class:
        raise ValueError("egress requires a distinct paired RuntimeClass")
    if (
        state.session_id,
        state.sandbox_id,
        state.project_id,
        state.namespace,
    ) != (pair.session_id, pair.sandbox_id, pair.project_id, settings.namespace):
        raise ValueError("persistent state does not belong to the egress pair")
    if (retained_from is None and state.creator_generation != pair.generation) or (
        retained_from is not None
        and (not isinstance(retained_from, UUID) or retained_from == pair.generation)
    ):
        raise ValueError("persistent state does not belong to original or retained provenance")
    if (
        state.key_dispatch != "settled"
        or state.volume_dispatch != "settled"
        or state.key_uid is None
        or state.volume_uid is None
    ):
        raise ValueError("settled UID-bound egress custody and volume required")
    custody = identity(state, "key")["metadata"]["name"]
    if custody == runtime.tls_secret:
        raise ValueError("wrapping custody and TLS identity must remain separate")
    inputs = {
        "SESSION_ID": str(pair.session_id),
        "SANDBOX_ID": str(pair.sandbox_id),
        "PROJECT_ID": str(pair.project_id),
        "ATTACHMENT_GENERATION": str(pair.generation),
        "CREATOR_GENERATION": str(state.creator_generation),
        "NAMESPACE": settings.namespace,
        "STATE_ID": str(state.state_id),
        "STATE_DEVICE": "/dev/ads-egress-state",
        "STATE_BYTES": str(state.storage_bytes),
        "STATE_PVC_UID": state.volume_uid,
        "WRAPPING_CUSTODY_UID": state.key_uid,
        "WRAPPING_KEY_SHA256": state.key_fingerprint,
        "CA_ATTEMPT": str(ca_attempt),
        "CA_PUBLIC_DEVICE": "/dev/ads-ca-public",
        "CA_PRIVATE_DEVICE": "/dev/ads-ca-private",
        "PRIVATE_INTERFACE": "eth1",
        "PRIVATE_MTU": str(runtime.transport_mtu - 110),
        "UPSTREAM_INTERFACE": "eth0",
        "RESOLVER_IPV4": runtime.resolver_ipv4,
        "KEYCLOAK_ISSUER": runtime.keycloak_issuer,
        "KEYCLOAK_WELL_KNOWN_URL": runtime.keycloak_well_known_url,
        "KEYCLOAK_AUDIENCE": "ads-sandbox-egress",
        "IPC_SERVICE_SUBJECT": str(runtime.ipc_service_subject),
        "PORT": str(CONTROL_PORT),
    }
    budgets = {"cpu": f"{runtime.cpu_millis}m", "memory": f"{runtime.memory_mib}Mi"}
    return {
        **compute_identity(settings, pair, "egress"),
        "spec": {
            **placement(pair, "egress"),
            "runtimeClassName": runtime.runtime_class,
            "restartPolicy": "Never",
            "terminationGracePeriodSeconds": 30,
            "automountServiceAccountToken": False,
            "enableServiceLinks": False,
            "nodeSelector": deepcopy(settings.node_selector),
            "tolerations": deepcopy(settings.tolerations),
            "imagePullSecrets": [{"name": name} for name in settings.image_pull_secrets],
            "dnsPolicy": "None",
            "dnsConfig": {"nameservers": [runtime.resolver_ipv4]},
            "containers": [
                {
                    "name": "egress",
                    "image": runtime.image,
                    "imagePullPolicy": "IfNotPresent",
                    "command": ["python", "-m", "ads_sandbox_egress"],
                    "env": [
                        *[
                            {"name": "ADS_SANDBOX_EGRESS_" + name, "value": value}
                            for name, value in inputs.items()
                        ],
                        *[
                            {
                                "name": "ADS_SANDBOX_EGRESS_" + name,
                                "valueFrom": {"fieldRef": {"apiVersion": "v1", "fieldPath": field}},
                            }
                            for name, field in (
                                ("POD_UID", "metadata.uid"),
                                ("BIND_HOST", "status.podIP"),
                            )
                        ],
                        _secret("WRAPPING_KEY_B64", custody, "wrapping.b64"),
                        _secret("TLS_CERT_PEM", runtime.tls_secret, "tls.crt"),
                        _secret("TLS_KEY_PEM", runtime.tls_secret, "tls.key"),
                        {
                            "name": "ADS_SANDBOX_EGRESS_ENFORCEMENT",
                            "valueFrom": {
                                "configMapKeyRef": {
                                    "name": runtime.enforcement_configmap,
                                    "key": "enforcement.json",
                                    "optional": False,
                                }
                            },
                        },
                        {
                            "name": "ADS_SANDBOX_EGRESS_TLS_CA_PEM",
                            "valueFrom": {
                                "secretKeyRef": {
                                    "name": runtime.tls_secret,
                                    "key": "ca.crt",
                                    "optional": True,
                                }
                            },
                        },
                    ],
                    "resources": {"requests": dict(budgets), "limits": dict(budgets)},
                    "ports": [{"name": "https", "containerPort": CONTROL_PORT, "protocol": "TCP"}],
                    "securityContext": {
                        "runAsUser": 0,
                        "runAsGroup": 0,
                        "privileged": False,
                        "readOnlyRootFilesystem": True,
                        "allowPrivilegeEscalation": False,
                        "capabilities": {
                            "drop": ["ALL"],
                            "add": ["SYS_ADMIN", "NET_ADMIN", "NET_RAW", "NET_BIND_SERVICE"],
                        },
                        "seccompProfile": {"type": "Unconfined"},
                        "appArmorProfile": {"type": "Unconfined"},
                    },
                    "volumeDevices": [
                        {"name": name, "devicePath": path}
                        for name, path in (
                            ("state", "/dev/ads-egress-state"),
                            ("ca-public", "/dev/ads-ca-public"),
                            ("ca-private", "/dev/ads-ca-private"),
                        )
                    ],
                    "volumeMounts": [
                        {"name": "runtime", "mountPath": "/run/ads-egress", "readOnly": False}
                    ],
                }
            ],
            "volumes": [
                {"name": "runtime", "emptyDir": {"medium": "Memory", "sizeLimit": "32Mi"}},
                {
                    "name": "state",
                    "persistentVolumeClaim": {
                        "claimName": identity(state, "volume")["metadata"]["name"]
                    },
                },
                *[
                    {
                        "name": name,
                        "persistentVolumeClaim": {
                            "claimName": ca_consumer_name(pair.sandbox_id, role),
                            "readOnly": True,
                        },
                    }
                    for name, role in (("ca-public", "egress"), ("ca-private", "key"))
                ],
            ],
        },
    }
