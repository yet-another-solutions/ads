"""Pair-scoped placement and control resources; never substitutes for runtime readiness."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.objects import COMPONENT, Object
from ads_sandbox_manager.session_objects import SANDBOX, labels

GENERATION = "ads.io/attachment-generation"
PROJECT = "ads.io/project-id"
ROLES = ("guest", "egress", "guest-relay", "egress-relay", "ipc")
COMPONENTS = {
    "guest": "ads-sandbox",
    "egress": "ads-sandbox-egress",
    "guest-relay": "ads-sandbox-relay",
    "egress-relay": "ads-sandbox-egress-relay",
    "ipc": "ads-sandbox-ipc",
}
CONTROL_PORT = 8080
RELAY_HEALTH_PORT = 8443
WIREGUARD_PORT = 51820


@dataclass(frozen=True, slots=True)
class PairBinding:
    session_id: UUID
    sandbox_id: UUID
    project_id: UUID
    generation: UUID

    def __post_init__(self) -> None:
        if not all(
            isinstance(value, UUID)
            for value in (
                self.session_id,
                self.sandbox_id,
                self.project_id,
                self.generation,
            )
        ):
            raise ValueError("pair identities must be trusted UUIDs")


def pair_name(pair: PairBinding, role: str) -> str:
    if role not in ROLES:
        raise ValueError("invalid pair role")
    return f"ads-{role}-{pair.sandbox_id}"


def pair_selector(pair: PairBinding, role: str) -> Object:
    if role not in COMPONENTS:
        raise ValueError("invalid pair role")
    return {
        SANDBOX: str(pair.sandbox_id),
        GENERATION: str(pair.generation),
        COMPONENT: COMPONENTS[role],
    }


def pair_labels(settings: Settings, pair: PairBinding, role: str) -> Object:
    return {
        **labels(pair.session_id, pair.sandbox_id, settings.golden_version, COMPONENTS[role]),
        **pair_selector(pair, role),
        PROJECT: str(pair.project_id),
    }


def metadata(settings: Settings, pair: PairBinding, role: str) -> Object:
    return {
        "name": pair_name(pair, role),
        "namespace": settings.namespace,
        "labels": pair_labels(settings, pair, role),
    }


def pod_group(settings: Settings, pair: PairBinding, side: str) -> Object:
    if side not in ("guest", "egress"):
        raise ValueError("PodGroup must bind a VM and its local relay")
    return {
        "apiVersion": "scheduling.k8s.io/v1alpha2",
        "kind": "PodGroup",
        "metadata": metadata(settings, pair, side),
        "spec": {
            "schedulingPolicy": {"gang": {"minCount": 2}},
            "schedulingConstraints": {"topology": [{"key": "kubernetes.io/hostname"}]},
        },
    }


def placement(pair: PairBinding, role: str) -> Object:
    if role not in ("guest", "egress", "guest-relay", "egress-relay"):
        raise ValueError("only VMs and their local relays join PodGroups")
    side = role.removesuffix("-relay")
    return {"schedulingGroup": {"podGroupName": pair_name(pair, side)}}


def control_service(settings: Settings, pair: PairBinding, role: str) -> Object:
    if role not in ("egress", "guest-relay", "egress-relay"):
        raise ValueError("invalid control service role")
    port = CONTROL_PORT if role == "egress" else RELAY_HEALTH_PORT
    ports = [{"name": "https", "protocol": "TCP", "port": port, "targetPort": port}]
    if role == "egress-relay":
        ports.append(
            {
                "name": "wireguard",
                "protocol": "UDP",
                "port": WIREGUARD_PORT,
                "targetPort": WIREGUARD_PORT,
            }
        )
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": metadata(settings, pair, role),
        "spec": {
            "type": "ClusterIP",
            "selector": pair_selector(pair, role),
            "ports": ports,
            # Socket readiness, not peer/handshake readiness, controls endpoints.
            # The relay runtime must expose these separately from session health.
            "publishNotReadyAddresses": False,
        },
    }


def ipc_pair_environment(settings: Settings, pair: PairBinding) -> Object:
    def url(role: str, port: int) -> str:
        return f"https://{pair_name(pair, role)}.{settings.namespace}.svc:{port}"

    return {
        "ADS_SANDBOX_IPC_PROJECT_ID": str(pair.project_id),
        "ADS_SANDBOX_IPC_EGRESS_URL": url("egress", CONTROL_PORT),
        "ADS_SANDBOX_IPC_LOCAL_RELAY_HEALTH_URL": url("guest-relay", RELAY_HEALTH_PORT) + "/health",
        "ADS_SANDBOX_IPC_PEER_RELAY_HEALTH_URL": url("egress-relay", RELAY_HEALTH_PORT) + "/health",
    }


def control_ingress(settings: Settings, pair: PairBinding, role: str) -> Object:
    if role not in ("egress", "guest-relay", "egress-relay"):
        raise ValueError("invalid control ingress role")
    port = CONTROL_PORT if role == "egress" else RELAY_HEALTH_PORT
    ingress = [
        {
            "from": [{"podSelector": {"matchLabels": pair_selector(pair, "ipc")}}],
            "ports": [{"protocol": "TCP", "port": port}],
        }
    ]
    if role.endswith("-relay"):
        peer = "guest-relay" if role == "egress-relay" else "egress-relay"
        ingress.append(
            {
                "from": [{"podSelector": {"matchLabels": pair_selector(pair, peer)}}],
                "ports": [{"protocol": "UDP", "port": WIREGUARD_PORT}],
            }
        )
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": metadata(settings, pair, role),
        "spec": {
            "podSelector": {"matchLabels": pair_selector(pair, role)},
            "policyTypes": ["Ingress"],
            "ingress": ingress,
        },
    }


def resources(settings: Settings, pair: PairBinding) -> list[Object]:
    """Create before all four compute members, then await independent runtime gates.

    No images, peer keys, NICs, data plane or successful readiness are fabricated.
    Full provisioning/cleanup must persist exact UID ownership for these objects.
    """
    return [
        *(pod_group(settings, pair, side) for side in ("guest", "egress")),
        *(
            control_ingress(settings, pair, role)
            for role in (
                "egress",
                "guest-relay",
                "egress-relay",
            )
        ),
        *(
            control_service(settings, pair, role)
            for role in (
                "egress",
                "guest-relay",
                "egress-relay",
            )
        ),
    ]
