"""Trusted paired runtime construction, never a caller-supplied Pod manifest."""

from __future__ import annotations

import re
from dataclasses import dataclass
from uuid import UUID

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_objects import PairBinding, compute_identity, placement
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
            {"name": "ADS_ATTACHMENT_GENERATION", "value": str(pair.generation)},
            {"name": "ADS_PRIVATE_MTU", "value": str(runtime.transport_mtu - 110)},
        ]
    )
    container["securityContext"]["runAsGroup"] = 0
    container["securityContext"]["capabilities"]["add"] = ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"]
    return {**compute_identity(settings, pair, "guest"), "spec": spec}
