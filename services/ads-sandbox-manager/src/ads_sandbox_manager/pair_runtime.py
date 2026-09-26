"""Strict nonsecret platform inputs for the manager's paired creation path."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.egress_compute import EgressRuntime
from ads_sandbox_manager.pair_compute import PrivateGuestRuntime, RelayRuntime


@dataclass(frozen=True, slots=True)
class PairRuntime:
    guest: PrivateGuestRuntime
    relay: RelayRuntime
    egress: EgressRuntime
    state_bytes: int


def pair_runtime(settings: Settings) -> PairRuntime:
    """Helm/environment owned values only, not request- or model-owned inputs."""
    try:
        raw = settings.pair_inputs
        if (
            not isinstance(raw, dict)
            or set(raw) != {"guest", "relay", "egress", "state_bytes"}
            or settings.ca is None
            or settings.session_objects is None
            or not isinstance(settings.ads_service_subject, UUID)
        ):
            raise ValueError
        guest = PrivateGuestRuntime(**raw["guest"])
        relay = RelayRuntime(**raw["relay"])
        egress_inputs = dict(raw["egress"])
        subject = egress_inputs.pop("ipc_service_subject")
        if not isinstance(subject, str) or str(UUID(subject)) != subject:
            raise ValueError
        egress = EgressRuntime(
            **egress_inputs,
            ipc_service_subject=UUID(subject),
            keycloak_issuer=settings.keycloak_issuer,
            keycloak_well_known_url=settings.keycloak_well_known_url,
        )
        if (
            len({guest.transport_mtu, relay.transport_mtu, egress.transport_mtu}) != 1
            or len(
                {
                    guest.runtime_class,
                    egress.runtime_class,
                    settings.session_objects.guest_runtime_class,
                }
            )
            != 3
            or type(raw["state_bytes"]) is not int
            or not 64 * 1024**2 <= raw["state_bytes"] <= 64 * 1024**3
        ):
            raise ValueError
        return PairRuntime(guest, relay, egress, raw["state_bytes"])
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ValueError("invalid trusted paired runtime configuration") from None
