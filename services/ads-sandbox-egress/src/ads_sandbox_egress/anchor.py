"""Authenticated public anchor delivery, no private key or upstream trust export."""

from __future__ import annotations

from ads_commons.egress import EgressDNSAnchor
from ads_commons.security import AccessDenied, SecurityContextHolder, ensure_caller
from ads_sandbox_egress.configuration import ConfigurationUnavailable, PairIdentity


class AnchorService:
    def __init__(self, pair: PairIdentity, value: EgressDNSAnchor | None) -> None:
        if value is not None and (value.project_id, value.sandbox_id) != (
            pair.project_id,
            pair.sandbox_id,
        ):
            raise ValueError("anchor pair identity mismatch")
        self.pair, self.value = pair, value

    def get(self) -> EgressDNSAnchor:
        context = SecurityContextHolder.require()
        ensure_caller(context, "ads-sandbox-ipc")
        if context.user_id != self.pair.ipc_service_subject:
            raise AccessDenied("expected IPC service identity")
        if self.value is None:
            raise ConfigurationUnavailable()
        return self.value
