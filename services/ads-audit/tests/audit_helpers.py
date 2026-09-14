from __future__ import annotations

from ads_policy.contract import AuditEvent, Capability, Effect

TOKEN = "audit-api-token-32-bytes-long"


def denied(
    run_id: str = "run-1",
    resource: str = "ads-client-secret",
    weight: int = 5,
    subject: str = "alice",
    capability: Capability = Capability.SECRET_READ,
) -> AuditEvent:
    return AuditEvent(
        run_id=run_id,
        subject=subject,
        capability=capability,
        resource=resource,
        effect=Effect.DENY,
        rule_id=capability.value,
        weight=weight,
        policy_hash="hash",
    )
