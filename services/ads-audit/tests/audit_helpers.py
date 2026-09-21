from __future__ import annotations

from ads_policy.contract import AuditEvent, Capability, Effect

TOKEN = "audit-api-token-32-bytes-long"
SESSION_SECRET = "audit-session-secret-32-bytes!!"


class SilentBroker:
    async def channel(self) -> _Channel:
        return _Channel()


class _Channel:
    async def set_qos(self, prefetch_count: int) -> None:
        return None

    async def declare_exchange(self, name: str, kind: object, durable: bool) -> _Exchange:
        return _Exchange()

    async def declare_queue(self, name: str, durable: bool) -> _Queue:
        return _Queue()


class _Exchange:
    pass


class _Queue:
    async def bind(self, exchange: object, routing_key: str) -> None:
        return None

    async def consume(self, callback: object) -> None:
        return None


def denied(
    run_id: str = "run-1",
    resource: str = "ads-client-secret",
    weight: int = 5,
    subject: str = "alice",
    capability: Capability = Capability.SECRET_READ,
    conversation: str = "",
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
        conversation=conversation,
    )
