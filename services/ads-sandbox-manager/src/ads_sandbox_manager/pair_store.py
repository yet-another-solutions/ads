"""Durable pair intent, separate from Kubernetes observations and readiness."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, UniqueConstraint, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from ads_sandbox_manager.pair_objects import PairBinding
from ads_sandbox_manager.store import Base, SandboxSession

CONTROL_RESOURCES = (
    ("PodGroup", "guest"),
    ("PodGroup", "egress"),
    ("Service", "egress"),
    ("Service", "guest-relay"),
    ("Service", "egress-relay"),
    ("NetworkPolicy", "egress"),
    ("NetworkPolicy", "guest-relay"),
    ("NetworkPolicy", "egress-relay"),
)


def resource_key(kind: str, role: str) -> str:
    if (kind, role) not in CONTROL_RESOURCES:
        raise ValueError("unsupported pair control resource")
    return f"{kind}/{role}"


class PairIntent(Base):
    """Captured ownership survives session replacement/deletion; no cascade.

    Missing UIDs mean unobserved creation, not absence. No row in this ledger
    declares compute readiness, attachment release, or completed retirement.
    """

    __tablename__ = "sandbox_pair_intent"
    __table_args__ = (
        UniqueConstraint("sandbox_id", name="sandbox_pair_intent_sandbox"),
        UniqueConstraint(
            "session_id", "claim_owner", "claim_changed", name="sandbox_pair_intent_claim"
        ),
    )

    generation: Mapped[UUID] = mapped_column(primary_key=True)
    session_id: Mapped[UUID] = mapped_column(index=True)
    sandbox_id: Mapped[UUID]
    project_id: Mapped[UUID]
    claim_owner: Mapped[UUID]
    claim_changed: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    namespace: Mapped[str]
    golden_version: Mapped[str]
    control_uids: Mapped[dict[str, str | None]] = mapped_column(JSONB)

    def binding(self) -> PairBinding:
        return PairBinding(self.session_id, self.sandbox_id, self.project_id, self.generation)


class PairClaimLost(RuntimeError):
    pass


class PairIntentRepository:
    """Caller-owned transactions: commit intent before any external operation.

    Lock the session first, then the intent, in the existing lifecycle order.
    No transaction here performs Kubernetes, Kafka, filesystem, or token I/O.
    Retirement/recreation is deliberately unavailable until runtime-release
    evidence and cleanup are integrated; old ownership is never overwritten.
    """

    async def _owned(
        self, db: AsyncSession, expected: SandboxSession, owner: UUID
    ) -> SandboxSession:
        identity = (
            expected.sandbox_id,
            expected.project_id,
            expected.status_changed_at,
        )
        row = await db.scalar(
            select(SandboxSession)
            .where(SandboxSession.session_id == expected.session_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if (
            row is None
            or (row.sandbox_id, row.project_id, row.status_changed_at) != identity
            or row.status != "creating"
            or row.claimed_by != owner
        ):
            raise PairClaimLost("session provisioning claim changed")
        return row

    @staticmethod
    def _validate(intent: PairIntent) -> None:
        expected = {resource_key(kind, role) for kind, role in CONTROL_RESOURCES}
        if (
            not isinstance(intent.control_uids, dict)
            or set(intent.control_uids) != expected
            or any(
                uid is not None and (not isinstance(uid, str) or not uid.strip())
                for uid in intent.control_uids.values()
            )
        ):
            raise RuntimeError("incomplete or corrupt pair control intent")

    @staticmethod
    def _matches(intent: PairIntent, row: SandboxSession, owner: UUID) -> None:
        if (
            intent.session_id != row.session_id
            or intent.sandbox_id != row.sandbox_id
            or intent.project_id != row.project_id
            or intent.claim_owner != owner
            or intent.claim_changed != row.status_changed_at
        ):
            raise PairClaimLost("prior pair requires fenced retirement")

    async def begin(
        self,
        db: AsyncSession,
        expected: SandboxSession,
        owner: UUID,
        *,
        namespace: str,
        golden_version: str,
    ) -> PairIntent:
        if not namespace or not golden_version:
            raise ValueError("pair namespace and builder version are required")
        row = await self._owned(db, expected, owner)
        intent = await db.scalar(
            select(PairIntent)
            .where(PairIntent.sandbox_id == row.sandbox_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if intent is None:
            intent = PairIntent(
                generation=uuid4(),
                session_id=row.session_id,
                sandbox_id=row.sandbox_id,
                project_id=row.project_id,
                claim_owner=owner,
                claim_changed=row.status_changed_at,
                namespace=namespace,
                golden_version=golden_version,
                control_uids={resource_key(kind, role): None for kind, role in CONTROL_RESOURCES},
            )
            db.add(intent)
            await db.flush()
        self._matches(intent, row, owner)
        if intent.namespace != namespace or intent.golden_version != golden_version:
            raise RuntimeError("pair builder configuration changed")
        self._validate(intent)
        return intent

    async def bind(
        self,
        db: AsyncSession,
        expected: SandboxSession,
        owner: UUID,
        generation: UUID,
        kind: str,
        role: str,
        uid: str,
    ) -> PairIntent:
        key = resource_key(kind, role)
        if not isinstance(uid, str) or not uid.strip():
            raise ValueError("an observed UID is required")
        row = await self._owned(db, expected, owner)
        intent = await db.scalar(
            select(PairIntent)
            .where(PairIntent.generation == generation)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if intent is None:
            raise PairClaimLost("pair intent missing")
        self._matches(intent, row, owner)
        self._validate(intent)
        previous = intent.control_uids[key]
        if previous is not None and previous != uid:
            raise RuntimeError("pair control UID replacement refused")
        intent.control_uids = {**intent.control_uids, key: uid}
        await db.flush()
        return intent

    async def snapshot(self, db: AsyncSession, generation: UUID) -> PairIntent | None:
        """Read one captured generation, never reinterpret the current session."""
        intent = await db.scalar(
            select(PairIntent)
            .where(PairIntent.generation == generation)
            .execution_options(populate_existing=True)
        )
        if intent is not None:
            self._validate(intent)
        return intent
