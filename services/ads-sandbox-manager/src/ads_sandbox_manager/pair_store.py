"""Durable pair intent, separate from Kubernetes observations and readiness."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, UniqueConstraint, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from ads_sandbox_manager.pair_objects import COMPUTE_ROLES as COMPUTE_ROLES
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


def compute_key(role: str) -> str:
    if role not in COMPUTE_ROLES:
        raise ValueError("unsupported pair compute role")
    return f"Pod/{role}"


def new_compute_uids() -> dict[str, str | None]:
    return {compute_key(role): None for role in COMPUTE_ROLES}


def new_compute_dispatch() -> dict[str, str]:
    return {compute_key(role): "unissued" for role in COMPUTE_ROLES}


def validate_compute_evidence(intent: PairIntent) -> None:
    expected = set(new_compute_uids())
    if (
        not isinstance(intent.compute_uids, dict)
        or set(intent.compute_uids) != expected
        or any(
            uid is not None and (not isinstance(uid, str) or not uid.strip())
            for uid in intent.compute_uids.values()
        )
        or not isinstance(intent.compute_dispatch, dict)
        or set(intent.compute_dispatch) != expected
        or any(
            value not in ("unissued", "inflight", "settled")
            for value in intent.compute_dispatch.values()
        )
    ):
        raise RuntimeError("corrupt pair compute evidence")


def resource_key(kind: str, role: str) -> str:
    if (kind, role) not in CONTROL_RESOURCES:
        raise ValueError("unsupported pair control resource")
    return f"{kind}/{role}"


def new_control_dispatch() -> dict[str, str]:
    return {resource_key(*item): "unissued" for item in CONTROL_RESOURCES}


def validate_control_dispatch(intent: PairIntent) -> None:
    if (
        type(intent.creation_fenced) is not bool
        or not isinstance(intent.control_dispatch, dict)
        or set(intent.control_dispatch) != set(new_control_dispatch())
        or any(
            value not in ("unissued", "inflight", "settled")
            for value in intent.control_dispatch.values()
        )
    ):
        raise RuntimeError("corrupt pair control dispatch evidence")


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
    creation_fenced: Mapped[bool] = mapped_column(default=False)
    control_dispatch: Mapped[dict[str, str]] = mapped_column(JSONB, default=new_control_dispatch)
    compute_uids: Mapped[dict[str, str | None]] = mapped_column(JSONB, default=new_compute_uids)
    compute_dispatch: Mapped[dict[str, str]] = mapped_column(JSONB, default=new_compute_dispatch)

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
        validate_control_dispatch(intent)
        validate_compute_evidence(intent)
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
        if intent.creation_fenced:
            raise PairClaimLost("pair creation is fenced")

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
        intent = await self.owned(db, expected, owner, generation)
        previous = intent.control_uids[key]
        if previous is not None and previous != uid:
            raise RuntimeError("pair control UID replacement refused")
        intent.control_uids = {**intent.control_uids, key: uid}
        await db.flush()
        return intent

    async def owned(
        self,
        db: AsyncSession,
        expected: SandboxSession,
        owner: UUID,
        generation: UUID,
    ) -> PairIntent:
        """Revalidate an existing intent without ever allocating a replacement."""
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

    async def dispatch(
        self,
        db: AsyncSession,
        row: SandboxSession,
        owner: UUID,
        generation: UUID,
        kind: str,
        role: str,
    ) -> tuple[PairIntent, bool]:
        """Reserve the only create-capable invocation for this control key.

        Replays only observe. Neither a timeout nor a later 404 resets this
        monotonic marker; there is no new claim epoch or retry generation.
        """
        key = resource_key(kind, role)
        intent = await self.owned(db, row, owner, generation)
        dispatch = intent.control_uids[key] is None and intent.control_dispatch[key] == "unissued"
        if dispatch:
            intent.control_dispatch = {**intent.control_dispatch, key: "inflight"}
            await db.flush()
        return intent, dispatch

    async def settle(self, db: AsyncSession, expected: PairIntent, kind: str, role: str) -> None:
        """Record normal return of the original invocation, even after fencing.

        This does not bind a UID or revive provisioning authority. Exceptions,
        cancellation, lost replies and observer retries cannot settle a write.
        """
        key = resource_key(kind, role)
        intent = await self._settlement_intent(db, expected)
        if intent.control_dispatch[key] not in ("inflight", "settled"):
            raise RuntimeError("pair control was never dispatched")
        intent.control_dispatch = {**intent.control_dispatch, key: "settled"}
        await db.flush()

    async def _settlement_intent(self, db: AsyncSession, expected: PairIntent) -> PairIntent:
        """Original immutable scope only; no claim revival or UID binding."""
        identity = (
            expected.binding(),
            expected.namespace,
            expected.golden_version,
            expected.claim_owner,
            expected.claim_changed,
        )
        intent = await db.get(
            PairIntent, expected.generation, with_for_update=True, populate_existing=True
        )
        if intent is None:
            raise PairClaimLost("pair intent missing")
        self._validate(intent)
        if (
            intent.binding(),
            intent.namespace,
            intent.golden_version,
            intent.claim_owner,
            intent.claim_changed,
        ) != identity:
            raise PairClaimLost("pair dispatch identity changed")
        return intent

    async def dispatch_compute(
        self,
        db: AsyncSession,
        row: SandboxSession,
        owner: UUID,
        generation: UUID,
        role: str,
    ) -> tuple[PairIntent, bool]:
        """Reserve one Pod create-capable invocation; commit before external I/O.

        This does not create a Pod, choose a runtime or authorize controllers
        to replace it. Unresolved reservations never expire or become retries.
        """
        key = compute_key(role)
        intent = await self.owned(db, row, owner, generation)
        dispatch = intent.compute_uids[key] is None and intent.compute_dispatch[key] == "unissued"
        if dispatch:
            intent.compute_dispatch = {**intent.compute_dispatch, key: "inflight"}
            await db.flush()
        return intent, dispatch

    async def bind_compute(
        self,
        db: AsyncSession,
        row: SandboxSession,
        owner: UUID,
        generation: UUID,
        role: str,
        uid: str,
    ) -> PairIntent:
        key = compute_key(role)
        if not isinstance(uid, str) or not uid.strip():
            raise ValueError("an observed compute UID is required")
        intent = await self.owned(db, row, owner, generation)
        previous = intent.compute_uids[key]
        if previous is not None and previous != uid:
            raise RuntimeError("pair compute UID replacement refused")
        intent.compute_uids = {**intent.compute_uids, key: uid}
        await db.flush()
        return intent

    async def settle_compute(self, db: AsyncSession, expected: PairIntent, role: str) -> None:
        """Only original invocation normal return may settle, never an observer."""
        key = compute_key(role)
        intent = await self._settlement_intent(db, expected)
        if intent.compute_dispatch[key] not in ("inflight", "settled"):
            raise RuntimeError("pair compute was never dispatched")
        intent.compute_dispatch = {**intent.compute_dispatch, key: "settled"}
        await db.flush()
