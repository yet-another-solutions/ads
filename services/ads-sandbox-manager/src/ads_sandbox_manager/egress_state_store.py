"""Sandbox-lifetime state reservations, not an attachment or a release verdict."""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import BigInteger, DateTime, UniqueConstraint, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent, PairIntentRepository
from ads_sandbox_manager.store import Base, SandboxSession


@dataclass(frozen=True)
class WrappingKey:
    """Transient input to the sole custody writer; never serialize or log."""

    value: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.value) is not bytes or len(self.value) != 32:
            raise ValueError("a 256-bit wrapping key is required")

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.value).hexdigest()


class EgressState(Base):
    """No session/pair cascade: state and custody outlive attachment generations.

    The initial creator generation is immutable provenance, not the persistent
    identity. Ownership transfer, retirement and deletion are deliberately not
    exposed until positive whole-pair fencing/release is integrated.
    """

    __tablename__ = "sandbox_egress_state"
    __table_args__ = (UniqueConstraint("sandbox_id", name="sandbox_egress_state_sandbox"),)

    state_id: Mapped[UUID] = mapped_column(primary_key=True)
    session_id: Mapped[UUID] = mapped_column(index=True)
    sandbox_id: Mapped[UUID]
    project_id: Mapped[UUID]
    creator_generation: Mapped[UUID]
    claim_owner: Mapped[UUID]
    claim_changed: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    namespace: Mapped[str]
    storage_bytes: Mapped[int] = mapped_column(BigInteger)
    key_fingerprint: Mapped[str]
    key_dispatch: Mapped[str]
    key_uid: Mapped[str | None]
    volume_dispatch: Mapped[str]
    volume_uid: Mapped[str | None]


def validate(state: EgressState) -> None:
    if (
        type(state.storage_bytes) is not int
        or not 0 < state.storage_bytes < 2**63
        or not isinstance(state.namespace, str)
        or not state.namespace.strip()
        or not isinstance(state.key_fingerprint, str)
        or re.fullmatch("[0-9a-f]{64}", state.key_fingerprint) is None
        or state.key_dispatch not in ("inflight", "settled")
        or state.volume_dispatch not in ("unissued", "inflight", "settled")
        or any(
            uid is not None and (not isinstance(uid, str) or not uid.strip())
            for uid in (state.key_uid, state.volume_uid)
        )
        or (state.volume_dispatch == "unissued" and state.volume_uid is not None)
        or (
            state.volume_dispatch != "unissued"
            and (state.key_dispatch != "settled" or state.key_uid is None)
        )
    ):
        raise RuntimeError("corrupt egress state reservation")


def _scope(state: EgressState) -> tuple[object, ...]:
    return (
        state.state_id,
        state.session_id,
        state.sandbox_id,
        state.project_id,
        state.creator_generation,
        state.claim_owner,
        state.claim_changed,
        state.namespace,
        state.storage_bytes,
        state.key_fingerprint,
    )


def _matches(state: EgressState, pair: PairIntent) -> None:
    if (
        state.session_id,
        state.sandbox_id,
        state.project_id,
        state.creator_generation,
        state.claim_owner,
        state.claim_changed,
        state.namespace,
    ) != (
        pair.session_id,
        pair.sandbox_id,
        pair.project_id,
        pair.generation,
        pair.claim_owner,
        pair.claim_changed,
        pair.namespace,
    ):
        raise PairClaimLost("persistent egress state ownership changed")


def _role(role: str) -> None:
    if role not in ("key", "volume"):
        raise ValueError("unsupported egress state resource")


class EgressStateRepository:
    """Caller commits before external writes; no network or filesystem I/O.

    Lock order is session, pair, state. Only the first committed reservation
    yields private bytes. Restart/losers get public evidence, never another key.
    An abandoned inflight write stays inflight even after observed UID binding.
    """

    def __init__(self, pairs: PairIntentRepository) -> None:
        self.pairs = pairs

    async def reserve(
        self,
        db: AsyncSession,
        row: SandboxSession,
        owner: UUID,
        generation: UUID,
        *,
        storage_bytes: int,
    ) -> tuple[EgressState, WrappingKey | None]:
        if type(storage_bytes) is not int or not 0 < storage_bytes < 2**63:
            raise ValueError("explicit positive egress storage bytes required")
        pair = await self.pairs.owned(db, row, owner, generation)
        state = await db.scalar(
            select(EgressState)
            .where(EgressState.sandbox_id == pair.sandbox_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        key = None
        if state is None:
            key = WrappingKey(secrets.token_bytes(32))
            state = EgressState(
                state_id=uuid4(),
                session_id=pair.session_id,
                sandbox_id=pair.sandbox_id,
                project_id=pair.project_id,
                creator_generation=pair.generation,
                claim_owner=pair.claim_owner,
                claim_changed=pair.claim_changed,
                namespace=pair.namespace,
                storage_bytes=storage_bytes,
                key_fingerprint=key.fingerprint,
                key_dispatch="inflight",
                key_uid=None,
                volume_dispatch="unissued",
                volume_uid=None,
            )
            db.add(state)
            await db.flush()
        validate(state)
        _matches(state, pair)
        if state.storage_bytes != storage_bytes:
            raise RuntimeError("egress state storage reservation changed")
        return state, key

    async def owned(
        self,
        db: AsyncSession,
        row: SandboxSession,
        owner: UUID,
        generation: UUID,
        state_id: UUID,
    ) -> EgressState:
        pair = await self.pairs.owned(db, row, owner, generation)
        state = await db.scalar(
            select(EgressState)
            .where(EgressState.state_id == state_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if state is None:
            raise PairClaimLost("persistent egress state reservation missing")
        validate(state)
        _matches(state, pair)
        return state

    async def reserve_volume(
        self,
        db: AsyncSession,
        row: SandboxSession,
        owner: UUID,
        generation: UUID,
        state_id: UUID,
    ) -> tuple[EgressState, bool]:
        state = await self.owned(db, row, owner, generation, state_id)
        if state.key_uid is None or state.key_dispatch != "settled":
            raise RuntimeError("wrapping key custody must be bound and settled")
        dispatch = state.volume_dispatch == "unissued"
        if dispatch:
            state.volume_dispatch = "inflight"
            await db.flush()
        return state, dispatch

    async def bind(
        self,
        db: AsyncSession,
        row: SandboxSession,
        owner: UUID,
        generation: UUID,
        state_id: UUID,
        role: str,
        uid: str,
    ) -> EgressState:
        _role(role)
        if not isinstance(uid, str) or not uid.strip():
            raise ValueError("observed egress state resource UID required")
        state = await self.owned(db, row, owner, generation, state_id)
        if getattr(state, f"{role}_dispatch") == "unissued":
            raise RuntimeError("egress state resource was never dispatched")
        previous = getattr(state, f"{role}_uid")
        if previous is not None and previous != uid:
            raise RuntimeError("egress state resource UID replacement refused")
        setattr(state, f"{role}_uid", uid)
        await db.flush()
        return state

    async def settle(self, db: AsyncSession, expected: EgressState, role: str) -> None:
        """Original invocation normal return only, including after claim loss.

        This records writer completion, not object absence or runtime release.
        An observer must never call this method.
        """
        _role(role)
        validate(expected)
        scope = _scope(expected)  # Capture before an identity-map refresh.
        custody_uid = expected.key_uid
        state = await db.scalar(
            select(EgressState)
            .where(EgressState.state_id == expected.state_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if state is None or _scope(state) != scope:
            raise PairClaimLost("egress state settlement identity changed")
        validate(state)
        if role == "volume" and state.key_uid != custody_uid:
            raise PairClaimLost("egress state settlement custody changed")
        if getattr(state, f"{role}_dispatch") == "unissued":
            raise RuntimeError("egress state resource was never dispatched")
        setattr(state, f"{role}_dispatch", "settled")
        await db.flush()

    async def snapshot(self, db: AsyncSession, state_id: UUID) -> EgressState | None:
        """Historical ownership only; no absence, release or retirement verdict."""
        state = await db.scalar(
            select(EgressState)
            .where(EgressState.state_id == state_id)
            .execution_options(populate_existing=True)
        )
        if state is not None:
            validate(state)
        return state
