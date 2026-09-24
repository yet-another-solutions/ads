"""Clone writer evidence in the existing pair and workspace lifetime."""

from __future__ import annotations

from copy import deepcopy
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent, PairIntentRepository
from ads_sandbox_manager.pair_volume_inputs import validate_volume_payload, volume_role
from ads_sandbox_manager.store import SandboxSession, SessionPVC


class PairVolumeRepository:
    def __init__(self, pairs: PairIntentRepository) -> None:
        self.pairs = pairs

    async def _current(
        self,
        db: AsyncSession,
        row: SandboxSession,
        owner: UUID,
        generation: UUID,
        role: str,
        payload: Object,
    ) -> tuple[PairIntent, SandboxSession, SessionPVC]:
        validate_volume_payload(role, payload)
        intent = await self.pairs.owned(db, row, owner, generation)
        current = await db.get(SandboxSession, row.session_id)
        assert current is not None
        pvc = await db.get(
            SessionPVC, UUID(payload["pvc_id"]), with_for_update=True, populate_existing=True
        )
        if (
            current.pvc_id != UUID(payload["pvc_id"])
            or current.golden_version != intent.golden_version
            or pvc is None
            or pvc.last_state_change.isoformat() != payload["pvc_changed"]
            or (pvc.session_id, pvc.sandbox_id, pvc.state)
            != (current.session_id, current.sandbox_id, "attaching")
            or pvc.uid != current.pvc_uid
            or not all(intent.control_uids.values())
            or set(intent.control_dispatch.values()) != {"settled"}
        ):
            raise PairClaimLost("paired clone workspace or control scope changed")
        if role != "workspace":
            workspace = intent.volume_resources["workspace"]
            if (
                workspace["payload"] is None
                or not workspace["uid"]
                or workspace["uid"] != current.pvc_uid
                or workspace["payload"]["pvc_changed"] != payload["pvc_changed"]
            ):
                raise PairClaimLost("paired workspace clone prerequisite changed")
            sources = payload["sources"]
            attempt = UUID(sources["public"]["job_uid"])
            identities = {key: value["uid"] for key, value in sources.items()}
            if current.ca_attempt is None:
                if (
                    current.ca_sources is not None
                    or current.ca_clones is not None
                    or any(
                        intent.volume_resources[member]["dispatch"] != "unissued"
                        for member in ("guest", "egress", "key")
                    )
                ):
                    raise PairClaimLost("untracked CA clone bindings")
                current.ca_attempt, current.ca_sources, current.ca_clones = attempt, identities, {}
            elif current.ca_attempt != attempt or current.ca_sources != identities:
                raise PairClaimLost("paired CA source identities changed")
        return intent, current, pvc

    async def reserve(
        self,
        db: AsyncSession,
        row: SandboxSession,
        owner: UUID,
        generation: UUID,
        role: str,
        payload: Object,
    ) -> tuple[PairIntent, bool]:
        intent, current, _ = await self._current(db, row, owner, generation, role, payload)
        entry = intent.volume_resources[role]
        bound = current.pvc_uid if role == "workspace" else (current.ca_clones or {}).get(role)
        if bound != entry["uid"]:
            raise PairClaimLost("untracked or replaced paired clone binding")
        if entry["payload"] is not None and entry["payload"] != payload:
            raise RuntimeError("committed paired clone payload changed")
        dispatch = entry["dispatch"] == "unissued"
        if dispatch:
            intent.volume_resources = {
                **intent.volume_resources,
                role: {"payload": deepcopy(payload), "uid": None, "dispatch": "inflight"},
            }
        await db.flush()
        return intent, dispatch

    async def bind(
        self,
        db: AsyncSession,
        row: SandboxSession,
        owner: UUID,
        generation: UUID,
        role: str,
        uid: str,
    ) -> PairIntent:
        volume_role(role)
        if not isinstance(uid, str) or not uid.strip():
            raise ValueError("observed paired clone UID required")
        intent = await self.pairs.owned(db, row, owner, generation)
        entry = intent.volume_resources[role]
        if entry["dispatch"] == "unissued":
            raise RuntimeError("paired clone was never dispatched")
        intent, current, pvc = await self._current(
            db, row, owner, generation, role, entry["payload"]
        )
        bound = current.pvc_uid if role == "workspace" else (current.ca_clones or {}).get(role)
        if any(previous is not None and previous != uid for previous in (bound, entry["uid"])):
            raise RuntimeError("paired clone UID replacement refused")
        if role == "workspace":
            current.pvc_uid = pvc.uid = uid
        else:
            current.ca_clones = {**(current.ca_clones or {}), role: uid}
        intent.volume_resources = {**intent.volume_resources, role: {**entry, "uid": uid}}
        await db.flush()
        return intent

    async def settle(self, db: AsyncSession, expected: PairIntent, role: str) -> None:
        volume_role(role)
        intent = await self.pairs._settlement_intent(db, expected)
        entry = intent.volume_resources[role]
        if entry["payload"] != expected.volume_resources[role]["payload"]:
            raise PairClaimLost("paired clone settlement payload changed")
        if entry["dispatch"] not in ("inflight", "settled"):
            raise RuntimeError("paired clone was never dispatched")
        intent.volume_resources = {
            **intent.volume_resources,
            role: {**entry, "dispatch": "settled"},
        }
        await db.flush()
