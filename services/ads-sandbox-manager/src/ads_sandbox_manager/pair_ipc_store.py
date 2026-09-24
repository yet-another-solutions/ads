"""IPC writer ownership under the existing pair and session claim."""

from __future__ import annotations

from copy import deepcopy
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_ipc_inputs import ipc_role, validate_ipc_payload
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent, PairIntentRepository
from ads_sandbox_manager.store import SandboxSession


class PairIpcRepository:
    def __init__(self, pairs: PairIntentRepository) -> None:
        self.pairs = pairs

    @staticmethod
    def dependencies(intent: PairIntent) -> Object:
        if (
            not all(intent.control_uids.values())
            or set(intent.control_dispatch.values()) != {"settled"}
            or not all(intent.compute_uids.values())
            or set(intent.compute_dispatch.values()) != {"settled"}
            or not all(intent.compute_payloads.values())
            or intent.egress_state_id is None
            or intent.relay_custody["dispatch"] != "settled"
            or not intent.relay_custody["uid"]
            or any(
                entry["dispatch"] != "settled" or not entry["uid"]
                for entry in intent.relay_inputs.values()
            )
        ):
            raise RuntimeError("settled UID-bound complete pair required before IPC")
        return {
            "control_uids": dict(intent.control_uids),
            "compute_uids": dict(intent.compute_uids),
            "relay_input_uids": {role: entry["uid"] for role, entry in intent.relay_inputs.items()},
            "custody_uid": intent.relay_custody["uid"],
            "state_id": str(intent.egress_state_id),
        }

    async def _dependencies(
        self,
        db: AsyncSession,
        intent: PairIntent,
        current: SandboxSession,
        role: str,
        payload: Object,
    ) -> None:
        if current.ipc_deployment_uid is not None:
            raise PairClaimLost("legacy IPC Deployment binding blocks paired Pod publication")
        expected = self.dependencies(intent)
        if any(payload[key] != value for key, value in expected.items()):
            raise PairClaimLost("paired IPC dependency identities changed")
        for member, committed in intent.compute_payloads.items():
            await self.pairs._compute_dependencies(db, intent, current, member, committed)
        if role == "pod":
            volume = intent.ipc_resources["volume"]
            if (
                volume["dispatch"] != "settled"
                or not volume["uid"]
                or volume["uid"] != payload["volume_uid"]
                or current.ipc_pvc_uid != volume["uid"]
            ):
                raise PairClaimLost("settled UID-bound IPC volume required")

    async def reserve(
        self,
        db: AsyncSession,
        row: SandboxSession,
        owner: UUID,
        generation: UUID,
        role: str,
        payload: Object,
    ) -> tuple[PairIntent, bool]:
        validate_ipc_payload(role, payload)
        intent = await self.pairs.owned(db, row, owner, generation)
        current = await db.get(SandboxSession, row.session_id)
        assert current is not None
        await self._dependencies(db, intent, current, role, payload)
        entry = intent.ipc_resources[role]
        field = "ipc_pvc_uid" if role == "volume" else "ipc_pod_uid"
        if getattr(current, field) != entry["uid"]:
            raise PairClaimLost("untracked or replaced IPC session binding")
        if entry["payload"] is not None and entry["payload"] != payload:
            raise RuntimeError("committed paired IPC payload changed")
        dispatch = entry["dispatch"] == "unissued"
        if dispatch:
            intent.ipc_resources = {
                **intent.ipc_resources,
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
        ipc_role(role)
        if not isinstance(uid, str) or not uid.strip():
            raise ValueError("observed paired IPC UID required")
        intent = await self.pairs.owned(db, row, owner, generation)
        current = await db.get(SandboxSession, row.session_id)
        assert current is not None
        entry = intent.ipc_resources[role]
        if entry["dispatch"] == "unissued":
            raise RuntimeError("paired IPC resource was never dispatched")
        await self._dependencies(db, intent, current, role, entry["payload"])
        field = "ipc_pvc_uid" if role == "volume" else "ipc_pod_uid"
        if any(
            previous is not None and previous != uid
            for previous in (entry["uid"], getattr(current, field))
        ):
            raise RuntimeError("paired IPC UID replacement refused")
        intent.ipc_resources = {**intent.ipc_resources, role: {**entry, "uid": uid}}
        setattr(current, field, uid)
        await db.flush()
        return intent

    async def settle(self, db: AsyncSession, expected: PairIntent, role: str) -> None:
        ipc_role(role)
        intent = await self.pairs._settlement_intent(db, expected)
        entry = intent.ipc_resources[role]
        if entry["payload"] != expected.ipc_resources[role]["payload"]:
            raise PairClaimLost("paired IPC settlement payload changed")
        if entry["dispatch"] not in ("inflight", "settled"):
            raise RuntimeError("paired IPC resource was never dispatched")
        intent.ipc_resources = {**intent.ipc_resources, role: {**entry, "dispatch": "settled"}}
        await db.flush()
