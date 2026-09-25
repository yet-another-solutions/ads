"""Never-mounted storage proof derived from positive original consumer history."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

import msgspec

from ads_commons.sandbox.ipc_storage import decode_unused_ipc_storage
from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_block_proof import CONSUMERS
from ads_sandbox_manager.pair_inherited_storage import (
    validate_inherited_capture,
    validate_inherited_release,
)
from ads_sandbox_manager.pair_storage_capture import storage_targets, validate_storage_observation
from ads_sandbox_manager.pair_unscheduled_proof import never_scheduled


def unused_consumer(journal: Object, role: str) -> str | None:
    consumer = "ipc" if role == "ipc" else CONSUMERS[role]
    if f"Pod/{consumer}" in journal["runtime_unissued"]:
        return "unissued"
    return "unscheduled" if never_scheduled(journal, consumer) else None


def validate_unused_capture(journal: Object, role: str, value: Object) -> None:
    targets = storage_targets(journal["snapshot"], journal["retain_workspace"], issued_only=True)
    if (
        role not in targets
        or not isinstance(value, dict)
        or set(value)
        != (
            {"mode", "target", "storage_class", "pvc_created"}
            | ({"node", "backing"} if value.get("mode") == "never-mounted-filesystem" else set())
            | ({"previous"} if value.get("mode") == "retired-inherited-csi" else set())
        )
        or unused_consumer(journal, role) is None
    ):
        raise RuntimeError("original never-mounted consumer proof required")
    target = value["target"]
    validate_storage_observation(targets[role], target)
    if target["nodes"] and value["mode"] != "retired-inherited-csi":
        raise RuntimeError("never-mounted capture contradicts observed node use")
    if value["mode"] == "retired-inherited-csi":
        validate_inherited_capture(journal, role, value)
    elif value["mode"] == "never-provisioned":
        sc = value["storage_class"]
        if (
            unused_consumer(journal, role) != "unissued"
            or target.get("never_bound") is not True
            or target["retain"]
            or not isinstance(sc, dict)
            or set(sc) != {"name", "uid", "created", "provisioner", "binding"}
            or sc["binding"] != "WaitForFirstConsumer"
            or sc["provisioner"] == "kubernetes.io/no-provisioner"
            or any(not isinstance(v, str) or not v.strip() for v in sc.values())
        ):
            raise RuntimeError("never-provisioned claim lacks original delayed-binding contract")
        if str(UUID(sc["uid"])) != sc["uid"]:
            raise RuntimeError("canonical StorageClass UID required")
        start, created = (
            datetime.fromisoformat(sc["created"]),
            datetime.fromisoformat(value["pvc_created"]),
        )
        if start.tzinfo is None or created.tzinfo is None or start > created:
            raise RuntimeError("StorageClass must predate the original claim")
    elif value["mode"] == "never-mounted-csi":
        if (
            target.get("never_bound")
            or not target.get("volume_key")
            or "filesystem_backing" in target
            or not (target["retain"] or (target["delete_policy"] and target["reclaim_guard"]))
            or value["storage_class"] is not None
            or value["pvc_created"] is not None
        ):
            raise RuntimeError("never-mounted claim lacks original CSI reclamation contract")
    elif value["mode"] == "never-mounted-filesystem":
        proof = decode_unused_ipc_storage(msgspec.json.encode(value["backing"]))
        if (
            role != "ipc"
            or target.get("never_bound")
            or not target.get("filesystem_backing")
            or target.get("volume_key")
            or not target["delete_policy"]
            or target["retain"]
            or value["storage_class"] is not None
            or value["pvc_created"] is not None
            or not isinstance(value["node"], str)
            or not value["node"]
            or proof.node != value["node"]
            or proof.namespace != journal["snapshot"]["namespace"]
            or str(proof.generation) != journal["snapshot"]["generation"]
            or str(proof.sandbox_id) != journal["snapshot"]["sandbox_id"]
            or str(proof.volume_uid) != target["uid"]
            or str(proof.pv_uid) != target["pv_uid"]
            or proof.observed
            or proof.released
            or proof.reclaimed
        ):
            raise RuntimeError("unused filesystem capture lacks exact original backing")
    else:
        raise RuntimeError("unsupported never-mounted storage proof")


def validate_unused_journal(journal: Object) -> None:
    values = journal["unused_storage"]
    if not isinstance(values, dict):
        raise RuntimeError("invalid never-mounted storage journal")
    for role, value in values.items():
        filesystem = (
            isinstance(value, dict)
            and isinstance(value.get("capture"), dict)
            and value["capture"].get("mode") == "never-mounted-filesystem"
        )
        inherited = (
            isinstance(value, dict)
            and isinstance(value.get("capture"), dict)
            and value["capture"].get("mode") == "retired-inherited-csi"
        )
        if not isinstance(value, dict) or set(value) != (
            {"capture", "disposition"}
            | ({"release", "reclaimed"} if filesystem else set())
            | ({"release"} if inherited else set())
        ):
            raise RuntimeError("invalid never-mounted storage receipt")
        validate_unused_capture(journal, role, value["capture"])
        expected = "retained" if value["capture"]["target"]["retain"] else "reclaimed"
        if value["disposition"] not in (None, expected):
            raise RuntimeError("never-mounted disposition changed")
        if inherited:
            validate_inherited_release(value)
        if filesystem:
            captured = value["capture"]["backing"]
            for phase in ("release", "reclaimed"):
                raw = value[phase]
                if raw is None:
                    continue
                proof = decode_unused_ipc_storage(msgspec.json.encode(raw))
                if (
                    not proof.observed
                    or not proof.released
                    or (phase == "reclaimed" and (not proof.reclaimed or value["release"] is None))
                    or any(
                        raw[key] != captured[key]
                        for key in captured
                        if key not in ("observed", "released", "reclaimed")
                    )
                ):
                    raise RuntimeError("unused filesystem observation changed original backing")
            if value["disposition"] is not None and value["reclaimed"] is None:
                raise RuntimeError("unused filesystem disposition lacks positive reclamation")
