"""Terminal resource obligations derived only from a sealed original ledger."""

from __future__ import annotations

from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_storage_capture import storage_targets
from ads_sandbox_manager.pair_unscheduled_proof import RUNTIME_ROLES, never_scheduled


def runtime_complete(journal: Object) -> bool:
    def never(role: str) -> bool:
        return f"Pod/{role}" in journal["runtime_unissued"] or never_scheduled(journal, role)

    ipc = never("ipc") or journal["ipc_release"] is not None
    private = journal["runtime_release"] is not None or all(
        never(role)
        or (
            journal["partial_release"] is not None
            and role in journal["partial_release"]["pod_uids"]
        )
        for role in RUNTIME_ROLES
        if role != "ipc"
    )
    return ipc and private


def storage_complete(journal: Object) -> bool:
    targets = storage_targets(journal["snapshot"], journal["retain_workspace"], issued_only=True)
    for role, target in targets.items():
        if role == "ipc":
            if journal["ipc_storage_reclaimed"] is None:
                return False
        elif journal["block_disposition"].get(role) != (
            "retained" if target["retain"] else "reclaimed"
        ):
            return False
    return True


def resource_targets(journal: Object) -> dict[str, Object]:
    snapshot = journal["snapshot"]
    creator = journal["creator_snapshot"]
    result = {}

    def add(key: str, uid: str | None, dispatch: str, retain: bool = False) -> None:
        if dispatch == "unissued" and uid is None:
            return
        if dispatch != "settled" or not uid:
            raise RuntimeError("resource disposition requires settled original UID")
        result[key] = {"uid": uid, "disposition": "retained" if retain else "deleted"}

    for key, uid in snapshot["control_uids"].items():
        add("control/" + key, uid, creator["control_dispatch"][key])
    for role, entry in snapshot["relay_inputs"].items():
        add("relay-input/" + role, entry["uid"], creator["relay_inputs"][role]["dispatch"])
    custody = snapshot["relay_custody"]
    add("relay-custody", custody["uid"], creator["relay_custody"]["dispatch"])
    state = snapshot["egress_state"]
    if state is not None:
        add(
            "state-key",
            state["key_uid"],
            creator["egress_state"]["key_dispatch"],
            journal["retain_workspace"],
        )
    return result


def validate_resource_journal(journal: Object) -> None:
    dispositions = journal["resource_disposition"]
    if not isinstance(dispositions, dict):
        raise RuntimeError("invalid retained resource disposition")
    if dispositions:
        if not runtime_complete(journal) or not storage_complete(journal):
            raise RuntimeError("resource disposal precedes positive runtime/storage release")
        targets = resource_targets(journal)
        if any(key not in targets or value != targets[key] for key, value in dispositions.items()):
            raise RuntimeError("resource disposition differs from original ownership")
    topics = journal["topic_disposition"]
    if topics is not None:
        if (
            topics not in ("unissued", "retained", "deleted")
            or not runtime_complete(journal)
            or not storage_complete(journal)
            or dispositions != resource_targets(journal)
            or topics
            != (
                "unissued"
                if journal["snapshot"]["topics_dispatch"] == "unissued"
                else "retained"
                if journal["retain_workspace"]
                else "deleted"
            )
            or journal["creator_snapshot"]["topics_dispatch"] == "inflight"
        ):
            raise RuntimeError("topic disposition lacks settled original terminal evidence")
