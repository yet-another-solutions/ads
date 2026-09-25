"""Original Block capture binding; no driver paths or API-absence proof."""

from __future__ import annotations

import msgspec

from ads_commons.sandbox.block_release import decode_block_release
from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_unscheduled_proof import never_scheduled

CONSUMERS = {
    "workspace": "guest",
    "guest": "guest",
    "egress": "egress",
    "key": "egress",
    "state": "egress",
}


def block_volumes(journal: Object) -> dict[str, dict[str, str]]:
    """Only originally bound claims of assigned original consumers."""
    snapshot = journal["snapshot"]
    targets = {**journal["storage_capture"], **journal["partial_storage"]}
    result = {}
    for role, consumer in CONSUMERS.items():
        target = targets.get(role)
        if (
            target is None
            or target.get("never_bound")
            or f"Pod/{consumer}" in journal["runtime_unissued"]
            or never_scheduled(journal, consumer)
        ):
            continue
        uid = snapshot["compute_uids"][f"Pod/{consumer}"]
        if not uid or not target.get("volume_key"):
            raise RuntimeError("original bound Block consumer identity required")
        result[role] = {"name": target["name"], "volume_uid": target["uid"], "pod_uid": uid}
    return result


def validate_block_journal(journal: Object) -> None:
    capture = journal["block_capture"]
    targets = {**journal["storage_capture"], **journal["partial_storage"]}
    if (
        (journal["runtime_release"] or journal["partial_release"])
        and block_volumes(journal)
        and capture is None
    ):
        raise RuntimeError("released runtime lacks original Block mapping capture")
    if capture is not None:
        report = decode_block_release(msgspec.json.encode(capture))
        runtime = journal["node_capture"] or journal["partial_capture"]
        wanted = block_volumes(journal)
        if (
            runtime is None
            or report.leftovers is not None
            or report.runtime_sha256 != runtime["inventory_sha256"]
            or any(
                capture[key] != runtime[key]
                for key in ("node", "namespace", "network", "generation", "sandbox_id", "boot_id")
            )
            or set(capture["volumes"]) != set(wanted)
        ):
            raise RuntimeError("Block capture missing original runtime binding")
        for role, expected in wanted.items():
            identity, target = capture["volumes"][role], targets[role]
            if (
                any(identity[key] != value for key, value in expected.items())
                or any(identity[key] != target[key] for key in ("pv_name", "pv_uid", "volume_key"))
                or report.node not in target["nodes"]
            ):
                raise RuntimeError("Block capture differs from original backing identity")
    proof = journal["block_release"]
    if proof is not None:
        report = decode_block_release(msgspec.json.encode(proof))
        if (
            capture is None
            or not report.released
            or not (journal["runtime_release"] or journal["partial_release"])
            or any(
                proof[key] != capture[key]
                for key in capture
                if key not in ("leftovers", "released")
            )
        ):
            raise RuntimeError("Block release lacks positive original runtime/device proof")
    dispositions = journal["block_disposition"]
    if not isinstance(dispositions, dict):
        raise RuntimeError("invalid Block disposition ledger")
    for role, disposition in dispositions.items():
        if (
            proof is None
            or role not in proof["volumes"]
            or role not in targets
            or disposition != ("retained" if targets[role]["retain"] else "reclaimed")
            or (
                disposition == "reclaimed"
                and not (targets[role]["delete_policy"] and targets[role]["reclaim_guard"])
            )
        ):
            raise RuntimeError("Block disposition lacks original protected release")
