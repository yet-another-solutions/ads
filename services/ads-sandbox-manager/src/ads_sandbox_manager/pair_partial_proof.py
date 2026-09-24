"""Bind partial private-runtime evidence without weakening full-pair proof."""

from __future__ import annotations

from uuid import UUID

import msgspec

from ads_commons.sandbox.partial_release import PartialReleaseReport, decode_partial_release
from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_objects import COMPUTE_ROLES, PairBinding
from ads_sandbox_manager.pair_storage_capture import (
    storage_targets,
    validate_storage_observation,
)
from ads_sandbox_manager.pair_unscheduled_proof import never_scheduled, pod_uid


def remaining_private(journal: Object) -> dict[str, str]:
    result = {}
    for role in COMPUTE_ROLES:
        if f"Pod/{role}" in journal["runtime_unissued"] or never_scheduled(journal, role):
            continue
        uid = pod_uid(journal["snapshot"], role)
        if uid is None:
            raise RuntimeError("partial runtime requires original issued UID")
        result[role] = uid
    return result


def partial_capture_report(
    raw: bytes,
    pair: PairBinding,
    *,
    node: str,
    namespace: str,
    network: str,
    pod_uids: dict[str, str],
) -> PartialReleaseReport:
    report = decode_partial_release(raw)
    if (
        not all((node, namespace, network))
        or (report.node, report.namespace, report.network, report.generation, report.sandbox_id)
        != (node, namespace, network, pair.generation, pair.sandbox_id)
        or dict(report.pod_uids) != {role: UUID(uid) for role, uid in pod_uids.items()}
        or report.leftovers is not None
    ):
        raise ValueError("partial node capture differs from original ownership")
    return report


def partial_release_report(raw: bytes, captured: PartialReleaseReport) -> bool:
    if captured.leftovers is not None:
        raise ValueError("original partial capture required")
    report = decode_partial_release(raw)
    fields = (
        "schema",
        "node",
        "namespace",
        "network",
        "generation",
        "sandbox_id",
        "boot_id",
        "pod_uids",
        "inventory_sha256",
    )
    if (
        any(getattr(report, key) != getattr(captured, key) for key in fields)
        or report.leftovers is None
    ):
        raise ValueError("partial node release changed original inventory")
    return report.observed_runtime_released


def validate_partial_journal(journal: Object, pair: PairBinding) -> None:
    observations = journal["partial_storage"]
    if not isinstance(observations, dict):
        raise RuntimeError("invalid retained partial storage observations")
    targets = storage_targets(journal["snapshot"], journal["retain_workspace"], issued_only=True)
    for role, observation in observations.items():
        if role not in targets:
            raise RuntimeError("foreign partial storage observation")
        validate_storage_observation(targets[role], observation)
    captured, released = journal["partial_capture"], journal["partial_release"]
    if captured is not None:
        report = decode_partial_release(msgspec.json.encode(captured))
        partial_capture_report(
            msgspec.json.encode(captured),
            pair,
            node=report.node,
            namespace=journal["snapshot"]["namespace"],
            network=report.network,
            pod_uids=remaining_private(journal),
        )
        if set(observations) != set(targets):
            raise RuntimeError("partial runtime capture missing original volume observations")
    if released is not None:
        if (
            "Pod/ipc" not in journal["runtime_unissued"]
            and not never_scheduled(journal, "ipc")
            and journal["ipc_release"] is None
        ):
            raise RuntimeError("partial runtime release requires original IPC release")
        if captured is None or not partial_release_report(
            msgspec.json.encode(released), decode_partial_release(msgspec.json.encode(captured))
        ):
            raise RuntimeError("partial runtime release missing positive original proof")
