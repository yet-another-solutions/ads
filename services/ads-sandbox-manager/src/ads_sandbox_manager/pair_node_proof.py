"""Exact node-report binding; no transport, release inference or cleanup mutation."""

from __future__ import annotations

from uuid import UUID

from ads_commons.sandbox.node_release import NodeReleaseReport, decode_node_release
from ads_sandbox_manager.pair_objects import PairBinding


def capture_report(
    raw: bytes,
    pair: PairBinding,
    *,
    node: str,
    namespace: str,
    network: str,
    pod_uids: dict[str, str | None],
) -> NodeReleaseReport:
    """Caller must supply freshly observed exact single-node placement.

    Four immutable Pod identities are mandatory. Partial startup has no invented
    empty inventory fallback. The returned report must be committed before any
    compute removal and must arrive over a separate trusted node-owner channel.
    """
    wanted = {"Pod/guest", "Pod/egress", "Pod/guest-relay", "Pod/egress-relay"}
    if (
        set(pod_uids) != wanted
        or any(not isinstance(value, str) or not value for value in pod_uids.values())
        or not all((node, namespace, network))
    ):
        raise ValueError("complete exact node and Pod identities required")
    expected = {UUID(value) for value in pod_uids.values() if value is not None}
    report = decode_node_release(raw)
    if (
        (report.node, report.namespace, report.network, report.generation, report.sandbox_id)
        != (node, namespace, network, pair.generation, pair.sandbox_id)
        or set(report.pod_uids) != expected
        or report.leftovers is not None
    ):
        raise ValueError("node capture report does not match cleanup ownership")
    return report


def release_report(raw: bytes, captured: NodeReleaseReport) -> bool:
    """A fresh trusted observation must match the original committed inventory."""
    if captured.leftovers is not None or captured.observed_runtime_released:
        raise ValueError("an original node capture report is required")
    report = decode_node_release(raw)
    fields = (
        "schema",
        "node",
        "namespace",
        "network",
        "generation",
        "sandbox_id",
        "boot_id",
        "inventory_sha256",
    )
    if (
        any(getattr(report, field) != getattr(captured, field) for field in fields)
        or set(report.pod_uids) != set(captured.pod_uids)
        or report.leftovers is None
    ):
        raise ValueError("node release report changed captured inventory")
    return report.observed_runtime_released
