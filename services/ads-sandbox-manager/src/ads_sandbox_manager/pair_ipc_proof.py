"""Bind authenticated IPC node evidence to the original retained ownership."""

from __future__ import annotations

from uuid import UUID

from ads_commons.sandbox.ipc_release import IpcReleaseReport, decode_ipc_release
from ads_sandbox_manager.pair_objects import PairBinding


def ipc_capture_report(
    raw: bytes,
    pair: PairBinding,
    *,
    node: str,
    namespace: str,
    pod_uid: str,
    volume_uid: str,
) -> IpcReleaseReport:
    report = decode_ipc_release(raw)
    if (
        not node.strip()
        or not namespace.strip()
        or (
            report.node,
            report.namespace,
            report.generation,
            report.sandbox_id,
            report.pod_uid,
            report.volume_uid,
        )
        != (node, namespace, pair.generation, pair.sandbox_id, UUID(pod_uid), UUID(volume_uid))
        or report.leftovers is not None
    ):
        raise ValueError("IPC capture report does not match cleanup ownership")
    return report


def ipc_release_report(raw: bytes, captured: IpcReleaseReport) -> bool:
    if captured.leftovers is not None or captured.observed_runtime_released:
        raise ValueError("an original IPC capture report is required")
    report = decode_ipc_release(raw)
    fields = (
        "schema",
        "node",
        "namespace",
        "generation",
        "sandbox_id",
        "boot_id",
        "pod_uid",
        "volume_uid",
        "inventory_sha256",
    )
    if any(getattr(report, field) != getattr(captured, field) for field in fields) or (
        report.leftovers is None
    ):
        raise ValueError("IPC release report changed captured inventory")
    return report.observed_runtime_released
