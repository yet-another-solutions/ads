# ruff: noqa: F811
from __future__ import annotations

import hashlib
import json
from uuid import uuid4

import httpx2
import msgspec
import pytest

from ads_commons.sandbox.ipc_release import decode_ipc_release
from ads_commons.sandbox.ipc_storage import decode_ipc_storage, decode_unused_ipc_storage
from ads_sandbox_manager.pair_objects import PairBinding
from test_ipc_release_wire import ipc_report  # noqa: F401
from test_node_owner import Stream, config, owner  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize(
    "fault", [None, "pv_uid", "volume_uid", "boot_id", "inventory_sha256", "nonce"]
)
async def test_unused_channel_binds_backing_without_inventing_pod(config, fault):
    pair = PairBinding(uuid4(), uuid4(), uuid4(), uuid4())
    volume, pv, boot = str(uuid4()), str(uuid4()), str(uuid4())
    calls = []

    def handler(request):
        body = json.loads(request.content)
        calls.append(body)
        observed = body["operation"].endswith("observe")
        report = {
            "schema": "ads-ipc-unused-storage-v1",
            **{
                key: body[key]
                for key in (
                    "node",
                    "namespace",
                    "generation",
                    "sandbox_id",
                    "volume_uid",
                    "pv_uid",
                )
            },
            "boot_id": boot,
            "inventory_sha256": "d" * 64,
            "observed": observed,
            "released": observed,
            "reclaimed": observed,
        }
        if observed and fault not in (None, "nonce"):
            report[fault] = "e" * 64 if fault == "inventory_sha256" else str(uuid4())
        envelope = {
            "schema": "ads-node-owner-v1",
            "nonce": str(uuid4()) if observed and fault == "nonce" else body["nonce"],
            "request_sha256": hashlib.sha256(request.content).hexdigest(),
            "report": report,
        }
        return httpx2.Response(
            200,
            headers={"Content-Type": "application/json"},
            stream=Stream(json.dumps(envelope).encode()),
        )

    channel = owner(config, handler)
    try:
        saved = decode_unused_ipc_storage(
            await channel.capture_unused_ipc_storage(
                pair,
                node="worker.test",
                volume_uid=volume,
                pv_uid=pv,
            )
        )
        if fault is None:
            assert decode_unused_ipc_storage(
                await channel.observe_unused_ipc_storage(saved)
            ).reclaimed
        else:
            with pytest.raises(ValueError):
                await channel.observe_unused_ipc_storage(saved)
        assert calls[0]["pod_uid"] is None and calls[1]["pod_uid"] is None
        assert calls[0]["nonce"] != calls[1]["nonce"]
        assert not any(key in calls[0] for key in ("path", "command", "handle", "config"))
    finally:
        await channel.close()


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "boot",
        "runtime",
        "pv",
        "digest",
        "pod",
        "phase",
        "nonce",
        "request",
    ],
)
async def test_backing_channel_binds_original_runtime_pv_phase_and_fresh_request(
    config,
    ipc_report,
    fault,  # noqa: F811
):
    ipc_report.update(node="worker.test", namespace=config.namespace)
    original = decode_ipc_release(msgspec.json.encode(ipc_report))
    pv_uid = str(uuid4())
    calls = []

    def handler(request):
        body = json.loads(request.content)
        calls.append(body)
        observed = body["operation"].endswith("observe")
        report = {
            "schema": "ads-ipc-storage-v1",
            **{
                key: ipc_report[key]
                for key in (
                    "node",
                    "namespace",
                    "generation",
                    "sandbox_id",
                    "boot_id",
                    "pod_uid",
                    "volume_uid",
                )
            },
            "pv_uid": pv_uid,
            "runtime_sha256": original.inventory_sha256,
            "inventory_sha256": "d" * 64,
            "observed": observed,
            "released": observed,
            "reclaimed": observed,
        }
        if observed:
            if fault in ("boot", "pod", "pv"):
                report[{"boot": "boot_id", "pod": "pod_uid", "pv": "pv_uid"}[fault]] = str(uuid4())
            elif fault in ("runtime", "digest"):
                report["runtime_sha256" if fault == "runtime" else "inventory_sha256"] = "e" * 64
            elif fault == "phase":
                report.update(observed=False, released=False, reclaimed=False)
        envelope = {
            "schema": "ads-node-owner-v1",
            "nonce": body["nonce"],
            "request_sha256": hashlib.sha256(request.content).hexdigest(),
            "report": report,
        }
        if observed and fault == "nonce":
            envelope["nonce"] = str(uuid4())
        if observed and fault == "request":
            envelope["request_sha256"] = "e" * 64
        return httpx2.Response(
            200,
            headers={"Content-Type": "application/json"},
            stream=Stream(json.dumps(envelope).encode()),
        )

    channel = owner(config, handler)
    try:
        captured = decode_ipc_storage(await channel.capture_ipc_storage(original))
        if fault is None:
            assert decode_ipc_storage(await channel.observe_ipc_storage(captured)).reclaimed
        else:
            with pytest.raises(ValueError):
                await channel.observe_ipc_storage(captured)
        assert calls[0]["nonce"] != calls[1]["nonce"]
        assert calls[1]["boot_id"] == str(original.boot_id)
        assert calls[1]["inventory_sha256"] == captured.inventory_sha256
        assert set(calls[0]) == set(calls[1])
        assert not any(key in calls[0] for key in ("path", "command", "handle", "config"))
    finally:
        await channel.close()
