from __future__ import annotations

import hashlib
import json
from uuid import uuid4

import httpx2
import msgspec
import pytest

from ads_commons.sandbox.node_release import NodeReleaseLeftovers
from ads_commons.sandbox.partial_release import decode_partial_release
from test_node_owner import Stream, config, owner, pair, report  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "role",
        "uid",
        "empty",
        "boot",
        "capture-digest",
        "nonce",
        "request",
        "phase",
        "scope",
        "counter",
        "full-schema",
    ],
)
async def test_partial_channel_binds_every_original_role_and_report_phase(config, pair, fault):  # noqa: F811
    uids = {"guest": str(uuid4()), "guest-relay": str(uuid4())}
    calls = []

    def handler(request):
        value = json.loads(request.content)
        calls.append(value)
        observing = value["operation"] == "partial-observe"
        result = report(
            value,
            leftovers=msgspec.to_builtins(NodeReleaseLeftovers(0, 0, 0, 0, 0, 0))
            if observing
            else None,
        )
        result.update(schema="ads-partial-release-v1", pod_uids=dict(value["pod_uids"]))
        if observing:
            if fault == "role":
                result["pod_uids"]["egress"] = result["pod_uids"].pop("guest")
            elif fault == "uid":
                result["pod_uids"]["guest"] = str(uuid4())
            elif fault == "empty":
                result["pod_uids"] = {}
            elif fault == "boot":
                result["boot_id"] = str(uuid4())
            elif fault == "capture-digest":
                result["inventory_sha256"] = "b" * 64
            elif fault == "phase":
                result.update(leftovers=None, observed_runtime_released=False)
            elif fault == "scope":
                result["network"] = "other"
            elif fault == "counter":
                result["leftovers"]["journals"] = True
            elif fault == "full-schema":
                result["schema"] = "ads-node-release-v1"
        envelope = {
            "schema": "ads-node-owner-v1",
            "nonce": value["nonce"],
            "request_sha256": hashlib.sha256(request.content).hexdigest(),
            "report": result,
        }
        if observing and fault == "nonce":
            envelope["nonce"] = str(uuid4())
        if observing and fault == "request":
            envelope["request_sha256"] = "c" * 64
        return httpx2.Response(
            200,
            headers={"Content-Type": "application/json"},
            stream=Stream(json.dumps(envelope).encode()),
        )

    channel = owner(config, handler)
    try:
        captured = decode_partial_release(
            await channel.capture_partial(pair, node="worker.test", pod_uids=uids)
        )
        if fault is None:
            released = decode_partial_release(await channel.observe_partial(captured))
            assert released.observed_runtime_released
            assert released.pod_uids == captured.pod_uids
        else:
            with pytest.raises((ValueError, RuntimeError)):
                await channel.observe_partial(captured)
        assert [r["operation"] for r in calls] == ["partial-capture", "partial-observe"]
        assert calls[0]["pod_uids"] == calls[1]["pod_uids"] == uids
        assert calls[1]["boot_id"] == str(captured.boot_id)
        assert calls[1]["inventory_sha256"] == captured.inventory_sha256
        assert calls[0]["nonce"] != calls[1]["nonce"]
        assert all(r["pod_uid"] is None and r["volume_uid"] is None for r in calls)
    finally:
        await channel.close()
