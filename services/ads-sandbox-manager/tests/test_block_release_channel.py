# ruff: noqa: F811
from __future__ import annotations

import hashlib
import json
from uuid import uuid4

import httpx2
import msgspec
import pytest

from ads_commons.sandbox.block_release import decode_block_release
from ads_commons.sandbox.node_release import decode_node_release
from test_node_owner import Stream, config, owner  # noqa: F401
from test_node_release_wire import node_report  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize(
    "fault", [None, "boot", "pv", "runtime", "digest", "pod", "nonce", "phase"]
)
async def test_block_channel_binds_original_runtime_volume_and_fresh_request(
    config, node_report, fault
):
    node_report.update(node="worker.test", namespace=config.namespace, network=config.network)
    runtime = decode_node_release(msgspec.json.encode(node_report))
    volumes = {
        "workspace": {
            "name": "workspace",
            "volume_uid": str(uuid4()),
            "pod_uid": str(runtime.pod_uids[0]),
        },
    }
    pv = str(uuid4())
    calls = []

    def handler(request):
        body = json.loads(request.content)
        calls.append(body)
        observed = body["operation"].endswith("observe")
        report = {
            "schema": "ads-block-release-v1",
            **{
                key: node_report[key]
                for key in (
                    "node",
                    "namespace",
                    "network",
                    "generation",
                    "sandbox_id",
                    "boot_id",
                )
            },
            "runtime_sha256": runtime.inventory_sha256,
            "inventory_sha256": "d" * 64,
            "volumes": {
                "workspace": {
                    **volumes["workspace"],
                    "pv_name": "original-pv",
                    "pv_uid": pv,
                    "volume_key": "kubernetes.io/csi/fixture^original",
                },
            },
            "leftovers": dict.fromkeys(("mappings", "mounts", "descriptors", "holders"), 0)
            if observed
            else None,
            "released": observed,
        }
        if observed:
            if fault == "boot":
                report["boot_id"] = str(uuid4())
            elif fault in ("pv", "pod"):
                report["volumes"]["workspace"][fault + "_uid"] = str(uuid4())
            elif fault in ("runtime", "digest"):
                report["runtime_sha256" if fault == "runtime" else "inventory_sha256"] = "e" * 64
            elif fault == "phase":
                report.update(leftovers=None, released=False)
        envelope = {
            "schema": "ads-node-owner-v1",
            "nonce": body["nonce"],
            "request_sha256": hashlib.sha256(request.content).hexdigest(),
            "report": report,
        }
        if observed and fault == "nonce":
            envelope["nonce"] = str(uuid4())
        return httpx2.Response(
            200,
            headers={"Content-Type": "application/json"},
            stream=Stream(json.dumps(envelope).encode()),
        )

    channel = owner(config, handler)
    try:
        captured = decode_block_release(await channel.capture_block(runtime, volumes))
        if fault is None:
            assert decode_block_release(await channel.observe_block(captured)).released
        else:
            with pytest.raises(ValueError):
                await channel.observe_block(captured)
        assert calls[0]["nonce"] != calls[1]["nonce"]
        assert calls[1]["inventory_sha256"] == captured.inventory_sha256
        assert calls[1]["runtime_sha256"] == runtime.inventory_sha256
        assert not any(key in calls[0] for key in ("path", "command", "kubeletRoot"))
    finally:
        await channel.close()
