from __future__ import annotations

import asyncio
import hashlib
import json
import ssl
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import httpx2
import msgspec
import pytest

from ads_commons.sandbox.node_release import decode_node_release
from ads_sandbox_manager.node_owner import HttpsNodeOwner, NodeOwnerSettings
from ads_sandbox_manager.pair_objects import PairBinding


class Stream(httpx2.AsyncByteStream):
    def __init__(self, content):
        self.content = content

    async def __aiter__(self):
        yield self.content


@pytest.fixture
def pair():
    return PairBinding(*(uuid4() for _ in range(4)))


@pytest.fixture
def config():
    return NodeOwnerSettings(
        endpoints={"worker.test": "https://worker.test:9443"},
        namespace="sandboxes",
        network="private",
        ca=Path("/ca"),
        certificate=Path("/certificate"),
        key=Path("/key"),
        timeout=5,
    )


def report(request, *, leftovers=None):
    return {
        "schema": "ads-node-release-v1",
        **{
            key: request[key]
            for key in ("node", "namespace", "network", "generation", "sandbox_id")
        },
        "boot_id": request["boot_id"] or str(uuid4()),
        "pod_uids": [str(uuid4()) for _ in range(4)],
        "inventory_sha256": request["inventory_sha256"] or "a" * 64,
        "attachment_admission_fenced": True,
        "release_inventory_captured": True,
        "observed_runtime_released": leftovers is not None and not any(leftovers.values()),
        "generation_retired": False,
        "leftovers": leftovers,
    }


def owner(config, handler):
    value = object.__new__(HttpsNodeOwner)
    value.settings = config
    value.client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler), trust_env=False)
    return value


@pytest.mark.anyio
async def test_request_is_fresh_correlated_bounded_and_exact(config, pair):
    requests = []

    def handler(request):
        body = request.content
        value = json.loads(body)
        requests.append(value)
        content = json.dumps(
            {
                "schema": "ads-node-owner-v1",
                "nonce": value["nonce"],
                "request_sha256": hashlib.sha256(body).hexdigest(),
                "report": report(value),
            }
        ).encode()
        return httpx2.Response(
            200,
            headers={"Content-Type": "application/json"},
            stream=Stream(content),
        )

    channel = owner(config, handler)
    raw = await channel.fence_and_capture(pair, node="worker.test")
    decoded = decode_node_release(raw)
    assert (decoded.generation, decoded.sandbox_id) == (pair.generation, pair.sandbox_id)
    assert requests[0]["operation"] == "pair-capture"
    assert requests[0]["boot_id"] is requests[0]["inventory_sha256"] is None
    await channel.close()


@pytest.mark.anyio
@pytest.mark.parametrize(
    "fault",
    ["nonce", "digest", "node", "boot", "oversize", "redirect", "uids", "phase", "duplicate"],
)
async def test_response_substitution_redirect_or_excess_fails_closed(config, pair, fault):
    capture = report(
        {
            "node": "worker.test",
            "namespace": "sandboxes",
            "network": "private",
            "generation": str(pair.generation),
            "sandbox_id": str(pair.sandbox_id),
            "boot_id": None,
            "inventory_sha256": None,
        }
    )
    captured = decode_node_release(msgspec.json.encode(capture))

    def handler(request):
        value = json.loads(request.content)
        if fault == "redirect":
            return httpx2.Response(307, headers={"Location": "https://other.test"})
        result = report(
            value,
            leftovers={
                "pods": 0,
                "ready_sandboxes": 0,
                "live_containers": 0,
                "journals": 0,
                "host_links": 0,
                "process_namespace_references": 0,
            },
        )
        result["pod_uids"] = list(capture["pod_uids"])
        if fault == "node":
            result["node"] = "other.test"
        elif fault == "boot":
            result["boot_id"] = str(uuid4())
        elif fault == "uids":
            result["pod_uids"][0] = str(uuid4())
        elif fault == "phase":
            result["leftovers"] = None
            result["observed_runtime_released"] = False
        reply = {
            "schema": "ads-node-owner-v1",
            "nonce": value["nonce"],
            "request_sha256": hashlib.sha256(request.content).hexdigest(),
            "report": result,
        }
        if fault == "nonce":
            reply["nonce"] = str(uuid4())
        elif fault == "digest":
            reply["request_sha256"] = "0" * 64
        content = json.dumps(reply).encode()
        if fault == "oversize":
            content += b" " * 32769
        elif fault == "duplicate":
            content = b'{"schema":"ads-node-owner-v1",' + content[1:]
        return httpx2.Response(
            200, headers={"Content-Type": "application/json"}, stream=Stream(content)
        )

    channel = owner(config, handler)
    with pytest.raises((ValueError, RuntimeError)):
        await channel.observe(captured)
    await channel.close()


@pytest.mark.anyio
@pytest.mark.parametrize("interruption", ["timeout", "cancel"])
async def test_interrupted_call_is_not_retried_or_reported_success(config, pair, interruption):
    entered = asyncio.Event()
    calls = []

    async def handler(request):
        calls.append(request)
        entered.set()
        await asyncio.Event().wait()
        pytest.fail("interrupted request cannot return success")

    channel = owner(replace(config, timeout=0.05), handler)
    task = asyncio.create_task(channel.fence_and_capture(pair, node="worker.test"))
    await entered.wait()
    if interruption == "cancel":
        task.cancel()
    with pytest.raises(asyncio.CancelledError if interruption == "cancel" else TimeoutError):
        await task
    assert len(calls) == 1
    await channel.close()


@pytest.mark.parametrize(
    "change",
    [
        {"endpoints": {}},
        {"endpoints": {"worker": "http://worker"}},
        {"endpoints": {"worker": "https://user:pass@worker"}},
        {"timeout": float("inf")},
        {"timeout": 71},
        {"ca": Path("relative")},
    ],
)
def test_invalid_configuration_fails_before_transport(config, change):
    with pytest.raises(ValueError):
        NodeOwnerSettings(**{**config.__dict__, **change})


def test_unverified_tls_context_cannot_construct_production_channel(config):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with pytest.raises(ValueError, match="verified mutual TLS"):
        HttpsNodeOwner(config, context)
