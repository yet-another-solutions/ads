"""pair_lookup: G9 join-key lookup logic + record fidelity (unit-level)."""

from __future__ import annotations

from uuid import uuid4

import pytest

from ads_sandbox_manager.config import PairLookupSettings
from ads_sandbox_manager.pair_lookup import (
    CLIENT_CN,
    GATEWAY,
    PairLookup,
    binding_record,
    container_identity,
)

GEN = uuid4()
SANDBOX = uuid4()
SESSION = uuid4()
PROJECT = uuid4()
POD_UID = str(uuid4())
RELAY_UID = str(uuid4())
RUNTIME_ID = "a" * 64

MTU = 1420


def relay_payload(role: str) -> dict:
    local = "10.10.30.2/24" if role == "guest-relay" else "10.10.30.1/24"
    return {
        "runtime": {
            "image": "registry.example/relay@sha256:" + "0" * 64,
            "tls_secret": "ads-relay-tls",
            "transport_mtu": MTU + 110,
            "packet_rate": 10000,
            "cpu_millis": 1000,
            "memory_mib": 256,
            "startup_seconds": 90,
        },
        "public_keys": {"guest": "k" * 43, "egress": "k" * 43},
        "custody_uid": str(uuid4()),
        "pod_uids": {"guest-relay": RELAY_UID, "egress-relay": str(uuid4())},
        "service_uid": str(uuid4()),
        "service_ipv4": "10.96.0.20",
        "configuration": {
            "pod_uid": RELAY_UID,
            "generation": str(GEN),
            "sandbox_id": str(SANDBOX),
            "side": "guest" if role == "guest-relay" else "egress",
            "local_private": local,
            "peer_private": "10.10.30.1/24" if role == "guest-relay" else "10.10.30.2/24",
            "local_tunnel": "10.10.40.2/32",
            "peer_tunnel": "10.10.40.1/32",
            "transport_mtu": MTU + 110,
            "peer_key": "k" * 43,
            "endpoint": None,
            "wireguard_port": 51820,
            "vxlan_port": 4789,
            "vni": 42,
        },
    }


def intent_row(**over):
    from ads_sandbox_manager.pair_store import PairIntent

    base = dict(
        generation=GEN,
        session_id=SESSION,
        sandbox_id=SANDBOX,
        project_id=PROJECT,
        claim_owner=PROJECT,
        claim_changed="2026-10-04T00:00:00Z",
        namespace="ads-sandbox",
        golden_version="v1.2.3",
        retired_at=None,
        creation_fenced=False,
        cleanup_journal=None,
        compute_uids={"Pod/guest": POD_UID, "Pod/guest-relay": RELAY_UID},
        compute_payloads={},
        relay_inputs={
            "guest-relay": {
                "payload": relay_payload("guest-relay"),
                "uid": str(uuid4()),
                "dispatch": "issued",
            },
            "egress-relay": {
                "payload": relay_payload("egress-relay"),
                "uid": str(uuid4()),
                "dispatch": "issued",
            },
        },
        relay_custody={},
        control_uids={},
        volume_resources={},
        ipc_resources={},
        topics_dispatch="settled",
        egress_state_id=None,
    )
    base.update(over)
    return PairIntent(**base)


class FakeDB:
    def __init__(self, intent):
        self.intent = intent

    async def get(self, model, key):
        return self.intent if key == GEN else None


class FakeCore:
    def __init__(self, pods):
        self.pods = pods

    async def read_namespaced_pod(self, name, namespace=None):
        return self.pods.get(name)


class FakeKube:
    def __init__(self, pods):
        self.core = FakeCore(pods)

    async def _get(self, method, name, *a, **kw):
        return await method(name, *a, **kw)


def relay_pod(container_id: str | None = "containerd://" + RUNTIME_ID):
    status = {"containerStatuses": [{"name": "relay", "containerID": container_id}]}
    return {"status": status}


def fixture():
    """PairLookup with an in-memory settings object (no env needed)."""
    from ads_sandbox_manager.config import Settings

    settings = Settings(
        golden_version="v1.2.3",
        golden_image="registry.example/golden@sha256:" + "0" * 64,
        session_size="10Gi",
        database_url="postgresql+psycopg://invalid",
        kafka_bootstrap_servers="kafka:9092",
        tls_cert_path="/tls/tls.crt",
        tls_key_path="/tls/tls.key",
        pair_lookup=PairLookupSettings(),
    )
    return settings


@pytest.fixture
def anyio_backend():
    return "asyncio"


async def lookup_with(intent, pods, role="guest", pod_uid=POD_UID):
    settings = fixture()
    lookup = PairLookup(settings)
    status, body = await lookup.lookup(FakeDB(intent), FakeKube(pods), GEN, role, pod_uid)
    return status, body


def test_container_identity_strips_prefix():
    pod = relay_pod()
    assert container_identity(pod, "relay") == RUNTIME_ID
    assert container_identity(relay_pod("cri-o://" + RUNTIME_ID), "relay") == RUNTIME_ID


def test_container_identity_absent():
    assert container_identity(relay_pod(None), "relay") is None
    assert container_identity(relay_pod("  "), "relay") is None
    assert container_identity({"status": {}}, "relay") is None


def test_binding_record_guest():
    payload = relay_payload("guest-relay")
    record = binding_record(
        {
            "pod_uid": POD_UID,
            "generation": str(GEN),
            "sandbox_id": str(SANDBOX),
            "network": "ads-sandbox",
        },
        "guest",
        payload,
        RELAY_UID,
        RUNTIME_ID,
    )
    assert record == {
        "pod_uid": POD_UID,
        "generation": str(GEN),
        "sandbox_id": str(SANDBOX),
        "role": "guest",
        "network": "ads-sandbox",
        "relay_pod_uid": RELAY_UID,
        "relay_runtime_id": RUNTIME_ID,
        "mtu": MTU,
        # Bare IP, not the /24 from the configuration.
        "address": "10.10.30.2",
        "gateway": GATEWAY,
    }


def test_binding_record_egress_gateway_none():
    record = binding_record(
        {
            "pod_uid": POD_UID,
            "generation": str(GEN),
            "sandbox_id": str(SANDBOX),
            "network": "ads-sandbox",
        },
        "egress",
        relay_payload("egress-relay"),
        RELAY_UID,
        RUNTIME_ID,
    )
    assert record["address"] == "10.10.30.1"
    assert record["gateway"] is None


def test_settings_parse_rejects_unknown_keys():
    with pytest.raises(ValueError):
        PairLookupSettings.parse({"host": "h", "port": 1, "client_cn": "c", "extra": "x"})


def test_settings_parse_accepts_subset():
    parsed = PairLookupSettings.parse({"port": 9443})
    assert parsed == PairLookupSettings(host="0.0.0.0", port=9443, client_cn=CLIENT_CN)


def test_settings_defaults():
    defaults = PairLookupSettings()
    assert defaults == PairLookupSettings(host="0.0.0.0", port=8443, client_cn="ads-ptp-cni")


@pytest.mark.anyio
async def test_lookup_unknown_generation():
    status, body = await lookup_with(None, {}, role="guest")
    assert status == 404 and body == {}


@pytest.mark.anyio
async def test_lookup_retired_is_404():
    status, _ = await lookup_with(intent_row(retired_at="2026-10-04T00:00:00Z"), {})
    assert status == 404


@pytest.mark.anyio
async def test_lookup_foreign_namespace_404():
    status, _ = await lookup_with(intent_row(namespace="other-ns"), {})
    assert status == 404


@pytest.mark.anyio
async def test_lookup_relay_role_rejected():
    status, _ = await lookup_with(intent_row(), {}, role="guest-relay")
    assert status == 404


@pytest.mark.anyio
async def test_lookup_uid_mismatch_404():
    status, _ = await lookup_with(intent_row(), {}, pod_uid=str(uuid4()))
    assert status == 404


@pytest.mark.anyio
async def test_lookup_ready_before_uid_capture():
    # G9: join works without capture; pod_uid query param stands in.
    intent = intent_row(compute_uids={"Pod/guest-relay": RELAY_UID})
    pods = {"ads-guest-relay-" + str(SANDBOX): relay_pod()}
    status, body = await lookup_with(intent, pods, pod_uid=POD_UID)
    assert status == 200
    assert body["pod_uid"] == POD_UID and body["relay_pod_uid"] == RELAY_UID


@pytest.mark.anyio
async def test_lookup_missing_relay_inputs_503():
    intent = intent_row(
        relay_inputs={
            "guest-relay": {"payload": None, "uid": None, "dispatch": "unissued"},
            "egress-relay": {"payload": None, "uid": None, "dispatch": "unissued"},
        }
    )
    status, body = await lookup_with(intent, {})
    assert status == 503 and body == {"Retry-After": "1"}


@pytest.mark.anyio
async def test_lookup_no_relay_uid_503():
    status, _ = await lookup_with(intent_row(compute_uids={"Pod/guest": POD_UID}), {})
    assert status == 503


@pytest.mark.anyio
async def test_lookup_no_container_id_503():
    pods = {"ads-guest-relay-" + str(SANDBOX): relay_pod(None)}
    status, _ = await lookup_with(intent_row(), pods)
    assert status == 503


@pytest.mark.anyio
async def test_lookup_ready_200():
    status, body = await lookup_with(intent_row(), {"ads-guest-relay-" + str(SANDBOX): relay_pod()})
    assert status == 200
    assert body["mtu"] == MTU and body["address"] == "10.10.30.2" and body["gateway"] == GATEWAY
    assert body["relay_runtime_id"] == RUNTIME_ID
