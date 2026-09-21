"""Real ADS publisher -> IPC JWT boundary -> HTTPS adapter -> egress receiver.

Broker transport, local health and service-token acquisition are fixtures. This
is component integration, not live Kafka/Keycloak/TLS/network acceptance.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx2
import pytest

from ads.egress_kafka import EgressKafka
from ads_commons.egress import ProjectEgressSettings, ProjectEgressSnapshot
from ads_commons_beans import JwtVerifier, JwtVerifierSettings
from ads_sandbox_egress.app import create_app
from ads_sandbox_egress.configuration import PairIdentity, PolicyStore
from ads_sandbox_ipc.controller import KafkaController
from ads_sandbox_ipc.egress import EgressDelivery, RevisionFloor
from ads_sandbox_ipc.egress_transport import HttpsEgressTransport
from test_configuration_receiver import Health, Keys


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_published_snapshot_reaches_receiver_and_restart_mints_again(tmp_path, monkeypatch):
    ads_subject, ipc_subject = uuid4(), uuid4()
    pair = PairIdentity(uuid4(), uuid4(), ipc_subject)
    keys, store, health = Keys(ipc_subject), PolicyStore(), Health()
    current_app = [create_app(pair, store, health, keys.verifier)]
    real_client = httpx2.AsyncClient

    def in_process_client(**kwargs):
        # Preserve production URLs/serialization/auth; replace only the network socket.
        return real_client(transport=httpx2.ASGITransport(app=current_app[0]), **kwargs)

    monkeypatch.setattr(httpx2, "AsyncClient", in_process_client)
    ipc_tokens = SimpleNamespace(calls=[])
    ads_tokens = SimpleNamespace(calls=[])

    def mint_ipc(audience):
        ipc_tokens.calls.append(audience)
        return keys.token(jti=str(uuid4()))

    def mint_ads(audience):
        ads_tokens.calls.append(audience)
        return keys.token(aud=audience, azp="ads", sub=str(ads_subject), jti=str(uuid4()))

    ipc_tokens.exchange_service = mint_ipc
    ads_tokens.exchange_service = mint_ads
    transport = HttpsEgressTransport(
        "https://egress.test",
        ("https://local.test/health", "https://peer.test/health"),
        ipc_tokens,
        None,
    )
    transport.relays_healthy = AsyncMock(return_value=True)
    delivery = EgressDelivery(pair.project_id, RevisionFloor(tmp_path, pair.project_id), transport)
    ipc_verifier = JwtVerifier(
        JwtVerifierSettings(
            "https://identity.test",
            "ads-sandbox-ipc",
            "ads-sandbox-ipc",
            "https://identity.test/jwks",
            None,
        ),
        keys,
    )
    settings = SimpleNamespace(
        egress=SimpleNamespace(project_id=pair.project_id, ads_service_subject=ads_subject)
    )
    ipc = KafkaController(settings, ipc_verifier, SimpleNamespace(egress=delivery))
    records = []

    async def send(topic, *, key, value, headers):
        records.append((topic, key, value, headers))
        await ipc.on_message(topic, value, headers)

    publisher = EgressKafka(SimpleNamespace(), ads_tokens)
    publisher.producer = SimpleNamespace(send_and_wait=send)
    publisher.started = True
    try:
        await publisher.publish(
            pair.project_id, ProjectEgressSnapshot(3, ProjectEgressSettings(rules=()))
        )
        assert store.capture().revision == 3 and delivery.installed.instance_id == store.instance_id
        assert delivery.ever_installed.is_set()
        assert ads_tokens.calls == ["ads-sandbox-ipc"]
        assert ipc_tokens.calls == ["ads-sandbox-egress"]
        original = store
        store = PolicyStore()
        current_app[0] = create_app(pair, store, health, keys.verifier)
        assert store.capture() is None
        assert await delivery.healthy()
        assert delivery.ever_installed.is_set()  # No post-start execution gate is revoked.
        await delivery._reapply
        assert store.capture().revision == 3
        assert delivery.installed.instance_id == store.instance_id != original.instance_id
        assert ipc_tokens.calls == ["ads-sandbox-egress"] * 2
        assert len(records) == 1  # Restart repair did not replay/cache a Kafka bearer.
        await publisher.publish(
            pair.project_id, ProjectEgressSnapshot(2, ProjectEgressSettings(rules=()))
        )
        assert store.capture().revision == 3 and not delivery.failed
        assert len(ipc_tokens.calls) == 2  # Durable revision floor rejected the old snapshot.
    finally:
        await delivery.close()
