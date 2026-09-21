from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace
from uuid import uuid4

import jwt
import msgspec
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from litestar.testing import AsyncTestClient

from ads_commons.egress import EgressApply, ProjectEgressSettings, ProjectEgressSnapshot
from ads_commons_beans import JwtVerifier, JwtVerifierSettings
from ads_sandbox_egress.app import create_app
from ads_sandbox_egress.configuration import (
    ConfigurationService,
    ConfigurationUnavailable,
    PairIdentity,
    PolicyStore,
    RevisionConflict,
    StaleConfiguration,
)


@pytest.fixture
def anyio_backend():
    return "asyncio"


class Keys:
    def __init__(self, subject):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.subject = subject
        self.verifier = JwtVerifier(
            JwtVerifierSettings(
                issuer="https://identity.test",
                audience="ads-sandbox-egress",
                client_id="ads-sandbox-egress",
                jwks_uri="https://identity.test/jwks",
                ssl_context=None,
            ),
            self,
        )

    def get_signing_key_from_jwt(self, token):
        return SimpleNamespace(key=self.key.public_key())

    def token(self, **changes):
        return jwt.encode(
            {
                "sub": str(self.subject),
                "iss": "https://identity.test",
                "aud": "ads-sandbox-egress",
                "azp": "ads-sandbox-ipc",
                "iat": int(time.time()),
                "exp": int(time.time()) + 600,
                **changes,
            },
            self.key,
            algorithm="RS256",
        )


class Health:
    def __init__(self):
        self.result = True
        self.error = None
        self.pause = None
        self.calls = 0

    async def healthy(self):
        self.calls += 1
        if self.pause is not None:
            await self.pause.wait()
        if self.error is not None:
            raise self.error
        return self.result


def snapshot(revision, mode="whitelist"):
    return ProjectEgressSnapshot(revision, ProjectEgressSettings(mode=mode, rules=()))


def payload(pair, revision=1, mode="whitelist"):
    return msgspec.json.encode(EgressApply(pair.project_id, snapshot(revision, mode)))


@pytest.fixture
def receiver():
    pair = PairIdentity(uuid4(), uuid4(), uuid4(), 0.03)
    keys, store, health = Keys(pair.ipc_service_subject), PolicyStore(), Health()
    return SimpleNamespace(
        pair=pair,
        keys=keys,
        store=store,
        health=health,
        app=create_app(pair, store, health, keys.verifier),
    )


@pytest.mark.anyio
async def test_fresh_process_health_and_atomic_revision_outcomes(receiver):
    r = receiver
    assert r.store.capture() is None
    async with AsyncTestClient(r.app) as client:
        ping = await client.get("/ping")
        assert ping.status_code == 200 and ping.json()["healthy"]
        instance = ping.json()["instance_id"]
        assert r.store.capture() is None  # Health proves update capability, not convergence.
        headers = {"Authorization": "Bearer " + r.keys.token()}
        first = await client.put("/configuration", content=payload(r.pair, 7), headers=headers)
        assert first.status_code == 200
        assert first.json() == {"instance_id": instance, "revision": 7}
        captured = r.store.capture()
        again = await client.put("/configuration", content=payload(r.pair, 7), headers=headers)
        assert again.json() == first.json() and r.store.capture() is captured
        stale = await client.put("/configuration", content=payload(r.pair, 6), headers=headers)
        assert stale.status_code == 409
        assert stale.json() == {
            "error": {"code": "stale_revision", "received_revision": 6, "applied_revision": 7}
        }
        conflict = await client.put(
            "/configuration", content=payload(r.pair, 7, "blacklist"), headers=headers
        )
        assert (
            conflict.status_code == 409 and conflict.json()["error"]["code"] == "revision_conflict"
        )
        assert r.store.capture() is captured
        new = await client.put(
            "/configuration", content=payload(r.pair, 8, "blacklist"), headers=headers
        )
        assert new.status_code == 200 and new.json()["instance_id"] == instance
        assert r.store.capture().revision == 8
        assert captured.revision == 7 and captured.settings.mode == "whitelist"
    assert not r.store.accepting
    fresh = PolicyStore()
    assert fresh.instance_id != r.store.instance_id and fresh.capture() is None
    assert (await fresh.install(snapshot(8))).revision == 8


@pytest.mark.anyio
@pytest.mark.parametrize(
    "claims,status",
    [
        ({"aud": "ads"}, 401),
        ({"iss": "https://foreign.test"}, 401),
        ({"exp": 1}, 401),
        ({"sub": "not-uuid"}, 401),
        ({"sub": str(uuid4())}, 403),
        ({"azp": "ads"}, 403),
    ],
)
async def test_verified_native_service_identity_before_mutation(receiver, claims, status):
    r = receiver
    async with AsyncTestClient(r.app) as client:
        response = await client.put(
            "/configuration",
            content=payload(r.pair),
            headers={"Authorization": "Bearer " + r.keys.token(**claims)},
        )
        assert response.status_code == status
        assert r.store.capture() is None


@pytest.mark.anyio
async def test_missing_bearer_foreign_project_and_invalid_body(receiver):
    r = receiver
    async with AsyncTestClient(r.app) as client:
        for authorization in ("", "Basic fixture", "Bearer "):
            assert (
                await client.put(
                    "/configuration",
                    content=payload(r.pair),
                    headers={"Authorization": authorization},
                )
            ).status_code == 401
        headers = {"Authorization": "Bearer " + r.keys.token()}
        foreign = EgressApply(uuid4(), snapshot(1))
        assert (
            await client.put(
                "/configuration", content=msgspec.json.encode(foreign), headers=headers
            )
        ).status_code == 403
        for body in (b"invalid", b"{}", payload(r.pair, 0), payload(r.pair, -1)):
            assert (
                await client.put("/configuration", content=body, headers=headers)
            ).status_code == 400
        assert (
            await client.post("/configuration", content=payload(r.pair), headers=headers)
        ).status_code == 405
        assert r.store.capture() is None


@pytest.mark.anyio
@pytest.mark.parametrize("failure", ["false", "error", "timeout", "closed"])
async def test_ping_is_bounded_local_health_and_not_a_revision_check(receiver, failure):
    r = receiver
    if failure == "false":
        r.health.result = False
    if failure == "error":
        r.health.error = RuntimeError("local helper down")
    if failure == "timeout":
        r.health.pause = asyncio.Event()
    async with AsyncTestClient(r.app) as client:
        if failure == "closed":
            await r.store.close()
        async with asyncio.timeout(1):
            response = await client.get("/ping")
        assert response.status_code == 503
        assert response.json() == {"instance_id": str(r.store.instance_id), "healthy": False}
        if failure == "closed":
            response = await client.put(
                "/configuration",
                content=payload(r.pair),
                headers={"Authorization": "Bearer " + r.keys.token()},
            )
            assert response.status_code == 503
        assert r.store.capture() is None


@pytest.mark.anyio
async def test_concurrent_revisions_never_regress_and_old_exchange_keeps_snapshot():
    store = PolicyStore()
    await store.install(snapshot(1))
    active = store.capture()
    results = await asyncio.gather(
        *(store.install(snapshot(revision)) for revision in (4, 2, 7, 5, 8, 3, 8)),
        return_exceptions=True,
    )
    assert store.capture().revision == 8
    assert sum(isinstance(result, StaleConfiguration) for result in results) == 3
    assert [result.revision for result in results if not isinstance(result, Exception)] == [
        4,
        7,
        8,
        8,
    ]
    assert active.revision == 1
    with pytest.raises(RevisionConflict):
        await store.install(snapshot(8, "blacklist"))
    await store.close()
    with pytest.raises(ConfigurationUnavailable):
        await store.install(snapshot(9))
    assert store.capture().revision == 8


@pytest.mark.anyio
async def test_same_revision_semantic_defaults_are_idempotent():
    store = PolicyStore()
    raw = {
        "revision": 1,
        "settings": {
            "mode": "blacklist",
            "rules": [
                {
                    "domain": "*.example.com",
                    "port": 443,
                    "protocol": "https",
                    "protocol_settings": {
                        "method": "any",
                        "upgrades": ["websocket", "http/2"],
                        "paths": [{"pattern": "/A/*"}],
                    },
                }
            ],
        },
    }
    first = msgspec.convert(raw, type=ProjectEgressSnapshot)
    await store.install(first)
    captured = store.capture()
    raw["settings"]["rules"][0]["protocol_settings"]["upgrades"].reverse()
    raw["settings"]["rules"][0]["protocol_settings"]["paths"][0]["case_insensitive"] = True
    await store.install(msgspec.convert(raw, type=ProjectEgressSnapshot))
    assert store.capture() is captured


@pytest.mark.anyio
async def test_health_cancellation_propagates(receiver):
    r = receiver
    r.health.pause = asyncio.Event()
    service = ConfigurationService(r.pair, r.store, r.health)
    task = asyncio.create_task(service.ping())
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
