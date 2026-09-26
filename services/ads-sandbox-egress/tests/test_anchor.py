from uuid import uuid4

import msgspec
import pytest
from litestar.testing import AsyncTestClient

from ads_commons.egress import EgressDNSAnchor
from ads_sandbox_egress.app import create_app
from ads_sandbox_egress.configuration import PairIdentity, PolicyStore
from test_configuration_receiver import Health, Keys


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "case", ["valid", "missing", "subject", "caller", "audience", "unavailable"]
)
async def test_public_anchor_requires_exact_ipc_service_identity(case):
    pair = PairIdentity(uuid4(), uuid4(), uuid4())
    keys = Keys(pair.ipc_service_subject)
    anchor = EgressDNSAnchor(pair.project_id, pair.sandbox_id, "a" * 64, "257 3 15 test")
    changes = {
        "subject": {"sub": str(uuid4())},
        "caller": {"azp": "ads"},
        "audience": {"aud": "ads"},
    }.get(case, {})
    async with AsyncTestClient(
        create_app(
            pair,
            PolicyStore(),
            Health(),
            keys.verifier,
            None if case == "unavailable" else anchor,
        )
    ) as client:
        response = await client.get(
            "/dnssec-anchor",
            headers={}
            if case == "missing"
            else {"Authorization": "Bearer " + keys.token(**changes)},
        )
        assert (
            response.status_code
            == {
                "valid": 200,
                "missing": 401,
                "subject": 403,
                "caller": 403,
                "audience": 401,
                "unavailable": 503,
            }[case]
        )
        if case == "valid":
            assert msgspec.json.decode(response.content, type=EgressDNSAnchor) == anchor
            assert set(response.json()) == {"project_id", "sandbox_id", "fingerprint", "dnskey"}
