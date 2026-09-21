from __future__ import annotations

from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import httpx2
import msgspec
import pytest

from ads_commons.egress import (
    EgressApplied,
    EgressApply,
    ProjectEgressSettings,
    ProjectEgressSnapshot,
)
from ads_sandbox_ipc.egress import StaleRevision
from ads_sandbox_ipc.egress_transport import HttpsEgressTransport


def setup():
    tokens = Mock()
    tokens.exchange_service.side_effect = ["fresh-1", "fresh-2"]
    transport = HttpsEgressTransport(
        "https://egress.test",
        ("https://local.test/health", "https://peer.test/health"),
        tokens,
        None,
    )
    return (
        transport,
        tokens,
        EgressApply(uuid4(), ProjectEgressSnapshot(3, ProjectEgressSettings(rules=()))),
    )


@pytest.mark.anyio
async def test_apply_fresh_credentials_and_actual_response_uuid(monkeypatch):
    transport, tokens, body = setup()
    expected = EgressApplied(uuid4(), 3)
    put = AsyncMock(return_value=httpx2.Response(200, content=msgspec.json.encode(expected)))
    monkeypatch.setattr(httpx2.AsyncClient, "put", put)
    assert await transport.apply(body) == expected
    assert await transport.apply(body) == expected
    assert tokens.exchange_service.call_count == 2
    assert [c.kwargs["headers"]["Authorization"] for c in put.call_args_list] == [
        "Bearer fresh-1",
        "Bearer fresh-2",
    ]


@pytest.mark.anyio
@pytest.mark.parametrize(
    "status,payload,stale",
    [
        (
            409,
            {"error": {"code": "stale_revision", "received_revision": 3, "applied_revision": 4}},
            True,
        ),
        (
            409,
            {"error": {"code": "conflict", "received_revision": 3, "applied_revision": 4}},
            False,
        ),
        (
            409,
            {"error": {"code": "stale_revision", "received_revision": 2, "applied_revision": 4}},
            False,
        ),
        (
            409,
            {"error": {"code": "stale_revision", "received_revision": 3, "applied_revision": 3}},
            False,
        ),
        (409, {"error": "stale_revision"}, False),
        (500, {}, False),
    ],
)
async def test_only_exact_matching_stale_response_is_nonfatal(monkeypatch, status, payload, stale):
    transport, _, body = setup()
    monkeypatch.setattr(
        httpx2.AsyncClient,
        "put",
        AsyncMock(return_value=httpx2.Response(status, content=msgspec.json.encode(payload))),
    )
    with pytest.raises(StaleRevision if stale else ValueError):
        await transport.apply(body)


@pytest.mark.parametrize(
    "url", ["http://egress.test", "https://user:secret@egress.test", "https://a/#b"]
)
def test_immutable_pair_urls_require_https_without_credentials(url):
    with pytest.raises(ValueError):
        HttpsEgressTransport(url, ("https://a/health", "https://b/health"), Mock(), None)
