# ruff: noqa: F811
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import UUID, uuid4

import httpx2
import msgspec
import pytest
from dishka import Provider, Scope, provide
from litestar.testing import AsyncTestClient

from ads_commons.egress import SessionProjectBinding
from ads_commons.security import AccessDenied, SecurityContext, SecurityContextHolder
from ads_commons_beans import JwtVerifier
from ads_sandbox_manager.app import create_app
from ads_sandbox_manager.binding import AdsSessionProjects, BindingService
from ads_sandbox_manager.runtime import ManagerRuntime
from ads_sandbox_manager.sessions import SessionBindError
from test_manager_security import keys  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import seed, sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


def context(subject, caller="ads"):
    return SecurityContext(
        subject=str(subject), name="ads", roles=frozenset(), authorized_party=caller
    )


@pytest.mark.parametrize(
    "status,eligible",
    [
        ("pending", True),
        ("creating", True),
        ("ready", True),
        ("stopped", False),
        ("shutting_down", False),
        ("recovering", False),
        ("service", False),
        ("failed", False),
    ],
)
async def test_binding_available_before_ready_and_fences_lifecycle(
    sessions_harness, status, eligible
):
    h, subject = sessions_harness, uuid4()
    row = await seed(h, uuid4(), status=status)
    service = BindingService(
        replace(h.settings, ads_service_subject=subject), h.sessions, h.repository
    )
    with SecurityContextHolder.bound(context(subject)):
        binding = await service.get(row.sandbox_id)
        assert binding.eligible is eligible
        assert binding.project_id == h.projects.project
        assert binding.session_id == row.session_id
        assert await service.get(uuid4()) is None
    for identity in (context(uuid4()), context(subject, "ads-sandbox-ipc")):
        with SecurityContextHolder.bound(identity), pytest.raises(AccessDenied):
            await service.get(row.sandbox_id)


async def test_provisioning_persists_project_before_first_object_and_rejects_rebinding(
    sessions_harness,
):
    h, sid = sessions_harness, uuid4()

    async def inspect(sandbox):
        async with h.sessions.begin() as db:
            row = await h.repository.by_sandbox(db, sandbox)
            assert row.project_id == h.projects.project

    h.topics.hook = inspect
    row = await h.service.provision(sid)
    assert row.project_id == h.projects.project
    calls = list(h.kube.calls)
    h.projects.project = uuid4()
    with pytest.raises(SessionBindError, match="project changed"):
        await h.service.provision(sid)
    assert h.kube.calls == calls


async def test_failed_project_lookup_creates_nothing(sessions_harness):
    h = sessions_harness

    async def failed(session_id):
        raise RuntimeError("unavailable")

    h.projects.session_project = failed
    sid = uuid4()
    with pytest.raises(RuntimeError):
        await h.service.provision(sid)
    async with h.sessions.begin() as db:
        assert await h.repository.get(db, sid) is None
    assert h.kube.calls == []


async def test_binding_http_verifies_jwt_and_remains_available_before_ready(sessions_harness, keys):
    h = sessions_harness
    row = await seed(h, uuid4(), status="creating")
    settings = replace(h.settings, ads_service_subject=UUID(keys.subject))
    service = BindingService(settings, h.sessions, h.repository)

    class Overrides(Provider):
        @provide(scope=Scope.APP, override=True)
        def verifier(self) -> JwtVerifier:
            return keys.verifier

        @provide(scope=Scope.APP, override=True)
        def bindings(self) -> BindingService:
            return service

        @provide(scope=Scope.APP, override=True)
        def runtime(self) -> ManagerRuntime:
            return SimpleNamespace(ready=False, start=AsyncMock(), stop=AsyncMock())

    async with AsyncTestClient(create_app(settings, overrides=(Overrides(),))) as client:
        path = f"/v1/sandboxes/{row.sandbox_id}/binding"
        assert (await client.get("/health/ready")).status_code == 503
        assert (await client.get(path)).status_code == 401
        for changes, status in [
            ({"aud": "ads"}, 401),
            ({"iss": "https://foreign.test"}, 401),
            ({"exp": 1}, 401),
            ({"sub": "not-uuid"}, 401),
            ({"sub": str(uuid4())}, 403),
            ({"azp": "ads-sandbox-ipc"}, 403),
        ]:
            token = keys.token(**{"azp": "ads", **changes})
            assert (
                await client.get(path, headers={"Authorization": f"Bearer {token}"})
            ).status_code == status
        headers = {"Authorization": "Bearer " + keys.token(azp="ads")}
        result = await client.get(path, headers=headers)
        assert result.status_code == 200 and result.json()["eligible"]
        assert result.json()["project_id"] == str(h.projects.project)
        assert (await client.post(path, headers=headers)).status_code == 405
        assert (
            await client.get(f"/v1/sandboxes/{uuid4()}/binding", headers=headers)
        ).status_code == 404


async def test_manager_fetches_project_with_fresh_own_token_each_time(
    manager_settings, monkeypatch
):
    sid, project = uuid4(), uuid4()
    binding = SessionProjectBinding(sid, project)
    get = AsyncMock(return_value=httpx2.Response(200, content=msgspec.json.encode(binding)))
    monkeypatch.setattr(httpx2.AsyncClient, "get", get)
    tokens = Mock()
    tokens.exchange_service.side_effect = ["fresh-one", "fresh-two", "fresh-three"]
    client = AdsSessionProjects(manager_settings, tokens, None)
    for _ in range(2):
        assert await client.session_project(sid) == binding
    assert [c.kwargs["headers"]["Authorization"] for c in get.call_args_list] == [
        "Bearer fresh-one",
        "Bearer fresh-two",
    ]
    get.return_value = httpx2.Response(
        200, content=msgspec.json.encode(SessionProjectBinding(uuid4(), project))
    )
    with pytest.raises(RuntimeError, match="mismatch"):
        await client.session_project(sid)
    assert tokens.exchange_service.call_count == 3
