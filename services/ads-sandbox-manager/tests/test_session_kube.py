from __future__ import annotations

from unittest.mock import Mock
from uuid import uuid4

import pytest
from dishka import Provider, Scope, make_async_container, provide
from kubernetes.client.exceptions import ApiException
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ads_sandbox_manager.ioc import AppProvider
from ads_sandbox_manager.kube import KubeClient, Kubernetes, SessionKubernetes
from ads_sandbox_manager.session_objects import guest_deployment, ipc_name, session_name
from ads_sandbox_manager.store import SessionRepository
from test_session_objects import object_settings  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.fixture
def session_api(object_settings, monkeypatch):  # noqa: F811
    def configure(*, client_configuration):
        client_configuration.host = "https://kubernetes.test"
        client_configuration.verify_ssl = True

    monkeypatch.setattr("ads_sandbox_manager.kube.config.load_incluster_config", configure)
    kube = KubeClient(object_settings)
    kube.core = Mock()
    kube.apps = Mock()
    kube.core.read_namespaced_persistent_volume_claim.return_value = {"metadata": {"uid": "disk"}}
    kube.apps.read_namespaced_deployment.return_value = {"metadata": {"uid": "compute"}}
    kube.apps.create_namespaced_deployment.return_value = {}
    yield kube
    kube.api_client.close()


async def test_named_gets_and_create_use_only_configured_namespace(session_api, object_settings):  # noqa: F811
    kube, sid, sandbox = session_api, uuid4(), uuid4()
    assert (await kube.named_pvc(session_name(sid)))["metadata"]["uid"] == "disk"
    assert (await kube.deployment(ipc_name(sandbox)))["metadata"]["uid"] == "compute"
    kube.core.read_namespaced_persistent_volume_claim.assert_called_once_with(
        session_name(sid),
        object_settings.namespace,
        _request_timeout=0.1,
    )
    kube.apps.read_namespaced_deployment.assert_called_once_with(
        ipc_name(sandbox),
        object_settings.namespace,
        _request_timeout=0.1,
    )
    body = guest_deployment(object_settings, sid, sandbox, object_settings.golden_version)
    await kube.create_deployment(body)
    kube.apps.create_namespaced_deployment.assert_called_once_with(
        object_settings.namespace,
        body,
        _request_timeout=0.1,
    )
    kube.core.list_namespaced_persistent_volume_claim.assert_not_called()
    kube.core.delete_namespaced_persistent_volume_claim.assert_not_called()
    kube.core.patch_namespaced_persistent_volume_claim.assert_not_called()
    kube.core.connect_get_namespaced_pod_exec.assert_not_called()


@pytest.mark.parametrize("status", [404, 403, 409, 500])
async def test_named_reads_only_treat_404_as_absent(session_api, status):
    session_api.core.read_namespaced_persistent_volume_claim.side_effect = ApiException(
        status=status,
    )
    session_api.apps.read_namespaced_deployment.side_effect = ApiException(status=status)
    for read in (session_api.named_pvc, session_api.deployment):
        if status == 404:
            assert await read("ads-sandbox-fixture") is None
        else:
            with pytest.raises(ApiException) as error:
                await read("ads-sandbox-fixture")
            assert error.value.status == status


async def test_create_conflict_is_not_retried_by_adapter(session_api):
    session_api.apps.create_namespaced_deployment.side_effect = ApiException(status=409)
    with pytest.raises(ApiException):
        await session_api.create_deployment({"metadata": {"name": "fixture"}})
    session_api.apps.create_namespaced_deployment.assert_called_once()


async def test_dishka_shares_client_and_supplies_durable_repository(session_api, object_settings):  # noqa: F811
    class Overrides(Provider):
        @provide(scope=Scope.APP, override=True)
        def kube(self) -> KubeClient:
            return session_api

    container = make_async_container(AppProvider(object_settings), Overrides())
    try:
        assert await container.get(Kubernetes) is session_api
        assert await container.get(SessionKubernetes) is session_api
        assert isinstance(await container.get(SessionRepository), SessionRepository)
        factory = await container.get(async_sessionmaker[AsyncSession])
        assert factory.kw["expire_on_commit"] is False
    finally:
        await container.close()
