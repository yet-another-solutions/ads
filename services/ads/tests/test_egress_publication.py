from __future__ import annotations

import asyncio
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import httpx2
import msgspec
import pytest

from ads.egress import EgressRequestService, ManagerBindings, SessionProjectService
from ads.egress_controller import EgressRequestController
from ads.egress_kafka import EgressKafka
from ads.ioc import session_factory_for
from ads.preferences_client import PreferencesClient
from ads_commons.egress import (
    EGRESS_CONFIG_TOPIC,
    EgressConfigRequest,
    EgressConfigUpdate,
    ProjectEgressSettings,
    ProjectEgressSnapshot,
    SandboxProjectBinding,
)
from ads_commons.security import (
    AccessDenied,
    InvalidAccessToken,
    SecurityContext,
    SecurityContextHolder,
)
from tests.threadline_fakes import FakeTokens, RecordingEgress, login
from tests.threadline_flows import create_project, create_session


def identity(subject, caller="ads-sandbox-ipc"):
    return SecurityContext(
        subject=str(subject), name="service", roles=frozenset(), authorized_party=caller
    )


def test_publication_uses_saved_snapshot_and_reports_failure(client, app, preferences):
    login(client)
    project = create_project(client)
    path = f"/projects/{project}/egress-settings"
    updates = app.state.egress_updates
    assert updates.updates == []  # No sandbox can exist during project initialization.
    body = {"settings": '{"mode":"blacklist","rules":[]}'}
    response = client.post(path, data=body)
    assert response.status_code == 200
    assert "update published" in response.text and "applied to all" not in response.text
    assert updates.updates == [(project, preferences.egress[project])]
    updates.failed = True
    response = client.post(path, data=body)
    assert response.status_code == 503
    assert response.headers["X-ADS-Egress-Saved"] == "true"
    assert "Settings saved, but update publication failed" in response.text
    assert preferences.egress[project].revision == 3
    assert len(updates.updates) == 1


def test_manager_read_requires_bearer_and_exact_native_service(client, app, settings, db_engine):
    login(client)
    project = create_project(client)
    session = create_session(client, project)
    path = f"/internal/sessions/{session}/project"
    assert client.get(path).status_code == 401  # A valid browser cookie is insufficient.
    subject = uuid4()
    service = SessionProjectService(
        replace(settings, manager_service_subject=subject), session_factory_for(db_engine)
    )
    with SecurityContextHolder.bound(identity(subject, "ads-sandbox-manager")):
        binding = asyncio.run(service.for_manager(session))
        assert binding.session_id == session and binding.project_id == project
    for context in (identity(uuid4(), "ads-sandbox-manager"), identity(subject, "ads")):
        with SecurityContextHolder.bound(context), pytest.raises(AccessDenied):
            asyncio.run(service.for_manager(session))


@pytest.mark.parametrize(
    "failure", ["subject", "caller", "retired", "sandbox", "project", "owner", "lookup", "read"]
)
def test_bad_startup_binding_cannot_publish(settings, failure):
    subject, project, session, sandbox = (uuid4() for _ in range(4))
    message = EgressConfigRequest(project, sandbox)
    binding = SandboxProjectBinding(sandbox, session, project, True)
    if failure == "retired":
        binding = msgspec.structs.replace(binding, eligible=False)
    if failure in ("sandbox", "project"):
        binding = msgspec.structs.replace(binding, **{failure + "_id": uuid4()})
    projects = Mock(spec=SessionProjectService)
    projects.project.return_value = uuid4() if failure == "owner" else project
    bindings = SimpleNamespace(sandbox_binding=AsyncMock(return_value=binding))
    preferences = SimpleNamespace(get_egress_for_startup=AsyncMock())
    if failure == "lookup":
        bindings.sandbox_binding.side_effect = RuntimeError()
    if failure == "read":
        preferences.get_egress_for_startup.side_effect = RuntimeError()
    updates = RecordingEgress()
    service = EgressRequestService(
        replace(settings, ipc_service_subject=subject), projects, bindings, preferences, updates
    )
    context = identity(
        uuid4() if failure == "subject" else subject,
        "ads" if failure == "caller" else "ads-sandbox-ipc",
    )
    with SecurityContextHolder.bound(context), pytest.raises((AccessDenied, RuntimeError)):
        asyncio.run(service.request(message))
    assert updates.updates == []
    if failure in ("subject", "caller"):
        bindings.sandbox_binding.assert_not_awaited()


def test_startup_uses_binding_then_service_read_then_project_fanout(settings):
    subject, project, session, sandbox = (uuid4() for _ in range(4))
    projects = Mock(spec=SessionProjectService)
    projects.project.return_value = project
    bindings = SimpleNamespace(
        sandbox_binding=AsyncMock(
            return_value=SandboxProjectBinding(sandbox, session, project, True)
        )
    )
    snapshot = ProjectEgressSnapshot(7, ProjectEgressSettings(rules=()))
    preferences = SimpleNamespace(get_egress_for_startup=AsyncMock(return_value=snapshot))
    updates = RecordingEgress()
    service = EgressRequestService(
        replace(settings, ipc_service_subject=subject), projects, bindings, preferences, updates
    )
    with SecurityContextHolder.bound(identity(subject)):
        asyncio.run(service.request(EgressConfigRequest(project, sandbox)))
    projects.project.assert_called_once_with(session)
    assert updates.updates == [(project, snapshot)]


@pytest.mark.parametrize("token", [None, "", "expired", "forwarded"])
def test_kafka_boundary_drops_missing_or_invalid_bearer(token):
    service = SimpleNamespace(request=AsyncMock())
    verifier = Mock()
    verifier.authenticate.side_effect = InvalidAccessToken("invalid")
    controller = EgressRequestController(verifier, service)
    headers = [] if token is None else [("authorization", token.encode())]
    asyncio.run(
        controller.on_record(msgspec.json.encode(EgressConfigRequest(uuid4(), uuid4())), headers)
    )
    service.request.assert_not_awaited()


def test_kafka_boundary_binds_verifier_identity_and_ignores_update_role():
    subject = uuid4()
    context = identity(subject)
    contexts = []

    async def request(message):
        contexts.append(SecurityContextHolder.require())

    verifier = Mock()
    verifier.authenticate.return_value = context
    controller = EgressRequestController(verifier, SimpleNamespace(request=request))
    message = EgressConfigRequest(uuid4(), uuid4())
    asyncio.run(
        controller.on_record(msgspec.json.encode(message), [("authorization", b"verified")])
    )
    assert contexts == [context]
    verifier.reset_mock()
    update = EgressConfigUpdate(uuid4(), ProjectEgressSnapshot(1, ProjectEgressSettings(rules=())))
    asyncio.run(controller.on_record(msgspec.json.encode(update), [("authorization", b"anything")]))
    verifier.authenticate.assert_not_called()


def test_background_clients_mint_fresh_service_tokens_not_user_tokens(settings, monkeypatch):
    tokens = FakeTokens()
    project, sandbox = uuid4(), uuid4()
    snapshot = ProjectEgressSnapshot(1, ProjectEgressSettings(rules=()))
    binding = SandboxProjectBinding(sandbox, uuid4(), project, True)
    request = AsyncMock(return_value=httpx2.Response(200, content=msgspec.json.encode(snapshot)))
    get = AsyncMock(return_value=httpx2.Response(200, content=msgspec.json.encode(binding)))
    monkeypatch.setattr(httpx2.AsyncClient, "request", request)
    monkeypatch.setattr(httpx2.AsyncClient, "get", get)
    preferences = PreferencesClient(settings, tokens)
    manager = ManagerBindings(settings, tokens)
    for _ in range(2):
        assert asyncio.run(preferences.get_egress_for_startup(project)) == snapshot
        assert asyncio.run(manager.sandbox_binding(sandbox)) == binding
    assert (
        tokens.calls
        == [
            ("ads-preferences", "fresh-own-service-token"),
            ("ads-sandbox-manager", "fresh-own-service-token"),
        ]
        * 2
    )


def test_publication_mints_each_time_and_carries_canonical_persisted_revision(settings):
    async def run():
        tokens = FakeTokens()
        runtime = EgressKafka(settings, tokens)
        runtime.started = True
        runtime.producer = SimpleNamespace(send_and_wait=AsyncMock())
        snapshot = ProjectEgressSnapshot(6, ProjectEgressSettings(rules=()))
        project = uuid4()
        for _ in range(2):
            await runtime.publish(project, snapshot)
        assert tokens.calls == [("ads-sandbox-ipc", "fresh-own-service-token")] * 2
        for call in runtime.producer.send_and_wait.call_args_list:
            assert call.args == (EGRESS_CONFIG_TOPIC,)
            assert call.kwargs["key"] == str(project).encode()
            assert (
                msgspec.json.decode(call.kwargs["value"], type=EgressConfigUpdate).snapshot
                == snapshot
            )
        runtime.failed = True
        with pytest.raises(RuntimeError):
            await runtime.publish(project, snapshot)
        assert len(tokens.calls) == 2

    asyncio.run(run())


def test_broker_transport_requires_credentials_and_never_exposes_password(settings):
    secured = replace(
        settings,
        kafka_security_protocol="SASL_PLAINTEXT",
        kafka_sasl_username="fixture-ads",
        kafka_sasl_password="fixture-password",
    )
    assert secured.kafka_options()["sasl_plain_username"] == "fixture-ads"
    assert "fixture-password" not in repr(secured)
    with pytest.raises(ValueError):
        replace(secured, kafka_sasl_password=None).kafka_options()
    with pytest.raises(ValueError):
        replace(secured, kafka_security_protocol="invalid").kafka_options()


@pytest.mark.parametrize("failure", ["none", "start", "consume", "ended"])
def test_configuration_broker_lifecycle_and_consumer_death(settings, monkeypatch, failure):
    class Consumer:
        def __init__(self):
            self.closed = False
            self.done = asyncio.Event()
            self.topics = None

        def subscribe(self, topics, listener):
            self.topics = topics
            self.listener = listener

        async def start(self):
            if failure == "start":
                raise RuntimeError("cannot subscribe")

        async def stop(self):
            self.closed = True

        async def commit(self):
            self.done.set()

        async def __aiter__(self):
            if failure == "consume":
                raise RuntimeError("broker lost")
            yield SimpleNamespace(value=b"record", headers=[])
            if failure == "ended":
                return
            await asyncio.Event().wait()

    async def run():
        producer = SimpleNamespace(start=AsyncMock(), stop=AsyncMock())
        consumer = Consumer()
        monkeypatch.setattr("ads.egress_kafka.AIOKafkaProducer", Mock(return_value=producer))
        monkeypatch.setattr("ads.egress_kafka.AIOKafkaConsumer", Mock(return_value=consumer))
        runtime = EgressKafka(settings, FakeTokens())
        runtime.controller = SimpleNamespace(on_record=AsyncMock())
        if failure == "start":
            with pytest.raises(RuntimeError):
                await runtime.start()
        else:
            await runtime.start()
            try:
                async with asyncio.timeout(1):
                    while not (runtime.failed or consumer.done.is_set()):
                        await asyncio.sleep(0)
                assert consumer.topics == [EGRESS_CONFIG_TOPIC]
                if failure in ("consume", "ended"):
                    assert runtime.failed
                else:
                    runtime.controller.on_record.assert_awaited_once_with(b"record", [])
            finally:
                await runtime.stop()
        assert consumer.closed and not runtime.started
        producer.stop.assert_awaited_once()

    asyncio.run(run())
