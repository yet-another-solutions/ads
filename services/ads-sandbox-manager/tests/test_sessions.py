from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from kubernetes.client.exceptions import ApiException
from sqlalchemy import create_engine, inspect, text, update
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from ads_commons.egress import SessionProjectBinding
from ads_commons_schema import mapped_tables, prepare_schema
from ads_sandbox_manager.lifecycle_store import CleanupWork
from ads_sandbox_manager.objects import VERSION
from ads_sandbox_manager.session_objects import SESSION, ipc_name, session_name, session_pvc
from ads_sandbox_manager.sessions import ClaimLost, SessionBindError, SessionProvisioner
from ads_sandbox_manager.store import PingProbe, SandboxSession, SessionPVC, SessionRepository
from session_support import FakeSessionKube, FakeTopics
from test_session_objects import object_settings  # noqa: F401

pytestmark = pytest.mark.anyio


class FakeProjects:
    def __init__(self):
        self.project = uuid4()

    async def session_project(self, session_id):
        return SessionProjectBinding(session_id, self.project)


@pytest.fixture
async def sessions_harness(baked, object_settings, manager_database_url):  # noqa: F811
    prepare_schema(
        alembic_ini=Path(__file__).parents[1] / "alembic.ini",
        database_url=manager_database_url,
        tables=mapped_tables(SandboxSession, SessionPVC, CleanupWork, PingProbe),
    )
    sync = create_engine(manager_database_url)
    with sync.begin() as db:
        db.execute(text("DELETE FROM sandbox_session"))
        db.execute(text("DELETE FROM ping_probe"))
    sync.dispose()
    engine = create_async_engine(manager_database_url, poolclass=NullPool)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    repository = SessionRepository()
    kube = FakeSessionKube()
    topics = FakeTopics(kube)
    baked.kube.is_released = True
    h = SimpleNamespace(
        settings=object_settings,
        engine=engine,
        sessions=sessions,
        repository=repository,
        kube=kube,
        topics=topics,
        golden=baked.golden,
        projects=FakeProjects(),
    )
    h.service = SessionProvisioner(
        h.settings,
        kube,
        h.golden,
        sessions,
        repository,
        topics,
        h.projects,
    )
    yield h
    await engine.dispose()


async def row_for(h, session_id):
    async with h.sessions.begin() as db:
        return await h.repository.get(db, session_id)


async def seed(h, session_id, status="stopped", pvc_uid=None):
    disk = next(
        (
            o
            for o in h.kube.objects.values()
            if o["kind"] == "PersistentVolumeClaim"
            and o["metadata"]["labels"].get(SESSION) == str(session_id)
        ),
        None,
    )
    pvc_id = UUID(disk["metadata"]["name"].removeprefix("ads-sandbox-")) if disk else uuid4()
    sandbox_id = UUID(disk["metadata"]["labels"]["ads.io/sandbox-id"]) if disk else uuid4()
    now = datetime.now(UTC)
    async with h.sessions.begin() as db:
        await h.repository.insert_pending(
            db,
            session_id,
            sandbox_id,
            disk["metadata"]["labels"][VERSION] if disk else h.settings.golden_version,
            now,
            h.projects.project,
        )
        await db.execute(
            update(SandboxSession)
            .where(
                SandboxSession.session_id == session_id,
            )
            .values(status=status, pvc_uid=pvc_uid, pvc_id=pvc_id)
        )
        db.add(
            SessionPVC(
                pvc_id=pvc_id,
                session_id=session_id,
                sandbox_id=sandbox_id,
                uid=pvc_uid,
                state="attached"
                if status == "ready"
                else "attaching"
                if status == "creating"
                else "detached",
                last_execution=now,
                last_state_change=now,
            )
        )
    return await row_for(h, session_id)


async def test_first_create_four_objects_bind_persisted_before_topics(sessions_harness):
    h, sid = sessions_harness, uuid4()

    async def inspect_bind(sandbox):
        row = await row_for(h, sid)
        assert row.status == "creating" and row.sandbox_id == sandbox and row.pvc_uid
        assert len(h.kube.objects) == 1

    h.topics.hook = inspect_bind
    row = await h.service.provision(sid)
    assert row.status == "creating"  # Kube existence is NEVER Kafka-ready.
    assert row.last_execution_at is not None and row.last_ping_at is None
    assert row.pvc_uid and row.guest_deployment_uid and row.ipc_deployment_uid and row.ipc_pvc_uid
    writes = [call for call in h.kube.calls if call[0] != "get"]
    assert writes == [
        ("create", "PersistentVolumeClaim", session_name(row.pvc_id)),
        ("topics-and-seek", str(row.sandbox_id)),
        ("create", "PersistentVolumeClaim", ipc_name(row.sandbox_id)),
        ("create", "Deployment", session_name(row.sandbox_id)),
        ("create", "Deployment", ipc_name(row.sandbox_id)),
    ]
    disk = h.kube.objects[("PersistentVolumeClaim", session_name(row.pvc_id))]
    assert disk["metadata"]["uid"] == row.pvc_uid
    assert disk["spec"]["resources"]["requests"]["storage"] == str(22 * 1024**3)
    # Neither claim needs Bound before Deployment creation (WaitForFirstConsumer).
    assert "status" not in disk
    reloaded = await row_for(h, sid)
    assert reloaded.sandbox_id == row.sandbox_id and reloaded.pvc_uid == row.pvc_uid
    before = list(h.kube.calls)
    fresh_service = SessionProvisioner(
        h.settings,
        h.kube,
        h.golden,
        h.sessions,
        h.repository,
        h.topics,
        h.projects,
    )
    assert (await fresh_service.provision(sid)).status == "creating"
    assert h.kube.calls == before


async def test_parallel_replicas_create_only_one_sandbox(sessions_harness):
    h, sid = sessions_harness, uuid4()
    rows = await asyncio.gather(*(h.service.provision(sid) for _ in range(8)))
    assert len({row.sandbox_id for row in rows}) == 1
    assert len([call for call in h.kube.calls if call[0] == "create"]) == 4
    assert len(h.kube.objects) == 4


async def test_parallel_resume_has_one_winner_and_preserves_disk(sessions_harness):
    h, sid = sessions_harness, uuid4()
    disk = h.kube.put(session_pvc(h.settings, sid, uuid4(), "v0.0.10", "22Gi", uuid4()))
    original = await seed(h, sid, pvc_uid=disk["metadata"]["uid"])
    rows = await asyncio.gather(*(h.service.provision(sid) for _ in range(8)))
    assert {row.sandbox_id for row in rows} == {original.sandbox_id}
    assert {row.status for row in rows} == {"creating"}
    assert {row.pvc_uid for row in rows} == {original.pvc_uid}
    assert len([call for call in h.kube.calls if call[0] == "create"]) == 3


async def test_database_claim_wait_is_bounded(sessions_harness):
    h, sid = sessions_harness, uuid4()
    h.service.settings = replace(
        h.settings,
        session_objects=replace(h.settings.session_objects, create_seconds=0.1),
    )
    # Uncommitted competing INSERT makes PostgreSQL wait on the unique constraint.
    async with h.sessions.begin() as db:
        await h.repository.insert_pending(
            db,
            sid,
            uuid4(),
            h.settings.golden_version,
            datetime.now(UTC),
            h.projects.project,
        )
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(h.service.provision(sid), timeout=2)
    assert not h.kube.calls
    assert (await row_for(h, sid)).status == "pending"


async def test_uuid_and_object_configuration_are_required_before_database_io(sessions_harness):
    h = sessions_harness
    with pytest.raises(ValueError, match="UUID"):
        await h.service.provision("../foreign")
    h.service.settings = replace(h.settings, session_objects=None)
    with pytest.raises(RuntimeError, match="configuration"):
        await h.service.provision(uuid4())
    assert not h.kube.calls


async def test_durable_lifetime_preserves_older_golden_version_without_clone(sessions_harness):
    h, sid = sessions_harness, uuid4()
    old = h.kube.put(session_pvc(h.settings, sid, uuid4(), "v0.0.9", "22Gi", uuid4()))
    await seed(h, sid, pvc_uid=old["metadata"]["uid"])
    h.golden = AsyncMock()
    h.golden.clone_source.side_effect = AssertionError("must not rebake or upgrade")
    h.service.golden = h.golden
    row = await h.service.provision(sid)
    assert row.pvc_uid == old["metadata"]["uid"] and row.golden_version == "v0.0.9"
    assert ("create", "PersistentVolumeClaim", session_name(row.pvc_id)) not in h.kube.calls
    guest = h.kube.objects[("Deployment", session_name(row.sandbox_id))]
    assert guest["metadata"]["labels"][VERSION] == "v0.0.9"
    h.golden.clone_source.assert_not_called()


async def test_resume_keeps_disk_identity_and_recreates_compute(sessions_harness):
    h, sid = sessions_harness, uuid4()
    original = await h.service.provision(sid)
    for key in list(h.kube.objects):
        if key != ("PersistentVolumeClaim", session_name(original.pvc_id)):
            del h.kube.objects[key]  # Fake the not-yet-built idle component.
    async with h.sessions.begin() as db:
        await db.execute(
            update(SandboxSession)
            .where(
                SandboxSession.session_id == sid,
            )
            .values(status="stopped")
        )
        await db.execute(
            update(SessionPVC).where(SessionPVC.pvc_id == original.pvc_id).values(state="detached")
        )
    h.kube.calls.clear()
    h.service.golden = AsyncMock()
    h.service.golden.clone_source.side_effect = AssertionError("resume must not clone")
    row = await h.service.provision(sid)
    assert row.pvc_uid == original.pvc_uid and row.sandbox_id == original.sandbox_id
    assert row.ipc_pvc_uid != original.ipc_pvc_uid
    assert row.guest_deployment_uid != original.guest_deployment_uid
    assert len([call for call in h.kube.calls if call[0] == "create"]) == 3
    h.service.golden.clone_source.assert_not_called()


@pytest.mark.parametrize(
    "fault",
    [
        "foreign-label",
        "no-label",
        "uid",
        "missing",
        "filesystem",
        "class",
        "deleting",
        "owner",
        "lost",
        "version",
        "no-uid",
    ],
)
async def test_resume_rejects_bad_bind_without_clone_attach_or_delete(sessions_harness, fault):
    h, sid = sessions_harness, uuid4()
    # This proves bind rejection, not cleanup latency on a busy CI database.
    h.service.settings = replace(h.settings, control_seconds=10)
    row = await seed(h, sid)
    disk = h.kube.put(
        session_pvc(h.settings, sid, row.sandbox_id, row.golden_version, "22Gi", row.pvc_id)
    )
    async with h.sessions.begin() as db:
        await db.execute(
            update(SandboxSession)
            .where(
                SandboxSession.session_id == sid,
            )
            .values(pvc_uid=None if fault == "no-uid" else disk["metadata"]["uid"])
        )
    if fault == "foreign-label":
        disk["metadata"]["labels"][SESSION] = str(uuid4())
    elif fault == "no-label":
        disk["metadata"]["labels"].pop(SESSION)
    elif fault == "uid":
        disk["metadata"]["uid"] = str(uuid4())
    elif fault == "missing":
        h.kube.objects.clear()
    elif fault == "filesystem":
        disk["spec"]["volumeMode"] = "Filesystem"
    elif fault == "class":
        disk["spec"]["storageClassName"] = "other"
    elif fault == "deleting":
        disk["metadata"]["deletionTimestamp"] = "now"
    elif fault == "owner":
        disk["metadata"]["ownerReferences"] = [{"uid": "foreign"}]
    elif fault == "lost":
        disk["status"] = {"phase": "Lost"}
    elif fault == "version":
        disk["metadata"]["labels"][VERSION] = "v0.0.11"
    with pytest.raises(SessionBindError):
        await h.service.provision(sid)
    assert not any(call[0] != "get" for call in h.kube.calls)
    assert (await row_for(h, sid)).status == "failed"


@pytest.mark.parametrize("fault", ["foreign", "filesystem", "class", "version"])
async def test_initial_adoption_also_fails_closed(sessions_harness, fault):
    h, sid = sessions_harness, uuid4()

    async def race(body):
        disk = h.kube.put(body)
        if fault == "foreign":
            disk["metadata"]["labels"][SESSION] = str(uuid4())
        elif fault == "filesystem":
            disk["spec"]["volumeMode"] = "Filesystem"
        elif fault == "class":
            disk["spec"]["storageClassName"] = "foreign"
        else:
            disk["metadata"]["labels"][VERSION] = "latest"

    h.kube.before_create = race
    with pytest.raises(SessionBindError):
        await h.service.provision(sid)
    assert not any(call[0] != "get" for call in h.kube.calls)


async def test_replacement_after_bind_is_rechecked_before_compute(sessions_harness):
    h, sid = sessions_harness, uuid4()

    async def replace_disk(_):
        row = await row_for(h, sid)
        h.kube.objects[("PersistentVolumeClaim", session_name(row.pvc_id))]["metadata"]["uid"] = (
            "new"
        )

    h.topics.hook = replace_disk
    with pytest.raises(SessionBindError, match="identity changed"):
        await h.service.provision(sid)
    assert not any(key[0] == "Deployment" for key in h.kube.objects)


@pytest.mark.parametrize("foreign", [False, True])
async def test_create_conflict_is_reread_not_blindly_adopted(sessions_harness, foreign):
    h, sid = sessions_harness, uuid4()
    # Ownership rejection is independent of database cleanup latency.
    h.service.settings = replace(h.settings, control_seconds=10)

    async def race(body):
        if body["kind"] == "PersistentVolumeClaim" and body["spec"].get("volumeMode") == "Block":
            disk = h.kube.put(body)
            if foreign:
                disk["metadata"]["labels"][SESSION] = str(uuid4())

    h.kube.before_create = race
    if foreign:
        with pytest.raises(SessionBindError):
            await h.service.provision(sid)
        assert len(h.kube.objects) == 1
    else:
        row = await h.service.provision(sid)
        assert row.pvc_uid and len(h.kube.objects) == 4


@pytest.mark.parametrize("fault", ["label", "claim", "replicas", "network", "ipc-source"])
async def test_existing_compute_or_ipc_disk_cannot_cross_bind(sessions_harness, fault):
    h, sid = sessions_harness, uuid4()
    # Preserve the ownership assertions without a 100 ms database race.
    h.service.settings = replace(h.settings, control_seconds=10)

    async def race(body):
        is_ipc = body["kind"] == "PersistentVolumeClaim" and "ipc" in body["metadata"]["name"]
        if (fault == "ipc-source" and is_ipc) or (
            fault != "ipc-source" and body["kind"] == "Deployment"
        ):
            obj = h.kube.put(body)
            if fault == "label":
                obj["spec"]["template"]["metadata"]["labels"][SESSION] = str(uuid4())
            elif fault == "claim":
                obj["spec"]["template"]["spec"]["volumes"][0]["persistentVolumeClaim"][
                    "claimName"
                ] = session_name(uuid4())
            elif fault == "replicas":
                obj["spec"]["replicas"] = 2
            elif fault == "network":
                obj["spec"]["template"]["spec"]["hostNetwork"] = True
            else:
                obj["spec"]["dataSource"] = {"name": "foreign"}

    h.kube.before_create = race
    with pytest.raises(SessionBindError, match="incompatible session object"):
        await h.service.provision(sid)
    assert (await row_for(h, sid)).status == "failed"


async def test_public_image_provisioning_accepts_api_omitted_empty_lists(sessions_harness):
    h, sid = sessions_harness, uuid4()
    h.service.settings = replace(h.settings, tolerations=[], image_pull_secrets=())

    async def normalize(body):
        if body["kind"] == "Deployment":
            obj = h.kube.objects[("Deployment", body["metadata"]["name"])]
            pod = obj["spec"]["template"]["spec"]
            for field in ("tolerations", "imagePullSecrets"):
                assert pod[field] == []
                del pod[field]

    h.kube.after_create = normalize
    row = await h.service.provision(sid)
    assert row.guest_deployment_uid and row.ipc_deployment_uid and row.ipc_pvc_uid
    assert len(h.kube.objects) == 4
    stored = await row_for(h, sid)
    assert stored.guest_deployment_uid == row.guest_deployment_uid
    assert stored.ipc_deployment_uid == row.ipc_deployment_uid


async def test_golden_must_be_released_and_clone_uses_actual_capacity(sessions_harness):
    h, sid = sessions_harness, uuid4()
    h.golden.kube.is_released = False
    with pytest.raises(SessionBindError, match="safe clone source"):
        await h.service.provision(sid)
    assert not h.kube.objects
    h.golden.kube.is_released = True
    h.golden.kube.objects["pvc"]["status"]["capacity"] = {"storage": "24Gi"}
    row = await h.service.provision(uuid4())
    disk = h.kube.objects[("PersistentVolumeClaim", session_name(row.pvc_id))]
    assert disk["spec"]["resources"]["requests"]["storage"] == str(24 * 1024**3)


async def test_cancelled_worker_leaves_durable_claim_not_duplicate_compute(sessions_harness):
    h, sid = sessions_harness, uuid4()
    entered = asyncio.Event()
    gate = asyncio.Event()

    async def wait(_):
        entered.set()
        await gate.wait()

    h.topics.hook = wait
    task = asyncio.create_task(h.service.provision(sid))
    await asyncio.wait_for(entered.wait(), 2)
    task.cancel()  # Fake process shutdown, NOT an execution abort/reset.
    with pytest.raises(asyncio.CancelledError):
        await task
    row = await row_for(h, sid)
    assert row.status == "creating" and row.pvc_uid
    calls = list(h.kube.calls)
    assert (await h.service.provision(sid)).sandbox_id == row.sandbox_id
    assert h.kube.calls == calls


@pytest.mark.parametrize(
    "status", ["pending", "ready", "creating", "shutting_down", "recovering", "failed"]
)
async def test_existing_nonstopped_rows_never_start_work(sessions_harness, status):
    h, sid = sessions_harness, uuid4()
    await seed(h, sid, status=status)
    assert (await h.service.provision(sid)).status == status
    assert not h.kube.calls


async def test_creation_timeout_and_api_denial_fail_without_deleting_disk(
    sessions_harness, monkeypatch
):
    h, sid = sessions_harness, uuid4()
    h.service.settings = replace(
        h.settings,
        # This test expires creation explicitly below. Failure persistence is
        # not the timeout under test; retain its production database budget.
        control_seconds=10,
        session_objects=replace(
            h.settings.session_objects,
            create_seconds=0.15,
        ),
    )

    deadlines = []

    def timeout(seconds):
        # Expire the real asyncio deadline at the intended network wait, not
        # during a slow CI database claim/commit before build() has started.
        deadline = asyncio.timeout(None if seconds == 0.15 else seconds)
        if seconds == 0.15:
            deadlines.append(deadline)
        return deadline

    monkeypatch.setattr("ads_sandbox_manager.sessions.asyncio", SimpleNamespace(timeout=timeout))

    async def wait(_):
        deadlines[-1].reschedule(asyncio.get_running_loop().time())
        await asyncio.Event().wait()

    h.topics.hook = wait
    with pytest.raises(TimeoutError):
        await h.service.provision(sid)
    row = await row_for(h, sid)
    assert row.status == "failed" and row.pvc_uid and len(h.kube.objects) == 1
    h.topics.hook = None

    async def denied(_):
        raise ApiException(status=403)

    h.kube.before_create = denied
    with pytest.raises(ApiException):
        await h.service.provision(uuid4())


async def test_stale_worker_does_not_overwrite_a_new_claim(sessions_harness):
    h, sid = sessions_harness, uuid4()

    async def replaced(_):
        async with h.sessions.begin() as db:
            await db.execute(
                update(SandboxSession)
                .where(
                    SandboxSession.session_id == sid,
                )
                .values(claimed_by=uuid4(), status="recovering")
            )

    h.topics.hook = replaced
    with pytest.raises(ClaimLost):
        await h.service.provision(sid)
    assert (await row_for(h, sid)).status == "recovering"
    assert len(h.kube.objects) == 1


async def test_schema_contains_only_lifecycle_and_migration_is_repeatable(sessions_harness):
    h = sessions_harness
    ini = Path(__file__).parents[1] / "alembic.ini"
    prepare_schema(
        alembic_ini=ini,
        database_url=h.engine.url.render_as_string(hide_password=False),
        tables=mapped_tables(SandboxSession, SessionPVC, CleanupWork),
    )
    async with h.engine.connect() as db:
        columns = await db.run_sync(lambda c: inspect(c).get_columns("sandbox_session"))
        unique = await db.run_sync(lambda c: inspect(c).get_unique_constraints("sandbox_session"))
    assert {c["name"] for c in columns} == set(SandboxSession.__table__.columns.keys())
    assert any(c["column_names"] == ["sandbox_id"] for c in unique)
    assert not {"authorization", "token", "stdout", "stderr", "execution_id"} & {
        c["name"] for c in columns
    }


async def test_ping_migration_preserves_legacy_probe_without_inventing_delivery(sessions_harness):
    h = sessions_harness
    ini = Path(__file__).parents[1] / "alembic.ini"
    config = Config(str(ini))
    config.set_main_option("script_location", str(ini.parent / "alembic"))
    url = h.engine.url.render_as_string(hide_password=False)
    config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    probe_id, sandbox_id = uuid4(), uuid4()
    command.downgrade(config, "0001_session")
    try:
        async with h.engine.begin() as db:
            await db.execute(
                text(
                    "INSERT INTO ping_probe (ping_id, sandbox_id, sent_at) "
                    "VALUES (:id, :sandbox, CURRENT_TIMESTAMP)"
                ),
                {"id": probe_id, "sandbox": sandbox_id},
            )
    finally:
        prepare_schema(alembic_ini=ini, database_url=url, tables=mapped_tables(PingProbe))
    async with h.sessions.begin() as db:
        probe = await db.get(PingProbe, probe_id)
        assert probe.sandbox_id == sandbox_id
        assert probe.published_at is None
