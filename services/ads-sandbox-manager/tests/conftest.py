from __future__ import annotations

import os
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from kubernetes.client.exceptions import ApiException

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.golden import GoldenEnsure
from ads_sandbox_manager.objects import golden_job, golden_pvc


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def manager_settings():
    return Settings(
        golden_version="v0.0.10",
        golden_image="registry.test/ads-sandbox-golden:0.0.10",
        session_size="20Gi",
        database_url="postgresql+psycopg://fixture:fixture@localhost/manager",
        kafka_bootstrap_servers="unused.test:9092",
        tls_cert_path=Path("/unused/cert"),
        tls_key_path=Path("/unused/key"),
        poll_seconds=0.01,
        control_seconds=0.1,
    )


class FakeKube:
    """API semantics including name uniqueness, deletion lag, and UID/RV preconditions."""

    def __init__(self):
        self.objects = {"job": None, "pvc": None}
        self.calls = []
        self.is_released = False
        self.release_hook = None

    async def job(self):
        return deepcopy(self.objects["job"])

    async def pvc(self):
        return deepcopy(self.objects["pvc"])

    def create(self, kind, body):
        if self.objects[kind] is not None:
            raise ApiException(status=409)
        obj = deepcopy(body)
        obj["metadata"].update(uid=str(uuid4()), resourceVersion="1")
        self.objects[kind] = obj
        self.calls.append(("create", kind))

    async def create_job(self, body):
        self.create("job", body)

    async def create_pvc(self, body):
        self.create("pvc", body)

    def delete(self, kind, observed):
        current = self.objects[kind]
        if current is None:
            raise ApiException(status=404)
        for key in ("uid", "resourceVersion"):
            if current["metadata"][key] != observed["metadata"][key]:
                raise ApiException(status=409)
        current["metadata"]["deletionTimestamp"] = "2026-09-17T00:00:00Z"
        self.calls.append(("delete", kind))

    async def delete_job(self, observed):
        self.delete("job", observed)

    async def delete_pvc(self, observed):
        self.delete("pvc", observed)

    async def delete_released_bake_pods(self, pvc, job):
        if self.is_released:
            self.bake_pods_deleted = True

    async def released(self, pvc, job):
        if self.release_hook:
            self.release_hook()
        return self.is_released

    def finish(self, status="Complete"):
        self.objects["job"]["status"] = {
            "conditions": [{"type": status, "status": "True"}],
            "active": 0,
        }
        self.objects["pvc"]["status"] = {"phase": "Bound"}
        self.objects["pvc"]["spec"]["volumeName"] = "pv-fixture"


@pytest.fixture
def manager(manager_settings):
    kube = FakeKube()
    return SimpleNamespace(
        settings=manager_settings, kube=kube, golden=GoldenEnsure(manager_settings, kube)
    )


@pytest.fixture
def baked(manager):
    k, s = manager.kube, manager.settings
    k.create("job", golden_job(s))
    k.create("pvc", golden_pvc(s, k.objects["job"]["metadata"]["uid"]))
    k.finish()
    k.calls.clear()
    return manager


@pytest.fixture(scope="session")
def manager_database_url():
    configured = os.environ.get("ADS_MANAGER_TEST_DATABASE_URL")
    if configured:
        yield configured
    else:
        from testcontainers.postgres import PostgresContainer

        with PostgresContainer("postgres:16-alpine", driver="psycopg") as postgres:
            yield postgres.get_connection_url()
