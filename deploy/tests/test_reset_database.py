# ruff: noqa: F811
from __future__ import annotations

import asyncio
import os
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime
from uuid import UUID, uuid4

import msgspec
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool
from test_reset_preservation import ROOT, load, models, protected, rows, store  # noqa: F401

from ads_commons.preferences import ModelWrite
from ads_commons.security import SecurityContext, SecurityContextHolder
from ads_preferences.repository import UserModelRepository
from ads_preferences.service import PreferencesService

database = load("database")


def test_reset_table_scope_is_independent_of_other_imported_applications():
    for service in database.MODULES:
        database.application_tables(service)
    preferences = {table.name for table in database.application_tables("ads-preferences")}
    ads = {table.name for table in database.application_tables("ads")}
    manager = {table.name for table in database.application_tables("ads-sandbox-manager")}
    assert preferences == {"user_model", "project_egress"}
    assert {"project", "session", "session_entry"} <= ads
    assert "sandbox_pair_disposal" in manager and "sandbox_pair_retirement" in manager
    assert preferences.isdisjoint(ads | manager) and ads.isdisjoint(manager)


@contextmanager
def postgres():
    configured = os.environ.get("ADS_PREFERENCES_TEST_DATABASE_URL")
    if configured:
        yield configured
    else:
        from testcontainers.postgres import PostgresContainer

        with PostgresContainer("postgres:16-alpine", driver="psycopg") as container:
            yield container.get_connection_url()


@pytest.fixture
def reset_db():
    with postgres() as source:
        url = make_url(source)
        admin = create_engine(url, isolation_level="AUTOCOMMIT", poolclass=NullPool)
        name = "reset_" + uuid4().hex
        with admin.connect() as db:
            db.execute(text(f'CREATE DATABASE "{name}"'))
        target = database.Target(
            "ads-preferences",
            name,
            url.username,
            url.set(database=name).render_as_string(hide_password=False),
        )
        service = database.Database(target, ROOT)
        try:
            empty = service.inventory()
            service.initialize(empty)
            yield service
        finally:
            service.close()
            with admin.connect() as db:
                db.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
            admin.dispose()


class ServiceApi:
    """External HTTP/token boundary only; production service/repository and real PG."""

    def __init__(self, engine):
        self.engine, self.invoked = engine, []

    def call(self, owner, operation, *args):
        with Session(self.engine) as db:
            service = PreferencesService(db, UserModelRepository(session=db))
            with SecurityContextHolder.bound(
                SecurityContext(
                    subject=owner,
                    name="Synthetic reset owner",
                    roles=frozenset({"user"}),
                )
            ):
                value = asyncio.run(getattr(service, operation)(*args))
                return msgspec.json.decode(msgspec.json.encode(value))

    def models(self, owner):
        return [self.model(owner, item["id"]) for item in self.call(owner, "list_models")["models"]]

    def create(self, owner, payload):
        return self.call(owner, "add_model", msgspec.convert(payload, type=ModelWrite))

    def model(self, owner, model_id):
        return self.call(owner, "get_model", UUID(model_id))

    def invoke(self, owner, model_id):
        self.invoked.append((owner, model_id))


def seed(reset_db, rows):
    from ads_preferences.models import UserModel

    with Session(reset_db.engine) as db, db.begin():
        for row in rows:
            values = deepcopy(row)
            for key in ("id", "user_id"):
                values[key] = UUID(values[key])
            for key in ("created_at", "updated_at"):
                values[key] = datetime.fromisoformat(values[key])
            db.add(UserModel(**values))


def test_repeatable_real_schema_reset_and_supported_owner_restore(reset_db, store, rows):
    seed(reset_db, rows)
    api = ServiceApi(reset_db.engine)
    original = reset_db.inventory()
    for _ in range(2):
        backup = models.refresh_backup(store, reset_db.models())
        capture = reset_db.inventory()
        reset_db.reset(capture)
        assert not reset_db.inventory()["tables"]
        reset_db.initialize(capture)
        assert reset_db.models() == []
        assert models.refresh_backup(store, []) == backup
        first = models.restore_models(backup, api, invoke=True)
        assert models.restore_models(backup, api, invoke=False) == first
        actual = reset_db.models()
        assert len(actual) == 1 and actual[0]["user_id"] == rows[0]["user_id"]
        assert actual[0]["authentication"] == rows[0]["authentication"]
        assert len(reset_db.inventory()["tables"]) == len(original["tables"])
    for key in ("database_oid", "role", "schema_oid", "schema_owner", "schema_acl"):
        assert reset_db.inventory()[key] == original[key]


@pytest.mark.parametrize("fault", ["foreign-table", "external-view", "connection", "scope"])
def test_reset_never_crosses_scope_or_connected_writer_fence(reset_db, rows, fault):
    seed(reset_db, rows)
    captured = reset_db.inventory()
    connection = None
    if fault == "foreign-table":
        with reset_db.engine.begin() as db:
            db.execute(text("CREATE TABLE unrelated(id integer)"))
    elif fault == "external-view":
        with reset_db.engine.begin() as db:
            db.execute(text("CREATE SCHEMA unrelated"))
            db.execute(text("CREATE VIEW unrelated.model_refs AS SELECT id FROM public.user_model"))
    elif fault == "connection":
        connection = reset_db.engine.connect()
    else:
        captured["database_oid"] += 1
    try:
        with pytest.raises(protected.PreservationError):
            reset_db.reset(captured)
        with reset_db.engine.begin() as db:
            assert db.scalar(text("SELECT count(*) FROM public.user_model")) == 1
    finally:
        if connection is not None:
            connection.close()


def test_table_grants_are_restored_without_changing_schema_or_role(reset_db):
    with reset_db.engine.begin() as db:
        db.execute(text("GRANT SELECT ON public.user_model TO PUBLIC"))
    captured = reset_db.inventory()
    assert captured["grants"]
    reset_db.reset(captured)
    reset_db.initialize(captured)
    assert reset_db.inventory()["grants"] == captured["grants"]


def test_explicit_reset_target_wins_over_application_environment(reset_db, monkeypatch):
    captured = reset_db.inventory()
    reset_db.reset(captured)
    variable = "ADS_PREFERENCES_DATABASE_URL"
    foreign = "postgresql+psycopg://unrelated@127.0.0.1:1/never-authorized"
    monkeypatch.setenv(variable, foreign)
    reset_db.initialize(captured)
    assert os.environ[variable] == foreign
    assert reset_db.inventory()["tables"] == captured["tables"]

    def fail(**kwargs):
        assert variable not in os.environ
        assert kwargs["database_url"] == reset_db.target.url
        raise RuntimeError("synthetic initialization failure")

    monkeypatch.setattr(database, "prepare_schema", fail)
    with pytest.raises(protected.PreservationError):
        reset_db.initialize(captured)
    assert os.environ[variable] == foreign
