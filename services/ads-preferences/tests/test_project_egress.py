from __future__ import annotations

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from uuid import uuid4

import pytest
from litestar.testing import TestClient
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session

from ads_commons.egress import ProjectEgressSettings
from ads_commons.security import AccessDenied, AuthenticationRequired, SecurityContextHolder
from ads_commons_schema import alembic_ini_for, mapped_tables, prepare_schema
from ads_preferences.app import create_app
from ads_preferences.egress_repository import ProjectEgressRepository
from ads_preferences.egress_service import ProjectEgressService
from ads_preferences.models import ProjectEgress, UserModel
from preference_tokens import encode_token


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_persisted_deny_all_and_monotonic_revisions(client, user_token):
    path = f"/v1/projects/{uuid4()}/egress-settings"
    headers = auth(user_token)
    assert client.get(path, headers=headers).status_code == 404
    body = {"mode": "whitelist", "rules": []}
    first = client.put(path, json=body, headers=headers)
    assert first.status_code == 200
    assert first.json() == {"revision": 1, "settings": body}
    second = client.put(path, json=body, headers=headers)
    assert second.json()["revision"] == 2
    assert client.get(path, headers=headers).json() == second.json()
    other = f"/v1/projects/{uuid4()}/egress-settings"
    assert client.get(other, headers=headers).status_code == 404
    assert client.delete(path, headers=headers).status_code == 204
    assert client.delete(path, headers=headers).status_code == 204
    assert client.get(path, headers=headers).status_code == 404


def test_project_row_is_shared_by_authorized_ads_delegations(client, user_token, rsa_key):
    path = f"/v1/projects/{uuid4()}/egress-settings"
    client.put(path, json={"rules": []}, headers=auth(user_token))
    other = encode_token(rsa_key, sub=str(uuid4()))
    assert client.get(path, headers=auth(other)).json()["revision"] == 1


@pytest.mark.parametrize("method", ["get", "put", "delete"])
@pytest.mark.parametrize(
    "claims,status",
    [
        ({"azp": "ads-engine"}, 403),
        ({"aud": "ads"}, 401),
        ({"iss": "https://wrong"}, 401),
        ({"exp": 1}, 401),
        ({"sub": "not-uuid"}, 401),
        ({"realm_access": {"roles": []}}, 403),
    ],
)
def test_rejections_before_sql(client, rsa_key, sql_count, method, claims, status):
    kwargs = {"headers": auth(encode_token(rsa_key, **claims))}
    if method == "put":
        kwargs["json"] = {"rules": []}
    response = getattr(client, method)(f"/v1/projects/{uuid4()}/egress-settings", **kwargs)
    assert response.status_code == status
    assert sql_count[0] == 0


def test_service_subject_only_get_even_if_misassigned_user_role(
    settings, jwt_verifier, engine, rsa_key, user_token
):
    service_id = uuid4()
    app = create_app(
        replace(settings, ads_service_subject=service_id), jwt_verifier=jwt_verifier, engine=engine
    )
    path = f"/v1/projects/{uuid4()}/egress-settings"
    with TestClient(app=app) as client:
        client.put(path, json={"rules": []}, headers=auth(user_token))
        for roles in ([], ["user"]):
            token = encode_token(rsa_key, sub=str(service_id), realm_access={"roles": roles})
            assert client.get(path, headers=auth(token)).status_code == 200
            assert client.put(path, json={"rules": []}, headers=auth(token)).status_code == 403
            assert client.delete(path, headers=auth(token)).status_code == 403
            assert client.get("/v1/models", headers=auth(token)).status_code == 403
            assert client.get("/v1/model-types", headers=auth(token)).status_code == 403
        wrong = encode_token(rsa_key, sub=str(uuid4()), realm_access={"roles": []})
        assert client.get(path, headers=auth(wrong)).status_code == 403


def test_invalid_dto_does_not_modify(client, user_token):
    path = f"/v1/projects/{uuid4()}/egress-settings"
    headers = auth(user_token)
    assert client.put(path, json={"rules": []}, headers=headers).status_code == 200
    invalid = {
        "rules": [
            {
                "domain": "*",
                "port": 443,
                "protocol": "https",
                "protocol_settings": {"upgrades": "any"},
            }
        ]
    }
    assert client.put(path, json=invalid, headers=headers).status_code == 400
    assert client.get(path, headers=headers).json()["revision"] == 1


def test_direct_service_security(settings, engine, jwt_verifier, rsa_key):
    service_id = uuid4()
    with Session(engine) as session:
        service = ProjectEgressService(
            session,
            ProjectEgressRepository(session),
            replace(settings, ads_service_subject=service_id),
        )
        with pytest.raises(AuthenticationRequired):
            asyncio.run(service.get_egress(uuid4()))
        context = jwt_verifier.authenticate(encode_token(rsa_key, sub=str(service_id)))
        with SecurityContextHolder.bound(context):
            with pytest.raises(AccessDenied):
                asyncio.run(service.save_egress(uuid4(), ProjectEgressSettings(rules=())))
            with pytest.raises(AccessDenied):
                asyncio.run(service.delete_egress(uuid4()))
        context = jwt_verifier.authenticate(encode_token(rsa_key, azp="foreign"))
        with SecurityContextHolder.bound(context), pytest.raises(AccessDenied):
            asyncio.run(service.get_egress(uuid4()))


def test_fresh_schema_contains_project_settings(tmp_path):
    url = f"sqlite:///{tmp_path / 'fresh.db'}"
    prepare_schema(
        alembic_ini=alembic_ini_for("ads-preferences"),
        database_url=url,
        tables=mapped_tables(UserModel, ProjectEgress),
    )
    engine = create_engine(url)
    try:
        assert inspect(engine).has_table("project_egress")
    finally:
        engine.dispose()


@pytest.fixture
def egress_postgres():
    configured = os.environ.get("ADS_PREFERENCES_TEST_DATABASE_URL")
    if configured:
        yield configured
    else:
        from testcontainers.postgres import PostgresContainer

        with PostgresContainer("postgres:16-alpine", driver="psycopg") as postgres:
            yield postgres.get_connection_url()


def test_real_postgres_concurrent_first_save_and_revisions(egress_postgres):
    prepare_schema(
        alembic_ini=alembic_ini_for("ads-preferences"),
        database_url=egress_postgres,
        tables=mapped_tables(UserModel, ProjectEgress),
    )
    engine = create_engine(egress_postgres)
    project = uuid4()

    def save(index):
        with Session(engine) as session, session.begin():
            row = ProjectEgressRepository(session).save(
                project, {"mode": "whitelist" if index % 2 else "blacklist", "rules": []}
            )
            return row.revision

    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            assert sorted(pool.map(save, range(24))) == list(range(1, 25))
        with Session(engine) as session, session.begin():
            repo = ProjectEgressRepository(session)
            assert repo.get(project).revision == 24
            repo.delete(project)
            repo.delete(project)
    finally:
        engine.dispose()
