from __future__ import annotations

import uuid

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from ads.project_service import ProjectService
from ads.repository import ProjectRepository, SessionRepository, SessionRunRepository
from ads.security_context import SecurityContext
from ads.security_holder import SecurityContextHolder
from ads_commons.security import AccessDenied, AuthenticationRequired
from tests.threadline_fakes import FakePreferences

USER_ID = uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")


def _ctx(*roles: str) -> SecurityContext:
    return SecurityContext(subject=str(USER_ID), name="Alice", roles=frozenset(roles))


def _service(engine: Engine, session: Session) -> ProjectService:
    del engine
    return ProjectService(
        session=session,
        projects=ProjectRepository(session=session),
        sessions=SessionRepository(session=session),
        runs=SessionRunRepository(session=session),
        egress=FakePreferences(),
    )


def test_create_project_requires_a_security_context(db_engine: Engine) -> None:
    with Session(db_engine) as session:
        with pytest.raises(AuthenticationRequired):
            _run(_service(db_engine, session).create("P", "D"))


def test_create_project_requires_the_user_role(db_engine: Engine) -> None:
    with Session(db_engine) as session:
        with pytest.raises(AccessDenied, match="role user required"):
            with SecurityContextHolder.bound(_ctx("other")):
                _run(_service(db_engine, session).create("P", "D"))


def test_create_project_stores_the_row_for_the_bound_user(db_engine: Engine) -> None:
    with Session(db_engine) as session:
        with SecurityContextHolder.bound(_ctx("user")):
            created = _run(_service(db_engine, session).create("Harness", "Design work"))
            assert created.name == "Harness"
            tree = _run(_service(db_engine, session).list_tree(None))
    assert [project.name for project in tree] == ["Harness"]


def test_list_tree_is_scoped_to_the_bound_user(db_engine: Engine) -> None:
    other = SecurityContext(
        subject="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        name="Bob",
        roles=frozenset({"user"}),
    )
    with Session(db_engine) as session:
        with SecurityContextHolder.bound(_ctx("user")):
            _run(_service(db_engine, session).create("Mine", "d"))
        with SecurityContextHolder.bound(other):
            assert _run(_service(db_engine, session).list_tree(None)) == []


def _run(coro: object) -> object:
    import asyncio

    return asyncio.run(coro)  # type: ignore[arg-type]
