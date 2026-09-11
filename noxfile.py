from __future__ import annotations

import os

import nox

os.environ.setdefault("UV_DEFAULT_INDEX", "https://pypi.org/simple")

nox.options.default_venv_backend = "uv"
nox.options.sessions = ["lint", "deps", "typecheck", "test", "package"]


def _uv_run(session: nox.Session, *args: str) -> None:
    session.run("uv", "run", *args, external=True)


@nox.session
def lint(session: nox.Session) -> None:
    session.run("uv", "sync", "--group", "lint", external=True)
    _uv_run(session, "--group", "lint", "ruff", "check", "src", "tests", "noxfile.py")
    _uv_run(session, "--group", "lint", "ruff", "format", "--check", "src", "tests", "noxfile.py")


@nox.session
def deps(session: nox.Session) -> None:
    session.run("uv", "sync", "--group", "deps", external=True)
    _uv_run(session, "--group", "deps", "deptry", "src")


@nox.session
def typecheck(session: nox.Session) -> None:
    session.run("uv", "sync", "--group", "typecheck", external=True)
    _uv_run(session, "--group", "typecheck", "mypy", "src")


@nox.session
def test(session: nox.Session) -> None:
    session.run("uv", "sync", "--group", "test", external=True)
    _uv_run(session, "--group", "test", "pytest", *session.posargs)


@nox.session
def package(session: nox.Session) -> None:
    session.run("uv", "build", external=True)
