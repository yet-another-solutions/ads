from __future__ import annotations

import os

import nox

os.environ.setdefault("UV_DEFAULT_INDEX", "https://pypi.org/simple")

nox.options.default_venv_backend = "uv"
nox.options.sessions = ["lint", "deps", "typecheck", "test", "package"]

_SRC = (
    "libraries/ads-commons/src",
    "libraries/ads-commons/tests",
    "services/ads/src",
    "services/ads/tests",
    "services/ads-engine/src",
    "services/ads-engine/tests",
    "services/ads-egress-controlplane/src",
    "services/ads-preferences/src",
    "services/ads-preferences/tests",
    "noxfile.py",
)

_PACKAGES = (
    "services/ads",
    "services/ads-engine",
    "libraries/ads-commons",
    "services/ads-preferences",
)


def _uv_run(session: nox.Session, *args: str) -> None:
    session.run("uv", "run", *args, external=True)


@nox.session
def lint(session: nox.Session) -> None:
    session.run("uv", "sync", "--group", "lint", external=True)
    _uv_run(session, "--group", "lint", "ruff", "check", *_SRC)
    _uv_run(session, "--group", "lint", "ruff", "format", "--check", *_SRC)


@nox.session
def deps(session: nox.Session) -> None:
    session.run("uv", "sync", "--group", "deps", external=True)
    root = os.getcwd()
    for package in _PACKAGES:
        session.chdir(package)
        session.run(
            "uv",
            "run",
            "--project",
            root,
            "--group",
            "deps",
            "deptry",
            "src",
            external=True,
        )
        session.chdir(root)


@nox.session
def typecheck(session: nox.Session) -> None:
    session.run("uv", "sync", "--group", "typecheck", external=True)
    _uv_run(session, "--group", "typecheck", "mypy")


@nox.session
def test(session: nox.Session) -> None:
    session.run("uv", "sync", "--group", "test", external=True)
    _uv_run(session, "--group", "test", "pytest", *session.posargs)


@nox.session
def package(session: nox.Session) -> None:
    session.run("uv", "build", "--package", "ads", external=True)
    session.run("uv", "build", "--package", "ads-commons", external=True)
    session.run("uv", "build", "--package", "ads-engine", external=True)
    session.run("uv", "build", "--package", "ads-egress-controlplane", external=True)
    session.run("uv", "build", "--package", "ads-preferences", external=True)
