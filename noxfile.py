from __future__ import annotations

import os

import nox

nox.options.default_venv_backend = "uv"
nox.options.sessions = ["lint", "deps", "typecheck", "test", "package"]

_SRC = (
    "charts/ads/package_release.py",
    "charts/ads/tests",
    "deploy/tests",
    "deploy/keycloak/tests",
    "services/ads-sandbox-base/scripts/ads-session-device-check",
    "services/ads-sandbox-base/scripts/ads-sandbox-runtime",
    "services/ads-sandbox-base/scripts/ads-agent-init",
    "services/ads-sandbox-golden/scripts/ads-session-device-check",
    "libraries/ads-commons/src",
    "libraries/ads-commons/tests",
    "libraries/ads-commons-beans/src",
    "libraries/ads-commons-beans/tests",
    "libraries/ads-commons-schema/src",
    "libraries/ads-commons-schema/tests",
    "services/ads/src",
    "services/ads/tests",
    "services/ads-audit/src",
    "services/ads-audit/tests",
    "services/ads-engine/src",
    "services/ads-engine/tests",
    "services/ads-egress-controlplane/src",
    "services/ads-guardrail/src",
    "services/ads-guardrail/tests",
    "services/ads-injection-scanner/src",
    "services/ads-injection-scanner/tests",
    "services/ads-mcp-probe/src",
    "services/ads-mcp-probe/tests",
    "services/ads-policy/src",
    "services/ads-policy/tests",
    "services/ads-preferences/src",
    "services/ads-preferences/tests",
    "services/ads-context-meter/src",
    "services/ads-context-compactor/src",
    "libraries/ads-context-runtime/src",
    "services/ads-context-meter/tests",
    "services/ads-context-compactor/tests",
    "libraries/ads-context-runtime/tests",
    "services/ads-sandbox-mcp/src",
    "services/ads-sandbox-mcp/tests",
    "services/ads-sandbox-ipc/src",
    "services/ads-sandbox-ipc/tests",
    "services/ads-sandbox-manager/src",
    "services/ads-sandbox-manager/tests",
    "tests/chain",
    "noxfile.py",
)

_PACKAGES = (
    "services/ads",
    "services/ads-engine",
    "libraries/ads-commons",
    "libraries/ads-commons-beans",
    "libraries/ads-commons-schema",
    "services/ads-audit",
    "services/ads-guardrail",
    "services/ads-injection-scanner",
    "services/ads-mcp-probe",
    "services/ads-policy",
    "services/ads-preferences",
    "services/ads-context-meter",
    "services/ads-context-compactor",
    "libraries/ads-context-runtime",
    "services/ads-sandbox-mcp",
    "services/ads-sandbox-ipc",
    "services/ads-sandbox-manager",
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
    session.run("uv", "build", "--package", "ads-commons-beans", external=True)
    session.run("uv", "build", "--package", "ads-commons-schema", external=True)
    session.run("uv", "build", "--package", "ads-engine", external=True)
    session.run("uv", "build", "--package", "ads-egress-controlplane", external=True)
    session.run("uv", "build", "--package", "ads-policy", external=True)
    session.run("uv", "build", "--package", "ads-audit", external=True)
    session.run("uv", "build", "--package", "ads-preferences", external=True)
    session.run("uv", "build", "--package", "ads-guardrail", external=True)
    session.run("uv", "build", "--package", "ads-mcp-probe", external=True)
    session.run("uv", "build", "--package", "ads-injection-scanner", external=True)
    session.run("uv", "build", "--package", "ads-context-meter", external=True)
    session.run("uv", "build", "--package", "ads-context-compactor", external=True)
    session.run("uv", "build", "--package", "ads-context-runtime", external=True)
    session.run("uv", "build", "--package", "ads-sandbox-mcp", external=True)
    session.run("uv", "build", "--package", "ads-sandbox-ipc", external=True)
    session.run("uv", "build", "--package", "ads-sandbox-manager", external=True)
