from __future__ import annotations

import asyncio
import time
from collections.abc import Coroutine
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from typing import Any

import jwt
import msgspec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from ads_commons_beans import JwtVerifier, JwtVerifierSettings
from ads_guardrail.contract import Opening, Workspace
from ads_policy.config import GovernanceSettings
from ads_policy.contract import (
    DecisionRequest,
    Placement,
    PolicyDecision,
    Run,
    RunRequest,
    Site,
    ToolCallRequest,
)
from ads_policy.service import PolicyService

API_TOKEN = "guardrail-api-token-32-bytes"
GOVERNANCE = GovernanceSettings()
WORKDIR_FILE = f"{GOVERNANCE.workdir}/src/app.py"

WORKSPACE = Workspace(
    project="ads", repo="yet-another-solutions/ads", env="dev", workdir=GOVERNANCE.workdir
)

KATA_VM_SITE = Site(
    placement=Placement.CLUSTER,
    runtime_class_name=GOVERNANCE.vm_runtime_class,
    node_labels={
        GOVERNANCE.sandbox_node_label: GOVERNANCE.node_label_value,
        GOVERNANCE.application_node_label: GOVERNANCE.node_label_value,
    },
)
APPLICATION_NODE_SITE = Site(
    placement=Placement.CLUSTER,
    node_labels={GOVERNANCE.application_node_label: GOVERNANCE.node_label_value},
)
WORKSTATION_SITE = Site(placement=Placement.WORKSTATION)
KATA_ON_UNLABELLED_NODE_SITE = Site(
    placement=Placement.CLUSTER, runtime_class_name=GOVERNANCE.vm_runtime_class
)

ISSUER = "https://keycloak.test/realms/ads"
AUDIENCE = "ads-mcp"
ALICE = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
BOB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

KEYCLOAK_SIGNING_KEY: RSAPrivateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
FORGING_KEY: RSAPrivateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def person_token(
    sub: str = ALICE,
    *,
    key: RSAPrivateKey = KEYCLOAK_SIGNING_KEY,
    issued_seconds_from_now: int = 0,
    **claims: Any,
) -> str:
    now = int(time.time()) + issued_seconds_from_now
    payload: dict[str, Any] = {
        "sub": sub,
        "name": "Alice" if sub == ALICE else "Bob",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "azp": "ads-sandbox",
        "iat": now,
        "exp": now + 300,
    }
    payload.update(claims)
    return jwt.encode(payload, key, algorithm="RS256")


class _KeycloakSigningKeys:
    def get_signing_key_from_jwt(self, token: str) -> SimpleNamespace:
        return SimpleNamespace(key=KEYCLOAK_SIGNING_KEY.public_key())


PERSON_TOKEN_VERIFIER = JwtVerifier(
    JwtVerifierSettings(
        issuer=ISSUER,
        audience=AUDIENCE,
        client_id=AUDIENCE,
        jwks_uri="https://keycloak.test/certs",
        ssl_context=None,
    ),
    _KeycloakSigningKeys(),
)

APPLICATION_KEY = "api-server-key-of-the-application"
ALICE_TOKEN = person_token()


def opening(bearer: str = ALICE_TOKEN, workspace: Workspace = WORKSPACE) -> Opening:
    return Opening(bearer=bearer, workspace=workspace)


def opening_body(bearer: str = ALICE_TOKEN) -> dict[str, Any]:
    return dict(msgspec.to_builtins(opening(bearer)))


def run_blocking[T](coroutine: Coroutine[Any, Any, T]) -> T:
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coroutine).result()


class InProcessPolicyClient:
    def __init__(self, service: PolicyService) -> None:
        self.service = service

    def start_run(self, request: RunRequest) -> Run:
        return run_blocking(self.service.start(request))

    def run(self, run_id: str) -> Run | None:
        return run_blocking(self.service.run(run_id))

    def runs_held(self, holder: str) -> list[Run]:
        return run_blocking(self.service.held_by(holder))

    def finish_run(self, run_id: str) -> Run | None:
        return run_blocking(self.service.finish(run_id))

    def revoke_run(self, run_id: str) -> Run:
        run = run_blocking(self.service.revoke(run_id))
        if run is None:
            raise KeyError(run_id)
        return run

    def decide(self, request: DecisionRequest) -> PolicyDecision:
        return run_blocking(self.service.decide(request))

    def decide_call(self, call: ToolCallRequest) -> PolicyDecision:
        return run_blocking(self.service.decide_call(call))


class UnreachablePolicyClient:
    def start_run(self, request: RunRequest) -> Run:
        raise ConnectionError("no route to the policy service")

    def run(self, run_id: str) -> Run | None:
        raise ConnectionError("no route to the policy service")

    def runs_held(self, holder: str) -> list[Run]:
        raise ConnectionError("no route to the policy service")

    def finish_run(self, run_id: str) -> Run | None:
        raise ConnectionError("no route to the policy service")

    def revoke_run(self, run_id: str) -> Run:
        raise ConnectionError("no route to the policy service")

    def decide(self, request: DecisionRequest) -> PolicyDecision:
        raise ConnectionError("no route to the policy service")

    def decide_call(self, call: ToolCallRequest) -> PolicyDecision:
        raise ConnectionError("no route to the policy service")
