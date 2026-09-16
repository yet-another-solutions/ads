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
from ads_guardrail.contract import Opening, Sandbox
from ads_policy.config import GovernanceSettings
from ads_policy.contract import (
    DecisionRequest,
    Placement,
    PolicyDecision,
    Run,
    RunRequest,
    ToolCallRequest,
)
from ads_policy.service import PolicyService

TOKEN = "guardrail-api-token-32-bytes"
GOVERNANCE = GovernanceSettings()

#: A Kata pod on a sandbox node, as the launcher that created it describes it.
VM_SANDBOX = Sandbox(
    project="ads",
    repo="yet-another-solutions/ads",
    env="dev",
    workdir=GOVERNANCE.workdir,
    placement=Placement.CLUSTER,
    runtime_class_name=GOVERNANCE.vm_runtime_class,
    node_labels={
        GOVERNANCE.sandbox_node_label: GOVERNANCE.node_label_value,
        GOVERNANCE.application_node_label: GOVERNANCE.node_label_value,
    },
)
WORKSTATION = msgspec.structs.replace(
    VM_SANDBOX, placement=Placement.WORKSTATION, runtime_class_name=None, node_labels={}
)

ISSUER = "https://keycloak.test/realms/ads"
#: Who the sandbox service's tokens are issued for.
AUDIENCE = "ads-mcp"
ALICE = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
BOB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

#: Keycloak's signing key, and one that is not Keycloak's.
SIGNING_KEY: RSAPrivateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
FORGING_KEY: RSAPrivateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def token(
    sub: str = ALICE, *, key: RSAPrivateKey = SIGNING_KEY, issued: int = 0, **claims: Any
) -> str:
    """A person's access token. ``issued`` shifts it in time, as a refresh would."""
    now = int(time.time()) + issued
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


class _KeycloakKeys:
    def get_signing_key_from_jwt(self, token: str) -> SimpleNamespace:
        return SimpleNamespace(key=SIGNING_KEY.public_key())


VERIFIER = JwtVerifier(
    JwtVerifierSettings(
        issuer=ISSUER,
        audience=AUDIENCE,
        client_id=AUDIENCE,
        jwks_uri="https://keycloak.test/certs",
        ssl_context=None,
    ),
    _KeycloakKeys(),
)

#: What hermes calls its MCP servers with: the application's own key, not a person's.
APP_KEY = "api-server-key-of-the-application"
#: What our sandbox service calls with: the token of the person it acts for.
USER_TOKEN = token()


def opening(sandbox: Sandbox = VM_SANDBOX, bearer: str = USER_TOKEN) -> Opening:
    return Opening(bearer=bearer, sandbox=sandbox)


def opening_body(sandbox: Sandbox = VM_SANDBOX, bearer: str = USER_TOKEN) -> dict[str, Any]:
    return dict(msgspec.to_builtins(opening(sandbox, bearer)))


def blocking[T](coroutine: Coroutine[Any, Any, T]) -> T:
    """The guardrail is synchronous, so the policy service runs on a loop of its own."""
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coroutine).result()


class DirectPolicyClient:
    """The policy service without the network, for tests that are not about transport."""

    def __init__(self, service: PolicyService) -> None:
        self.service = service

    def start_run(self, request: RunRequest) -> Run:
        return blocking(self.service.start(request))

    def run(self, run_id: str) -> Run | None:
        return blocking(self.service.run(run_id))

    def runs_held(self, holder: str) -> list[Run]:
        return blocking(self.service.held_by(holder))

    def finish_run(self, run_id: str) -> Run | None:
        return blocking(self.service.finish(run_id))

    def revoke_run(self, run_id: str) -> Run:
        run = blocking(self.service.revoke(run_id))
        if run is None:
            raise KeyError(run_id)
        return run

    def decide(self, request: DecisionRequest) -> PolicyDecision:
        return blocking(self.service.decide(request))

    def decide_call(self, call: ToolCallRequest) -> PolicyDecision:
        return blocking(self.service.decide_call(call))


class RefusingPolicyClient:
    """Stands in for a policy service that cannot be reached at all."""

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
