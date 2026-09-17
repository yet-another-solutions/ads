from __future__ import annotations

from pathlib import Path

import pytest

from ads_guardrail.config import Settings
from ads_guardrail.contract import McpServer
from ads_guardrail.guardrail import Guardrail
from ads_guardrail.logconfig import configure_logging
from ads_policy.audit import BufferedAuditSink, CollectingAuditSink
from ads_policy.client import PolicyClient
from ads_policy.contract import Run
from ads_policy.pdp import PolicyDecisionPoint
from ads_policy.policy import org_policy
from ads_policy.run import InMemoryRunStore
from ads_policy.service import PolicyService
from guardrail_helpers import (
    API_TOKEN,
    AUDIENCE,
    ISSUER,
    KATA_VM_SITE,
    PERSON_TOKEN_VERIFIER,
    InProcessPolicyClient,
    opening,
)


@pytest.fixture(scope="session", autouse=True)
def _logging() -> None:
    configure_logging()


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def policy_service() -> PolicyService:
    journal = BufferedAuditSink(CollectingAuditSink())
    return PolicyService(PolicyDecisionPoint(org_policy()), InMemoryRunStore(), journal)


@pytest.fixture
def policy_client(policy_service: PolicyService) -> PolicyClient:
    return InProcessPolicyClient(policy_service)


@pytest.fixture
def journal() -> CollectingAuditSink:
    return CollectingAuditSink()


@pytest.fixture
def audit(journal: CollectingAuditSink) -> BufferedAuditSink:
    return BufferedAuditSink(journal)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    cert = tmp_path / "tls.crt"
    key = tmp_path / "tls.key"
    cert.write_text("placeholder")
    key.write_text("placeholder")
    return Settings(
        api_token=API_TOKEN,
        tls_cert_path=cert,
        tls_key_path=key,
        policy_url="https://policy.interlab:8081",
        policy_api_token="policy-api-token-32-bytes-long",
        amqp_url="amqp://unused",
        attributes={"repo.write": "true", "agent": "true"},
        mcp_servers=(McpServer("retriever", "http://mcp.invalid/mcp", KATA_VM_SITE),),
        person_token_audience=AUDIENCE,
        keycloak_well_known_url="https://keycloak.test/.well-known/openid-configuration",
        keycloak_issuer=ISSUER,
    )


@pytest.fixture
def guardrail(
    settings: Settings, policy_client: PolicyClient, audit: BufferedAuditSink
) -> Guardrail:
    return Guardrail(
        settings=settings,
        client=policy_client,
        audit=audit,
        person_token_verifier=PERSON_TOKEN_VERIFIER,
    )


@pytest.fixture
def alice_run(guardrail: Guardrail) -> Run:
    return guardrail.open_run(opening())
