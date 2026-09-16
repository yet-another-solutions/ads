from __future__ import annotations

from pathlib import Path

import pytest

from ads_policy.audit import BufferedAuditSink, CollectingAuditSink
from ads_policy.client import PolicyClient
from ads_policy.contract import IsolationLevel
from ads_policy.pdp import PolicyDecisionPoint
from ads_policy.policy import org_policy
from ads_policy.run import InMemoryRunStore
from ads_policy.service import PolicyService
from ads_supervisor.config import Settings
from ads_supervisor.logconfig import configure_logging
from ads_supervisor.supervisor import Supervisor
from supervisor_helpers import TOKEN, VM_SANDBOX, DirectPolicyClient


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
    return DirectPolicyClient(policy_service)


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
        api_token=TOKEN,
        tls_cert_path=cert,
        tls_key_path=key,
        subject="alice",
        policy_url="https://policy.interlab:8081",
        policy_api_token="policy-api-token-32-bytes-long",
        amqp_url="amqp://unused",
        attributes={"repo.write": "true", "agent": "true"},
        mcp_servers={"retriever": "http://mcp.invalid/mcp"},
    )


@pytest.fixture
def run_id(supervisor: Supervisor) -> str:
    """The launcher opens one of these per task; the id then rides with every call."""
    return supervisor.open(VM_SANDBOX).id


@pytest.fixture
def supervisor(
    settings: Settings, policy_client: PolicyClient, audit: BufferedAuditSink
) -> Supervisor:
    return Supervisor(settings=settings, client=policy_client, audit=audit)


@pytest.fixture
def vm_level() -> IsolationLevel:
    return IsolationLevel.VM
