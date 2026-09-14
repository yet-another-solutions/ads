from __future__ import annotations

import fakeredis
import pytest
from redis.asyncio import Redis

from ads_policy.audit import BufferedAuditSink, CollectingAuditSink
from ads_policy.config import GovernanceSettings
from ads_policy.contract import Policy
from ads_policy.logconfig import configure_logging
from ads_policy.pdp import PolicyDecisionPoint
from ads_policy.policy import org_policy
from ads_policy.run import RedisRunStore, RunStore
from ads_policy.service import PolicyService

_NO_ROOM = GovernanceSettings(audit_backlog=0)


@pytest.fixture(scope="session", autouse=True)
def _logging() -> None:
    configure_logging()


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def policy() -> Policy:
    return org_policy()


@pytest.fixture
def pdp(policy: Policy) -> PolicyDecisionPoint:
    return PolicyDecisionPoint(policy)


@pytest.fixture
def journal() -> CollectingAuditSink:
    """Stands in for the audit exchange: whatever was published lands here."""
    return CollectingAuditSink()


@pytest.fixture
def audit(journal: CollectingAuditSink) -> BufferedAuditSink:
    return BufferedAuditSink(journal)


@pytest.fixture
def redis() -> Redis:
    """Redis in process, with the real expiry semantics and no container."""
    return fakeredis.FakeAsyncRedis()


@pytest.fixture
def runs(redis: Redis) -> RunStore:
    return RedisRunStore(redis)


@pytest.fixture
def service(pdp: PolicyDecisionPoint, runs: RunStore, audit: BufferedAuditSink) -> PolicyService:
    return PolicyService(pdp, runs, audit)


@pytest.fixture
def pdp_service_with_full_backlog(
    pdp: PolicyDecisionPoint, runs: RunStore, journal: CollectingAuditSink
) -> PolicyService:
    """A journal that accepts nothing more, so decisions have nowhere to be recorded."""
    return PolicyService(pdp, runs, BufferedAuditSink(journal, _NO_ROOM))
