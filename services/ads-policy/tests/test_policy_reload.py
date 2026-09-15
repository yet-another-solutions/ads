from __future__ import annotations

from pathlib import Path

import msgspec
import pytest

from ads_policy.config import GovernanceSettings
from ads_policy.contract import Capability, Effect, IsolationLevel, RunState, Scope
from ads_policy.pdp import PolicyDecisionPoint
from ads_policy.policy import org_policy, reload_policy
from ads_policy.run import InMemoryRunStore
from policy_helpers import policy_request, run_context

TIGHTENED = """
version: org-2
rules:
  - id: process.exec
    capability: process.exec
    scope: any
    levels: []
"""


def _settings(tmp_path: Path) -> GovernanceSettings:
    return GovernanceSettings(policy_dir=tmp_path)


def _pdp(settings: GovernanceSettings) -> PolicyDecisionPoint:
    return PolicyDecisionPoint(org_policy(settings), settings)


def test_no_document_leaves_the_built_in_matrix(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    pdp = _pdp(settings)
    before = pdp.policy_hash
    assert reload_policy(pdp, settings) is None
    assert pdp.policy_hash == before


def test_an_edited_document_is_published(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    pdp = _pdp(settings)
    before = pdp.policy_hash
    (tmp_path / "policy.yaml").write_text(TIGHTENED)

    published = reload_policy(pdp, settings)

    assert published is not None
    assert published != before
    assert pdp.policy.version == "org-2"
    decision = pdp.decide(policy_request(Capability.PROCESS_EXEC, "ls", level=IsolationLevel.VM))
    assert decision.effect is Effect.DENY


def test_an_unchanged_document_is_not_republished(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    pdp = _pdp(settings)
    (tmp_path / "policy.yaml").write_text(TIGHTENED)

    first = reload_policy(pdp, settings)

    assert first is not None
    assert reload_policy(pdp, settings) is None
    assert pdp.policy_hash == first


def test_an_unreadable_document_keeps_the_current_version(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    pdp = _pdp(settings)
    before = pdp.policy_hash
    (tmp_path / "policy.yaml").write_text("rules: [ this is not a rule")

    with pytest.raises(msgspec.DecodeError):
        reload_policy(pdp, settings)

    assert pdp.policy_hash == before
    allowed = pdp.decide(policy_request(Capability.FS_READ, f"{settings.workdir}/main.py"))
    assert allowed.effect is Effect.ALLOW


@pytest.mark.anyio
async def test_a_rule_the_new_version_drops_is_not_applied_to_a_pinned_run(tmp_path: Path) -> None:
    """A run decides under the version it started with, reload or no reload."""
    settings = _settings(tmp_path)
    pdp = _pdp(settings)
    store = InMemoryRunStore()
    run = await store.start(
        subject="alice",
        context=run_context(),
        isolation_level=IsolationLevel.VM,
        policy_hash=pdp.policy_hash,
    )
    (tmp_path / "policy.yaml").write_text(TIGHTENED)
    assert reload_policy(pdp, settings) is not None

    pinned = pdp.decide_for_run(
        run, policy_request(Capability.PROCESS_EXEC, "ls", level=IsolationLevel.VM)
    )
    current = pdp.decide(policy_request(Capability.PROCESS_EXEC, "ls", level=IsolationLevel.VM))

    assert run.state is RunState.RUNNING
    assert pinned.effect is Effect.ALLOW
    assert current.effect is Effect.DENY
    assert pdp.policy.rule_for(Capability.PROCESS_EXEC, Scope.ANY) is not None
