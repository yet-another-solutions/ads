from __future__ import annotations

import inspect

import pytest
from litestar.exceptions import NotAuthorizedException, PermissionDeniedException

from ads.governance.enforcement import Enforcer, EnforcerHolder, require_permission
from ads.security_holder import SecurityContextHolder
from ads_policy.audit import BufferedAuditSink, CollectingAuditSink
from ads_policy.config import GovernanceSettings
from ads_policy.contract import Capability, Effect, IsolationLevel
from ads_policy.service import PolicyService
from tests.policy import (
    ATTRIBUTES,
    DirectPolicyClient,
    journalled,
    run_request,
    security_context,
)


class _AgentTools:
    @require_permission(Capability.FS_READ, resource_arg="path")
    def read_file(self, path: str) -> str:
        return f"contents of {path}"

    @require_permission(Capability.SECRET_READ, resource="ads-client-secret")
    def read_secret(self) -> str:
        return "s3cret"


def _enforcer(
    policy_client: DirectPolicyClient,
    audit: BufferedAuditSink,
    level: IsolationLevel = IsolationLevel.VM,
) -> Enforcer:
    run = policy_client.start_run(run_request(level))
    return Enforcer(client=policy_client, run=run, audit=audit, attributes=ATTRIBUTES)


def test_without_a_security_context_it_is_unauthorized(
    policy_client: DirectPolicyClient, audit: BufferedAuditSink
) -> None:
    with EnforcerHolder.bound(_enforcer(policy_client, audit)):
        with pytest.raises(NotAuthorizedException):
            _AgentTools().read_file("/workspace/src/app.py")


def test_without_an_enforcer_it_fails_closed() -> None:
    with SecurityContextHolder.bound(security_context("user")):
        with pytest.raises(PermissionDeniedException):
            _AgentTools().read_file("/workspace/src/app.py")


def test_a_permitted_call_runs(policy_client: DirectPolicyClient, audit: BufferedAuditSink) -> None:
    with SecurityContextHolder.bound(security_context("user")):
        with EnforcerHolder.bound(_enforcer(policy_client, audit)):
            assert _AgentTools().read_file("/workspace/src/app.py") == (
                "contents of /workspace/src/app.py"
            )


def test_a_denied_call_is_forbidden_and_says_nothing_useful(
    policy_client: DirectPolicyClient, audit: BufferedAuditSink
) -> None:
    with SecurityContextHolder.bound(security_context("user")):
        with EnforcerHolder.bound(_enforcer(policy_client, audit)):
            with pytest.raises(PermissionDeniedException) as denied:
                _AgentTools().read_secret()
    assert denied.value.detail == GovernanceSettings().denied_message
    assert Capability.SECRET_READ.value not in denied.value.detail


def test_the_resource_comes_from_the_named_argument(
    policy_client: DirectPolicyClient,
    audit: BufferedAuditSink,
    service: PolicyService,
    service_journal: CollectingAuditSink,
) -> None:
    with SecurityContextHolder.bound(security_context("user")):
        with EnforcerHolder.bound(_enforcer(policy_client, audit)):
            with pytest.raises(PermissionDeniedException):
                _AgentTools().read_file("/home/dev/other/.env")
    journalled(service)
    assert service_journal.events()[-1].resource == "/home/dev/other/.env"


def test_a_role_is_no_longer_the_unit_of_authorization(
    policy_client: DirectPolicyClient, audit: BufferedAuditSink
) -> None:
    with SecurityContextHolder.bound(security_context()):
        with EnforcerHolder.bound(_enforcer(policy_client, audit)):
            assert _AgentTools().read_file("/workspace/src/app.py").endswith("app.py")


def test_the_caller_cannot_declare_its_own_isolation_level() -> None:
    assert "isolation_level" not in inspect.signature(Enforcer.check).parameters


def test_the_level_of_the_run_decides(
    policy_client: DirectPolicyClient, audit: BufferedAuditSink
) -> None:
    with SecurityContextHolder.bound(security_context("user")):
        with EnforcerHolder.bound(_enforcer(policy_client, audit, IsolationLevel.CONTAINER)):
            denied = EnforcerHolder.require().check(Capability.PROCESS_EXEC, "uv sync")
        with EnforcerHolder.bound(_enforcer(policy_client, audit, IsolationLevel.VM)):
            allowed = EnforcerHolder.require().check(Capability.PROCESS_EXEC, "uv sync")
    assert denied.effect is Effect.DENY
    assert allowed.effect is Effect.ALLOW


def test_another_subject_cannot_use_the_run(
    policy_client: DirectPolicyClient,
    audit: BufferedAuditSink,
    service: PolicyService,
    service_journal: CollectingAuditSink,
) -> None:
    run = policy_client.start_run(run_request(IsolationLevel.VM, subject="bob"))
    enforcer = Enforcer(client=policy_client, run=run, audit=audit, attributes=ATTRIBUTES)
    with SecurityContextHolder.bound(security_context("user")):
        with EnforcerHolder.bound(enforcer):
            with pytest.raises(PermissionDeniedException):
                _AgentTools().read_file("/workspace/src/app.py")
    journalled(service)
    assert service_journal.events()[-1].rule_id == "run.subject"


def test_a_revoked_run_forbids_the_next_call(
    policy_client: DirectPolicyClient, audit: BufferedAuditSink
) -> None:
    run = policy_client.start_run(run_request(IsolationLevel.VM))
    revoked = policy_client.revoke_run(run.id)
    enforcer = Enforcer(client=policy_client, run=revoked, audit=audit, attributes=ATTRIBUTES)
    with SecurityContextHolder.bound(security_context("user")):
        with EnforcerHolder.bound(enforcer):
            with pytest.raises(PermissionDeniedException):
                _AgentTools().read_file("/workspace/src/app.py")


def test_an_answered_call_is_journalled_once(
    policy_client: DirectPolicyClient, audit: BufferedAuditSink, service: PolicyService
) -> None:
    """Only the policy service records what it decided; a copy here would double-count."""
    tools = _AgentTools()
    with SecurityContextHolder.bound(security_context("user")):
        with EnforcerHolder.bound(_enforcer(policy_client, audit)):
            tools.read_file("/workspace/src/app.py")
            with pytest.raises(PermissionDeniedException):
                tools.read_secret()
    assert audit.pending == ()
    assert journalled(service) == 2


def test_the_decorator_keeps_the_signature() -> None:
    assert list(inspect.signature(_AgentTools.read_file).parameters) == ["self", "path"]


def test_the_holder_is_empty_outside_the_binding() -> None:
    assert EnforcerHolder.get() is None
    with pytest.raises(PermissionDeniedException):
        EnforcerHolder.require()
