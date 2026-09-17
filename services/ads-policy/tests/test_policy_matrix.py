from __future__ import annotations

from ads_policy.config import GovernanceSettings
from ads_policy.contract import Capability, Effect, IsolationLevel
from ads_policy.isolation import assign_isolation_level
from ads_policy.pdp import PolicyDecisionPoint
from policy_helpers import policy_request

ALLOWED_SOMEWHERE = {
    Capability.FS_READ: "/workspace/src/app.py",
    Capability.FS_WRITE: "/workspace/src/app.py",
    Capability.PROCESS_EXEC: "uv sync",
    Capability.NET_EGRESS: "https://mirror.interlab/simple",
    Capability.DB_QUERY: "select 1",
    Capability.DB_MIGRATE: "/workspace/migrations/0001_init.sql",
    Capability.SECRET_READ: "ads-client-secret",
    Capability.VCS_PUSH: "feature/governance",
}


def _effect(
    pdp: PolicyDecisionPoint,
    capability: Capability,
    resource: str,
    level: IsolationLevel,
) -> Effect:
    return pdp.decide(policy_request(capability, resource, level=level)).effect


def test_workdir_reads_and_writes_are_allowed_everywhere(pdp: PolicyDecisionPoint) -> None:
    for level in IsolationLevel:
        assert _effect(pdp, Capability.FS_READ, "/workspace/src/app.py", level) is Effect.ALLOW
        assert _effect(pdp, Capability.FS_WRITE, "/workspace/src/app.py", level) is Effect.ALLOW


def test_reads_outside_the_workdir_are_denied_everywhere(pdp: PolicyDecisionPoint) -> None:
    for level in IsolationLevel:
        assert _effect(pdp, Capability.FS_READ, "/home/dev/other/.env", level) is Effect.DENY


def test_process_exec_is_denied_only_in_a_container(pdp: PolicyDecisionPoint) -> None:
    assert _effect(pdp, Capability.PROCESS_EXEC, "uv sync", IsolationLevel.LOCAL) is Effect.ALLOW
    assert _effect(pdp, Capability.PROCESS_EXEC, "uv sync", IsolationLevel.CONTAINER) is Effect.DENY
    assert _effect(pdp, Capability.PROCESS_EXEC, "uv sync", IsolationLevel.VM) is Effect.ALLOW


def test_internet_egress_is_allowed_only_locally(pdp: PolicyDecisionPoint) -> None:
    target = "https://pypi.org/simple"
    assert _effect(pdp, Capability.NET_EGRESS, target, IsolationLevel.LOCAL) is Effect.ALLOW
    assert _effect(pdp, Capability.NET_EGRESS, target, IsolationLevel.CONTAINER) is Effect.DENY
    assert _effect(pdp, Capability.NET_EGRESS, target, IsolationLevel.VM) is Effect.DENY


def test_allowlisted_egress_is_allowed_everywhere(pdp: PolicyDecisionPoint) -> None:
    for level in IsolationLevel:
        assert (
            _effect(pdp, Capability.NET_EGRESS, "https://mirror.interlab/x", level) is Effect.ALLOW
        )


def test_broker_queries_are_allowed_everywhere(pdp: PolicyDecisionPoint) -> None:
    for level in IsolationLevel:
        assert _effect(pdp, Capability.DB_QUERY, "select 1", level) is Effect.ALLOW


def test_migrations_are_allowed_only_in_a_vm(pdp: PolicyDecisionPoint) -> None:
    migration = "/workspace/migrations/0001_init.sql"
    assert _effect(pdp, Capability.DB_MIGRATE, migration, IsolationLevel.LOCAL) is Effect.DENY
    assert _effect(pdp, Capability.DB_MIGRATE, migration, IsolationLevel.CONTAINER) is Effect.DENY
    assert _effect(pdp, Capability.DB_MIGRATE, migration, IsolationLevel.VM) is Effect.ALLOW


def test_secret_read_is_denied_everywhere(pdp: PolicyDecisionPoint) -> None:
    for level in IsolationLevel:
        assert _effect(pdp, Capability.SECRET_READ, "ads-client-secret", level) is Effect.DENY


def test_feature_branch_push_is_denied_only_in_a_container(pdp: PolicyDecisionPoint) -> None:
    branch = "feature/governance"
    assert _effect(pdp, Capability.VCS_PUSH, branch, IsolationLevel.LOCAL) is Effect.ALLOW
    assert _effect(pdp, Capability.VCS_PUSH, branch, IsolationLevel.CONTAINER) is Effect.DENY
    assert _effect(pdp, Capability.VCS_PUSH, branch, IsolationLevel.VM) is Effect.ALLOW


def test_protected_branch_push_is_denied_everywhere(pdp: PolicyDecisionPoint) -> None:
    for level in IsolationLevel:
        assert _effect(pdp, Capability.VCS_PUSH, "main", level) is Effect.DENY


def test_container_and_vm_differ_in_exec_migrate_and_push(pdp: PolicyDecisionPoint) -> None:
    differing = {
        capability
        for capability, resource in ALLOWED_SOMEWHERE.items()
        if _effect(pdp, capability, resource, IsolationLevel.CONTAINER)
        is not _effect(pdp, capability, resource, IsolationLevel.VM)
    }
    assert differing == {Capability.PROCESS_EXEC, Capability.DB_MIGRATE, Capability.VCS_PUSH}


def test_without_a_sandbox_the_vm_only_rows_are_out_of_reach(pdp: PolicyDecisionPoint) -> None:
    without = GovernanceSettings(sandbox_available=False)
    claimed = assign_isolation_level(
        runtime_class_name=without.vm_runtime_class,
        node_labels={
            without.sandbox_node_label: without.node_label_value,
            without.application_node_label: without.node_label_value,
        },
        settings=without,
    )
    assert claimed is IsolationLevel.CONTAINER
    for capability, resource in (
        (Capability.PROCESS_EXEC, "uv sync"),
        (Capability.DB_MIGRATE, "/workspace/migrations/0001_init.sql"),
        (Capability.VCS_PUSH, "feature/governance"),
    ):
        assert _effect(pdp, capability, resource, claimed) is Effect.DENY


def test_db_write_and_deploy_are_not_capabilities() -> None:
    values = {capability.value for capability in Capability}
    assert "db.write" not in values
    assert "deploy" not in values


def test_every_capability_has_a_row(pdp: PolicyDecisionPoint) -> None:
    assert set(ALLOWED_SOMEWHERE) == set(Capability)
