# Slice 19 implementation and evidence boundary

This document maps the CA/pair lifecycle and credential-preserving reset
obligations to implementation and regression evidence. It is not a second
slice tracker. The canonical Project tracker remains open; the current
continuation permits local implementation, a completed-feature push and
exact-head non-publish CI/review, but explicitly prohibits merging or live
deployment/reset.

## Lifecycle proof matrix

Paths below are relative to `services/ads-sandbox-manager/` unless stated
otherwise. Tests use actual repositories and adapters with temporary PostgreSQL;
Kubernetes, node-owner, Kafka and provider boundaries are simulated where named.
An adapter/unit result does not prove live CSI, native or Kata behavior.

| Obligation | Implementation and evidence |
| --- | --- |
| Ordered creation and readiness | `src/ads_sandbox_manager/pair_creation.py`, `pair_ready.py`; `tests/test_pair_creation.py`, `test_pair_ipc_publication.py`, `test_pair_volume_publication.py`, `test_pair_controls.py`. Ready requires original settled publications and authenticated IPC transition. |
| Original writer settlement | `pair_store.py`, `pair_cleanup.py`, `lifecycle_store.py`; `test_pair_dispatch_completion.py`, `test_pair_cleanup_writers.py`, `test_pair_creator_fence.py`. Caller/claim loss cannot clear an original in-flight writer or authorize replay. |
| Original IPC and private runtime | `pair_runtime_teardown.py`, `node_owner.py`; `test_pair_runtime_teardown.py`, `test_pair_ipc_removal.py`, `test_pair_node_proof.py`, `test_node_owner.py`, `test_node_owner_tls.py`. IPC release precedes private compute deletion; fixed mTLS operations bind original node, boot, UIDs and inventory. |
| Supported partial starts | `pair_unscheduled_proof.py`, `pair_unused_storage.py` and partial runtime composition; `test_pair_unissued_runtime.py`, `test_pair_unscheduled_runtime.py`, `test_pair_partial_runtime.py`, `test_pair_unused_storage.py`. Positive never-issued/never-scheduled history is distinct from missing history. |
| IPC filesystem release/reclamation | `pair_ipc_storage.py`, `pair_unused_storage.py`; `test_pair_ipc_storage.py`, `test_unused_ipc_storage.py`, `test_ipc_storage_channel.py`; root helper tests in `deploy/tests/test_ipc_storage.py`. Retained export handles distinguish actual reclamation from rename, open deleted inodes and API disappearance. |
| Private Block storage | `pair_block_storage.py`, `pair_unused_proof.py`; `test_pair_block_storage.py`, `test_pair_unused_storage.py`; `deploy/tests/test_block_release.py`. Original device mappings, host references and CSI identities precede exact PVC deletion and protected driver reclamation. |
| Controls, credentials and topics | `pair_resource_teardown.py`, `pair_resource_proof.py`; `test_pair_resource_teardown.py`. Isolation remains until runtime/storage obligations finish. Only original UID-bound controls and transient custody are removed; idle preserves wrapping custody and topics. |
| Irreversible retirement | `pair_retirement.py`; `test_pair_retirement.py`, `test_pair_completion.py`. Non-cascading journal/tombstone, atomic completion, one active generation and permanent stale creator/ready refusal. |
| Retained transfer/resume | `pair_transfer.py`, `pair_creation.py`; `test_pair_transfer.py`, `test_pair_resume.py`. Same workspace/state UUID, original volume UID and wrapping fingerprint; new attachment and transient relay keys. Missing/replaced custody is never recreated. |
| Failed-resume lineage | `pair_inherited_storage.py`; `test_pair_inherited_storage.py`. A new never-started consumer does not make previously mounted inherited storage “never mounted”; fresh release observes the verified predecessor's original Block capture. |
| Destructive recovery | `recovery.py`; `test_pair_completion.py`, `test_ping_recovery.py`, `test_pair_recovery_capture.py`. Old storage/topics and generation retire before a fresh sandbox/PVC/state identity is admitted. No execution replay. |
| Retained expiry | `pair_disposal.py`, `lifecycle_store.py`; `test_pair_disposal.py`. Resume/reap serialize on original scope; an irreversible disposal receipt excludes later transfer even after work/session loss. |
| Orphans, maintenance and watchdog | `pair_registry.py`, `lifecycle.py`; `test_pair_registry.py`, `test_pair_cleanup_intent.py`, `test_lifecycle.py`. Durable exact ledger is paired inventory, not arbitrary labels/Secret listing. Retired lifetimes cannot reenter legacy maintenance; unknown paired markers confer no legacy deletion authority. |

## Unsupported evidence stays quarantined

Unsettled original remote writes, lost original runtime history, changed node
boot, substituted UIDs, unreadable host references, unsupported filesystem
handles/provisioners, and contradictory storage ownership do not become empty
success. The existing evidence and creator fence remain retained. A timeout,
API 404, regenerated key or newly reconstructed inventory cannot replace the
missing original proof.

This is not a promised automatic recovery across loss of trusted node history.
Such a case needs an independently authorized and sufficient recovery procedure.
Ordinary supported publication prefixes instead use explicit positive runtime
or never-started evidence and converge through their corresponding storage path.
Shared golden/CA source volumes and platform signer material are never per-pair
cleanup targets.

## Permission decision

The user explicitly authorized the manager to get/create/delete Secrets in
`sandbox.namespace`, accepting get access to the configured signer in that same
namespace. Secret list/watch/update/patch remain absent. Signer custody is not
copied or relocated. Manager pods/exec and general node/PV mutation remain absent.
The chart assertion in `charts/ads/tests/test_chart.py` records the exact verbs
and namespace alongside required paired Pod, Service, NetworkPolicy and PodGroup
permissions.

## Reset proof matrix

The operator entrypoint is `deploy/reset/cli.py`; its runbook is
[credential-preserving reset](../deploy/reset/README.md). No real credentials are
embedded in the tool, its tests or this evidence document.

| Gate | Implementation and regression |
| --- | --- |
| Complete external preservation | `protected.py`, `models.py`; `test_reset_preservation.py`. Private owner/mode/no-link checks, authenticated encryption, verified nonempty roundtrip, refresh, empty-source protection and exclusive operator lock. |
| Exact schema scope | `database.py`; `test_reset_database.py`. Explicit service/database/owner, service-owned mapped tables rather than shared metadata, database/schema identity, unknown-object and connected-writer refusal, RESTRICT reset, ordinary fresh initialization and grant preservation. |
| Writer/controller fencing | `workloads.py`; `test_reset_adapters.py`. Original namespace/workload UID and selector, zero desired/observed replicas and no remaining Pods; HPA/operator/identity changes block. |
| Owner-correct restoration | `preferences.py`, `models.py`; `test_reset_adapters.py`, `test_reset_database.py`, `test_reset_preservation.py`. Protected rotating owner refresh, exact userinfo subject, fresh STE, supported model API, full field verification, generated-ID idempotency and lost-create recovery. |
| Repeatable coordinator | `coordinator.py`; `test_reset_coordinator.py`. Durable phases around reset/initialization/restoration/resumption, preserved credentials after interruptions, refusal of a new cycle while unfinished, repeated completed cycles and empty-source recovery. |
| Safe continuation | `coordinator.py`, `cli.py`; `test_reset_coordinator.py`, `test_reset_cli.py`. Sanitized failures, minimal tool-free authenticated provider hook, dependent writers blocked on restore failure, persistent manager/MCP quarantine after reset. |

The provider hook is implemented but synthetic test invocation is not live
provider evidence. Historical association backups remain encrypted externally;
an empty registry never authorizes deleting historical Kubernetes objects.
Controller resumption requires separately authorized reconciliation. Helm
rollback does not undo a database reset.

## Verification status

The corrected cumulative Nox lint/deps/typecheck/test/package invocation passed:
4,434 tests and four subtests passed, with two Keycloak TLS Testcontainers tests
skipped because the Computer runner has no Docker executable. They remain in
the suite and are applicable to Docker-equipped CI. The suite emitted 2,088
existing framework/deprecation warnings. The test gate took 27m33s, so the CI
Python job allowance is 60 minutes; application deadlines are unchanged.

The first cumulative run exposed a reset shared-metadata isolation defect and
older lifecycle expectations. Corrections retain all security assertions and
add cross-service reset scope, explicit target/environment, original settlement
versus retirement, maintenance exclusion and bounded scan progress regressions.
The isolated reset and lifecycle correction suites each passed 41 tests; these
overlap the cumulative total and must not be added to it.

The Helm suite passed all 31 tests. Each temporary rootless PostgreSQL store was
force-reset to a tiny empty store and its listener verified absent; additional
isolated correction databases were deleted. Exact-head image/Helm/kernel CI and
final PR review remain to be recorded separately before claiming this
continuation ready.

The privileged network-disabled kernel smoke programs are wired into the
existing CI image job, not replaced by unit mocks. They have not been executed
in this Computer sandbox. No merge, published candidate, lab revision, real
provider invocation, repeated live reset or native/Kata/CSI live acceptance is
claimed. Later data-plane and full integration slices remain separate.
