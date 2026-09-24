# Paired IPC publication

This internal slice-19 component publishes the existing IPC PID/revision PVC
and fixed ordinary-runtime manager-owned Pod. Paired creation calls this publisher;
publication does not assert readiness, delete resources or claim runtime release.
The user-approved Pod ownership change replaces Deployment/ReplicaSet child
creation with the same fenced one-shot manager writer used by other pair resources.

## Committed ownership

The existing pair intent carries an `ipc_resources` map for `volume` and `pod`.
Each entry holds the complete nonsecret immutable payload, observed UID and
unissued/inflight/settled dispatch evidence. Fresh-schema initialization adds the
schema and a distinct `SandboxSession.ipc_pod_uid`; there is no old-schema
migration, Deployment adoption or backfill. Legacy unpaired fixtures continue
using their separate `ipc_deployment_uid`.

Publication requires the current creating claim, all eight bound settled controls,
four bound settled compute Pods with committed payloads, both immutable relay
inputs and paired-key custody, and the anchored egress state. SQL dependency
checks include the current workspace/CA/state bindings. Kubernetes dependency
checks re-read exact compute/control/custody/input identities and contents before
and after publication. The Pod additionally requires the settled IPC PVC.

Reservation commits before unlocked API I/O. Only its winning original task may
create, and only normal return permits that task to settle its own dispatch.
Caller cancellation does not cancel the retained task. Lost replies, shutdown and
commit failures cannot turn inflight into unissued or authorize another create.
Observation may bind an exact UID but cannot settle an ambiguous write.

UID binding updates pair intent and existing session IPC UID fields atomically.
Untracked legacy session UIDs, changed subjects/manifests, wrong claims, replacement
UIDs and missing bound resources fail closed without adoption or repair.

## Observation and cleanup

Pod comparison accepts narrow Kubernetes defaults, numeric quantity equivalence,
the exact service-account alias and scheduling's nonempty node assignment.
It rejects additive containers, host networking, token authority, all annotations
(including rollout revisions), changed Secret modes, ports and probes. Existing
IPC credentials, TLS, limits, application-node selector and health checks remain.

The committed Pod uses `restartPolicy: Always` and the existing grace period.
Its projected ServiceAccount token, API CA and namespace mount are explicit at
the existing in-cluster SDK path; implicit token injection is disabled. The
token request is Pod-bound, rotating, API-audience default and one hour, not a
static token Secret. The existing shared Helm ServiceAccount and bound-Pod exec
admission remain, with no new permissions. Kubernetes supports explicit rotating
token projections ([ServiceAccounts](https://kubernetes.io/docs/concepts/security/service-accounts/)).

An absent or replaced bound Pod cannot be recreated by publisher retries or a
restarted manager. Only fenced whole-pair recovery can replace its ownership.
This component does not yet complete that recovery/retirement path.

Cleanup snapshots retain payload, UID and dispatch. The existing cleanup or
recovery claim permanently fences creators before named metadata-only observation.
Late IPC writes remain owned; deleting or content-drifted owned objects are still
captured. Absence never erases a known UID, settles a writer, completes cleanup or
proves that a runtime is gone.

Ordered teardown, positive node release, persistent-state transfer/retirement and
credential-preserving reset remain separate required slice-19 work. Actual egress
data-plane behavior and final live integration retain their later-slice boundaries.
