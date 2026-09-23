# Paired IPC publication

This internal slice-19 component publishes the existing IPC PID/revision PVC
and fixed ordinary-runtime Deployment. It does not activate a production caller,
assert readiness, delete resources or claim runtime release.

## Committed ownership

The existing pair intent carries an `ipc_resources` map for volume and Deployment.
Each entry holds the complete nonsecret immutable payload, observed UID and
unissued/inflight/settled dispatch evidence. Fresh-schema initialization adds the
column; there is no legacy adoption or backfill.

Publication requires the current creating claim, all eight bound settled controls,
four bound settled compute Pods with committed payloads, both immutable relay
inputs and paired-key custody, and the anchored egress state. SQL dependency
checks include the current workspace/CA/state bindings. Kubernetes dependency
checks re-read exact compute/control/custody/input identities and contents before
and after publication. The Deployment additionally requires the settled IPC PVC.

Reservation commits before unlocked API I/O. Only its winning original task may
create, and only normal return permits that task to settle its own dispatch.
Caller cancellation does not cancel the retained task. Lost replies, shutdown and
commit failures cannot turn inflight into unissued or authorize another create.
Observation may bind an exact UID but cannot settle an ambiguous write.

UID binding updates pair intent and existing session IPC UID fields atomically.
Untracked legacy session UIDs, changed subjects/manifests, wrong claims, replacement
UIDs and missing bound resources fail closed without adoption or repair.

## Observation and cleanup

Deployment comparison accepts narrow Kubernetes defaults, numeric quantity
equivalence, the exact service-account alias and canonical rollout revision only.
It rejects additive containers, host networking, token authority, template
annotations, changed Secret modes, ports and probes. Existing IPC credentials,
projected ServiceAccount, TLS, limits and health checks remain unchanged.

Cleanup snapshots retain payload, UID and dispatch. The existing cleanup or
recovery claim permanently fences creators before named metadata-only observation.
Late IPC writes remain owned; deleting or content-drifted owned objects are still
captured. Absence never erases a known UID, settles a writer, completes cleanup or
proves that a runtime is gone.

Ordered teardown, positive node release, persistent-state transfer/retirement and
credential-preserving reset remain separate required slice-19 work. Actual egress
data-plane behavior and final live integration retain their later-slice boundaries.
