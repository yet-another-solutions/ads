# Paired placement and control resource contract

## Immutable per-relay input publication

`RelayInputPublication` is an internal, claim-bound step, not a production
activation path. It uses existing paired custody; it cannot generate keys.
Both relay Pod UIDs, the egress relay Service UID and allocated numeric IPv4,
the custody UID/public keys, trusted runtime parameters and exact nonsecret
configuration are committed before each input Secret create reservation.
`PairIntent.relay_inputs` is fresh-bootstrap JSONB, not a migration/adoption path.

The fixed-name API adapter checks both recorded Pod identities and the exact
Service identity/spec, including generation, namespace and ownership labels.
It loads only the recorded custody UID and verifies its original public keys.
Each immutable Opaque input Secret contains canonical `config.json` and only
that relay's `wg.key`. Neither the peer private key nor the combined custody
Secret is mounted. SQL and cleanup snapshots contain no private material.
The adapter never patches, rotates or silently repairs incompatible input.

Each role has monotonic `unissued/inflight/settled` dispatch evidence and a
separate immutable UID binding. Reservation and payload commit atomically under
the existing claim before external I/O. Replays only observe and verify the
original payload, never recalculate or recreate reserved inputs. Only normal
completion of the original retained invocation may settle its write, even after
claim loss/fencing. Caller cancellation does not cancel that invocation or allow
it to advance provisioning. Original-operation timeout, process loss, lost
reply and failed settlement remain inflight, regardless of later UID capture.

Cleanup captures the two input obligations in its existing ownership snapshot
and permanently fences creation before observing their exact names. Each UID
commits under the still-current normal/recovery/orphan claim. Metadata-only
cleanup observation can capture drifted/deleting Secrets; absence never erases
a known UID or proves release. No deletion, dispatch force-clear or retirement
authority is added. Both production provisioning and full paired teardown remain
unactivated until their separate integration gates are implemented and proved.

The manager's `pair_objects` builders define the native Kubernetes placement
and control-plane resources for the upcoming four-component pair. These
builders are not yet called by session provisioning. They neither create a
success-returning runtime fake nor claim a working private attachment.

## Identity and placement

`PairBinding` contains manager-owned session, sandbox, project and attachment
generation UUIDs. A generation is distinct from policy revision, egress process
UUID and persistent DNSSEC identity. Service and control-policy selectors match
sandbox, generation and exact component together, not project alone or a
reused private IP address. Stable object names do not authorize adopting a
replacement UID; the lifecycle integration must retain exact object bindings.

Two `scheduling.k8s.io/v1alpha2` PodGroups use `minCount: 2` and hostname
topology: guest VM plus its local relay, and egress VM plus its local relay.
IPC remains outside those groups. The manager must create both groups and all
four compute members before waiting for readiness. The groups need not occupy
the same worker; current lab proof remains single-worker.

The native feature prerequisites were verified with a disposable lab canary.
For Kubernetes v1.36.4, API server needs `GenericWorkload` and
`TopologyAwareWorkloadScheduling`, plus the alpha API runtime configuration.
Scheduler needs those two gates and `GangScheduling`. Controller-manager needs
`GenericWorkload` so its PodGroup protection controller releases terminal/empty
groups. Merely exposing the API or seeing the topology field in OpenAPI is
insufficient: the API server drops gated fields when their feature is disabled.

## Control surfaces

Three ClusterIP Services provide immutable manager-supplied HTTPS targets:
egress configuration/ping and one direct session-health URL for each relay.
The egress relay Service additionally exposes its WireGuard UDP socket.
No Service exposes a NodePort, external address or plaintext control endpoint.

Pair-scoped ingress policies allow HTTPS only from the exact paired IPC
generation. Relay UDP is allowed only from the opposite relay of that same
pair/generation. No namespace-wide peer selector or project-only selector is
used. These policies must coexist with no broader additive allow policy that
would defeat the boundary; that is a rendered-chart and live acceptance gate.

Service endpoint readiness must reflect a configured listening socket, not an
established WireGuard peer. Relay `/health` separately reports bounded session
health for IPC and kubelet liveness after startup allowance. The runtime must
not create a circular dependency where the Service hides the socket until the
peer connects. Kubernetes Pod Ready alone is never the IPC health verdict.

## Remaining integration

`PairControlAdapter` now provides fixed-kind Kubernetes create/read/delete for
these eight control objects using the existing verified in-cluster client.
It verifies exact generation/session/sandbox/project labels, UID and resource
version, rejects foreign ownership, terminating objects and incompatible specs,
and permits only explicit Service allocation/defaulting fields. It never patches
or adopts a replacement with a previously recorded name. Foreground deletion
uses UID/resourceVersion preconditions and completes only on observed absence.
PodGroup finalizers are never stripped; deletion lag remains incomplete.

The lifecycle caller must durably commit pair/generation intent before creation
and persist each returned UID before advancing. This adapter does not yet wire
the pair into session provisioning or broaden deployed RBAC. Its tests use
simulated API responses; neither live manager integration nor readiness is
claimed. Read/create errors are not successful absence or adoption.

`PairIntentRepository` records one generation and all eight intended control
resources under the existing session's exact creating claim (sandbox/project,
owner UUID and transition timestamp). Callers own transactions: commit the
intent before calling the adapter, then commit each observed UID before further
work. An unknown UID is not evidence of absence. Idempotent retries preserve the
generation and UID; replacement UIDs, stale claims, configuration drift and
corrupt intent fail closed. Database uniqueness and row locks serialize replica
attempts. Captured namespace and builder version must be used for that generation
instead of reinterpreting it under a later manager configuration.

Intent has no cascading foreign key to the mutable session row, so recovery or
session-row loss cannot erase old ownership. There is deliberately no retirement
or same-sandbox generation-reset operation yet: a later provisioning claim must
not overwrite that history before exact cleanup and attachment-release evidence
are wired. A replacement sandbox gets a new generation while keeping the old
record. This bounded repository is not called by provisioning or cleanup yet and
does not claim pair readiness or end-to-end restart recovery.

The table belongs to the fresh `0001_session` schema bootstrap, not an upgrade,
backfill or legacy-object adoption path. Startup validates that it exists; an old
database already stamped at head will fail validation rather than invent empty
ownership. A candidate rollout therefore still requires the authorized scoped
fresh-schema/model-credential preservation and restoration procedure.

`PairControlProvisioner.prepare` joins this repository to the real control
adapter. It commits all eight intended resources before the first API call,
revalidates the exact claim and captured configuration before each step, and
commits each observed UID before proceeding. It never holds a SQL transaction
across Kubernetes I/O. Repeated calls under the same claim are idempotent; missing
bound objects or replacement UIDs fail instead of being recreated/adopted.
The overall preparation deadline and each SQL-control step are bounded.

Failures and cancellation propagate without fabricating success or forgetting
partial ownership. In particular, cancelling an SDK thread does not cancel an
API request already in flight. The adapter's new observation-only method can
identify a later result under the exact generation without creating anything.
Tests exercise a real delayed SDK thread that commits after coroutine cancellation:
an earlier 404 is not retirement evidence, and the ledger remains retained.

This internal provisioning step is not yet invoked by `SessionProvisioner`:
enabling it without full compute/relay startup, retained-generation cleanup,
runtime-release evidence and recovery would expose an incomplete pair. It
returns captured controls, not execution readiness. Retirement and production
activation remain explicit subsequent integration gates.

Existing lifecycle admission now captures the pair generation, original
session/sandbox/project IDs, namespace/version and all control UID observations
inside `CleanupWork`, in the same transaction that claims idle, service, reap
or recovery. Recovery carries every earlier generation and never overwrites a
previous captured snapshot. True-orphan work can capture retained pair ownership
even after the mutable session row is gone.

The existing guest/IPC-only cleanup and recovery executors explicitly stop on
any captured pair snapshot, including an empty/malformed one. Idle still waits
for the authenticated drain acknowledgment. They do not remove policies,
volumes, records or topics and then pretend the four-component runtime is gone.
The repository independently refuses ordinary completion for paired work, so a
stale in-memory work object cannot erase a newly captured snapshot. This is a
fail-closed integration guard, not a working paired retirement implementation:
node/runtime release evidence and exact control cleanup remain required before
activation. The additional nullable field is fresh bootstrap only, not an
upgrade/adoption path for deployed databases.

### Cleanup-side control observation

For an acknowledged idle claim, or a current service/reap claim,
`PairCleanupCapture` now runs before the paired-retirement guard. It uses the
real control adapter's read-only observation path; it cannot call ensure or
delete. Before and after every API read, short transactions revalidate the
existing session/PVC transition, work identity, deadline, original pair scope,
snapshot and builder configuration. Each newly observed UID commits before the
next read. No database transaction spans Kubernetes I/O, and no new claim epoch
or schema column is introduced.

The manager's sandbox-namespace Role adds only `get` for Services,
NetworkPolicies and PodGroups. It gains no control-resource writes, no Secrets
or exec, and no cluster-wide control access. These chart permissions are not
applied to the live lab by a source merge.

Missing UIDs still mean potentially late/lost-response creation. A 404 does
not write an absence or completion bit; previously captured UIDs survive absent
reads, and a different UID is rejected. A later pass can capture an object that
appeared after an earlier 404. Cancellation, API failure, lost ownership or a
failed commit preserves earlier evidence and cannot advance cleanup.

The lifecycle remains blocked after this observation step even when every
control UID is known. It performs no compute, node, policy, volume or topic
deletion and never marks the generation retired.

Recovery capture uses the current recovering session's exact sandbox, project
and transition timestamp, rather than treating an old work deadline or old
sandbox ID as the active claim. Each old pair snapshot is retained unchanged
except for newly observed control UIDs. Old PVCs must still belong to the
session and be failed; retained targets are refused. Repeated recovery can
resume capture of older generations, but a stale recovery worker cannot write
after the active boundary changes.

True-orphan capture requires no current session under either captured session
or sandbox identity, no retained session PVC and no competing recovery intent.
It also validates the surviving pair ledger's immutable identity and scope.
A replacement session conservatively blocks this path. The old orphan work
deadline does not discard evidence or prevent a bounded retry. These absence
checks are not an insertion fence and confer no destructive authority.

Both paths perform only read-only Kubernetes observations, revalidate around
every read and keep the existing teardown guards. They do not resolve late
Kubernetes creates, deliver node commands or complete retirement.

### Control creator fence and dispatch evidence

The existing generation ledger now carries a permanent `creation_fenced` bit
and one monotonic dispatch state per fixed control key: `unissued`, `inflight`
or `settled`. No new claim epoch, retry generation or credential is introduced.
The new columns belong to the fresh initial schema only; an existing stamped
database must not be upgraded by silently adopting old rows.

Provisioning commits `inflight` before its sole create-capable adapter call.
Concurrent preparations and retries may observe an outstanding key, but cannot
dispatch another create. A found UID is checked through the strict adapter with
that UID supplied, which forbids recreation and validates the desired spec.
A missing observation only polls within the existing creation deadline.

Only normal return of the original create-capable invocation can mark that
dispatch `settled`, in a separate short transaction before UID binding. This
settlement validates the original immutable ledger scope even after the
provisioning claim is lost or fenced. It does not bind a UID, revive a claim or
advance provisioning. Thus a successful API operation with a lost binding
transaction remains safely observable, without dispatching another create.

Cleanup commits the permanent fence under its validated normal, recovery or
true-orphan claim before reading controls. The fence prevents later dispatch
reservations and prevents stale preparation from advancing. An invocation
reserved before the fence can still reach Kubernetes afterwards; the durable
`inflight` marker makes that uncertainty explicit. No SQL transaction spans
external I/O.

The provisioner strongly retains the original reserved operation if its waiting
caller is cancelled or reaches its creation deadline. Only that operation may
finish the create-capable invocation and commit settlement; it cannot bind a UID,
advance to another resource or revive the cancelled claim. Its adapter invocation
has a separate bound of three control timeouts (read/create/read), followed by
one bounded settlement transaction. Caller cancellation still propagates promptly.

The internal `drain` operation is a bounded join for the eventual runtime owner,
which must join retained work before closing SQL/Kubernetes. Cancelling or timing
out that join does not cancel original operations. A successful join is not a
settlement verdict: failed operations can be finished with durable uncertainty.
This lifecycle hook is not production runtime wiring.

Cancellation of the original operation itself, process loss, API exceptions,
lost replies and interrupted settlement leave the marker `inflight`, even if a
later read captures the object's UID. Neither
404, elapsed time, restart, successful observation nor a complete UID set
settles that marker. There is deliberately no automatic reset or force-clear.
Resolving ambiguous abandoned dispatches requires a separately proved
quiescence mechanism; this component may safely block retirement indefinitely.

A fenced ledger without inflight entries describes only the recorded control
dispatches. It does not fence legacy compute creation, prove node/runtime
release or authorize deleting control policies. Whole-pair creator fencing,
ambiguous-dispatch recovery, manager-to-node delivery and final retirement
remain integration gates. Production pair provisioning is still not enabled.

### Retained ownership blocks legacy admission

The ordinary session repository now refuses a newly inserted session mapping if
any retained pair ledger uses its session ID or sandbox ID. It also rejects a
pending/stopped claim before changing PVC or claim state, so a retained pair
cannot enter the legacy guest/IPC-only resume builder. Existing creating rows
may still be observed without claiming or creating anything; unrelated sessions
in the same project are unaffected.

The insertion check is deliberately after the unique-key wait, in a fresh
READ COMMITTED statement within the same caller-owned transaction. A concurrent
old-session deletion can commit previously invisible pair intent while INSERT
waits. Rejection rolls back the new row before any disk, topic or compute work.
The inserted/locked session row also serializes legitimate pair intent creation,
whose repository must validate that exact locked provisioning claim.

Ledger presence is blocking even with unknown UIDs, all dispatches settled, a
permanent creator fence or corrupt control evidence. None proves retirement.
There is no ledger deletion, expiry, new lifecycle epoch or adoption path here.
This prevents the normal manager admission path from resurrecting an orphan's
session identity; it does not fence arbitrary database writers, resolve old
external creates, stop existing runtimes or authorize cleanup. Whole-pair
resume/retirement integration must supply the eventual positive admission path.

### Four-member compute intent

The same `PairIntent` now records `compute_uids` and `compute_dispatch` for
exactly `Pod/guest`, `Pod/egress`, `Pod/guest-relay` and `Pod/egress-relay`.
These are Pod UID bindings, not Deployment/controller identities or readiness
verdicts. All four slots exist with the control intent before any compute
dispatch. No new generation, claim epoch, resource registry or lifecycle
controller is introduced.

`dispatch_compute` reserves the sole create-capable invocation under the exact
existing creating claim; its caller must commit before external I/O. Concurrent
reservations have one winner. Retries and restarts never reset `inflight`.
`bind_compute` records an observed UID under the still-current claim and rejects
replacement. Binding is not settlement. Only normal return of the original
invocation may call `settle_compute`, which validates immutable ledger scope
and may commit after claim loss/fencing without reviving authority.

Cleanup's permanent creator fence now checks both evidence sets and blocks
both compute and control reservations/bindings. Pre-fence reservations can
still finish late, so fencing alone is not quiescence. Compute reservations,
UID bindings and unresolved dispatches survive session-row loss. The two new
nonnullable columns belong to fresh bootstrap only; no old-schema backfill or
legacy-object adoption is provided.

Lifecycle admission snapshots all four compute UIDs alongside the controls for
normal, recovery and orphan work. The repository can commit later exact-scope
compute observations under the current cleanup claim, preserving known UIDs
through absence, rejecting replacements and refusing stale claims. This does
not settle a dispatch or prove absence. Earlier captured mappings survive
later ledger changes; existing completion guards remain unconditional for
paired work.

This ledger is a durable ownership prerequisite, not an active compute
provisioner. The read-only integration below uses these snapshots, but no
compute create/delete adapter, runtime builder, controller replacement
permission, node delivery or retirement is supplied. Future compute creators
must use these transactions, retain original-operation completion and supply
their separate runtime proof.
Any workload controllers require their own exact ownership/fencing coverage;
these Pod UID slots must never be treated as controller UIDs.

### Cleanup-side compute observation

The existing `PairControlAdapter.observe_compute` reads the four fixed Pod
names through the verified in-cluster client. `compute_identity` constructs
only API identity and manager-owned metadata, deliberately not a create-capable
Pod specification. The read verifies kind/API version, namespace/name, all
session/sandbox/project/generation/component/version labels, nonempty UID and
resourceVersion, and any previously captured UID. Owner references are refused;
this does not adopt a Deployment's replacement Pod. Terminating or spec-drifted
owned Pods remain cleanup obligations, not readiness or safe-execution proof.

`PairCleanupCapture` now observes all four compute members after the eight
controls in the existing normal/recovery/orphan lifecycle paths. Before each
read it validates the current claim and commits the permanent creator fence;
after each read it revalidates and commits that UID before advancing. There is
no SQL transaction across SDK I/O. A failed read/commit or lost claim cannot
advance capture or erase earlier evidence. Restart repeats observation only,
never creation. A 404 preserves known UIDs and never records absence as release.

The sandbox-namespace Role adds only Pod `get` to its existing Pod permissions;
no compute create, patch, Secret, exec or cluster-wide Pod permission is added.
The observer never lists, creates, patches or deletes. All paired-retirement
guards remain: even four known Pod UIDs cannot settle outstanding dispatches,
stand in for captured node/runtime identities or authorize destructive cleanup.
This is source wiring, not a live deployment, partial-startup release proof or
full egress acceptance.

### Trusted private guest Pod

`pair_compute.private_guest_pod` is the first runtime member constructor. It
reuses the existing immutable guest boot, budget and block-device contract,
but emits a fixed-name bare Pod with exact pair labels and guest-side PodGroup
placement. It emits no Deployment/controller or replacement policy. Restart is
`Never`; the 30-second termination allowance covers the existing bounded
orderly shutdown path, but does not prove a particular shutdown succeeded.

`PrivateGuestRuntime` requires an explicit DNS-label RuntimeClass distinct from
the legacy guest setting and an observed integer transport MTU. This is a
platform-owned input, not project policy or a guessed path MTU. The builder
passes private MTU as transport MTU minus 110, matching the node attestor and
relay encapsulation contract. The guest DNS endpoint is the adopted pair-local
egress address, not Kubernetes DNS. The normal image entrypoint receives
private mode, the exact generation and the committed CA attempt.

The guest retains its workspace block device and read-only public CA consumer
only. It receives no CA private-key volume, hostPath, runtime socket, API token,
config Secret, command override or arbitrary caller manifest. Bootstrap adds
only the previously kernel/live-proved `NET_ADMIN` and `SYS_PTRACE` alongside
`SYS_ADMIN`; the immutable boot path remains responsible for dropping them
before normal inner execution. A nonprivileged outer Pod and existing rootless
budgets are preserved.

This pure constructor does not verify the installed RuntimeClass/CNI, prove
workspace/CA PVC UID ownership, create a Pod or claim readiness. Its eventual
caller must commit the immutable inputs, verify exact retained volume ownership,
use the existing single-dispatch ledger and await real component health.
Egress/relay builders, persistent runtime configuration/key delivery and full
creation/retirement integration remain open. No production caller or Helm
activation is added by this constructor.

### Trusted relay Pods and configuration

`pair_compute.relay_pod` builds either fixed relay member in the ordinary
container runtime, sharing the appropriate VM's PodGroup placement and exact
pair labels. `RelayRuntime` requires a digest-pinned image, a separate
platform-provisioned TLS Secret reference, observed transport MTU and bounded
packet/resource/startup inputs. The caller must match that image and MTU to the
installed node attestor; syntactic validation is not installation proof.

The fixed container invokes `ads-ptp-relay` with file paths only. It receives
its actual Pod UID through the downward API and the committed generation
through trusted environment. Config/WireGuard-key and TLS files mount as
required root-readable 0400 single-file read-only subPaths. The config input
name is role/sandbox/generation-specific; TLS and transport input references
cannot alias. No host namespace/path/runtime socket, service-account token,
CA signing key, mutable rootfs or arbitrary command is supplied. The explicit
SYS_ADMIN/NET_ADMIN/NET_RAW and Unconfined profiles match the existing trusted
relay proof, not permissions for the untrusted guest.

There is no readiness probe, startup probe or readiness gate. The HTTPS
`/health` liveness probe has a bounded startup allowance and a timeout exceeding
the runtime's six-second connection deadline. IPC remains responsible for
calling actual session health directly. Bare relay Pods use `Always` so kubelet
owns liveness-triggered container restarts, as designed; this does not authorize
Pod replacement or private-attachment adoption. The runtime still refuses
existing state on a container restart, leaving the pair unhealthy until
manager-owned recovery. Do not erase its journal to make a restart succeed.

`relay_configuration` accepts only the observed canonical Pod UID, exact pair,
peer public key and platform inputs. It emits the runtime's exact nonsecret
configuration shape with the adopted isolated addresses, ports and VNI. Guest
relay needs the observed numeric egress-relay Service IPv4; egress learns only
the authenticated endpoint. Tests pass the resulting JSON through the actual
runtime parser and prove mismatched UID/generation rejection.

Bootstrap must create and capture the Pod UID before publishing its immutable
input. Required, nonoptional Secret keys hold container startup until that input
exists; there is no placeholder configuration or optional empty-key fallback.
The future publisher must generate and retain two distinct per-generation
private keys, verify peer/public-key relationships, commit input intent and
exact Secret ownership, and deliver immutable payloads after validating the
recorded Pod/Service identities. It must cover late Secret creates and preserve
input ownership through cleanup/recovery. These pure builders neither publish
Secrets nor claim those ordering/immutability/ownership checks are implemented.

No production caller, new RBAC, Secret read/copy, key generation, schema/Helm
activation or lab deployment is added here. Egress construction, committed
runtime inputs, exact volume verification and actual create/retirement wiring
remain required before activation.

This component builds two PodGroups, three Services and three ingress policies.
It does not yet provide egress/relay images, compute Pods, upstream/private
namespaces, peer keys, persistent identity, node attachment, lifecycle orchestration or
egress enforcement. Production provisioning remains on the existing path until
those components are wired with mandatory runtime checks and exact cleanup
ownership. Tests cover native API shape, grouping, generation separation,
same-project foreign-pair control denial selectors and distinct direct URLs.
Live CNI control isolation, transport and application acceptance remain open.

## Durable paired transport-key custody

`RelayKeyCustody` is an internal, not-yet-production-called step under the
existing exact creating claim and pair generation. Under the existing
session/intent locks it generates two distinct canonical WireGuard/X25519
private keys and atomically commits their **public keys only** with the sole
custody-create reservation. SQL holds neither private key nor a Secret body.
The winning invocation publishes both keys in one immutable `Opaque` Secret
named `ads-relay-keys-<sandbox UUID>.<generation UUID>`. No relay or guest mounts
that combined custody Secret. Later per-relay publication must take only the
appropriate private key plus the opposite peer's public key.

The original operation is strongly retained across caller cancellation. Only
its normal return and successful settlement commit can mark dispatch settled;
UID observation is separate. Process loss, SDK cancellation, lost replies and
failed settlement leave an inflight obligation indefinitely. A restart reads
the original named Secret and verifies immutable type, exact labels, UID,
resource version, lack of ownership/deletion, canonical paired private data,
and correspondence to the two committed public keys. It never generates keys
after reservation, overwrites an object, recreates a missing bound object or
expires unresolved dispatch. A reservation lost before its POST may therefore
block forever; recovery authority to resolve that ambiguity is not invented.

The adapter has no list, patch, delete, namespace discovery or platform-Secret
copy operation. Read/create SDK exceptions are replaced with generic errors,
and the private-key container's repr omits its fields. Python memory is not a
securely erased key vault: deployment must retain the platform's encryption at
rest, restrictive Secret access, safe audit policy and log/debug configuration.
No transport private key belongs in SQL, snapshots, API replies, traces or
exception bodies. This does not touch the interception CA or TLS signing keys.

Cleanup snapshots retain only public keys, dispatch snapshot and custody UID.
After the permanent creator fence, normal/recovery/orphan capture observes the
fixed custody name only if there was a reservation, commits each UID under the
same revalidated cleanup claim, and preserves old UIDs after absence.
Terminating or data-drifted owned Secrets are still cleanup obligations.
Snapshot dispatch is historical, never authority to settle the live ledger.
Late creation can be captured on a later pass; neither it nor 404 is retirement.

One nonnullable JSONB field is added to the **fresh** schema bootstrap; no
migration, adoption or automatic upgrade is provided. No live reset is done.
No production provisioning call, new RBAC/Helm activation or release is added.
Activation will require narrowly reviewed namespaced Secret permissions for
the manager only, not IPC/guests/relays. Per-relay config/private-key publication
still needs its own committed immutable payload, dispatch/UID ownership,
actual Pod/Service binding and cleanup coverage. Egress construction, runtime
activation, ordered key deletion after proven release, retirement and protected
credential-preserving reset remain open.
