# ads-sandbox-manager

Slices 7 through 12 implement golden ensure, session object provisioning,
authenticated Kafka transit, deterministic handshake proof, lifecycle cleanup,
IPC-alive ping, and durable recovery.
This is a top-level uv workspace member,
included in all five Nox gates and CI image lint, build, and import smoke.
Application/Helm service wiring remains in later slices.
The production `TopicPreparation` creates dynamic topics, waits for the local
response subscription/seek, then runs a best-effort manager barrier before compute.
There is no unauthenticated provisioning endpoint.

## Authenticated transit

The shared consumer group `ads-sandbox-manager` consumes `ads.sandbox.exec.request`
and regex-discovers every `sandbox.res.{sandbox_id}`, including topics created by
another replica. New local assignments seek to end; already-seen local assignments
restore their recorded position on rebalance rather than discarding more live data.
Partition movement to a replica that has never owned it still seeks to end.

All initial requests and controls carry `execution_id`, `session_id`, `message_id`.
MCP keys requests and controls by `session_id`; the manager checks key/body agreement.
IPC's `acknowledge` carries the same tuple, while `result` remains execution-correlated.
IPC keys responses by `sandbox_id`; manager verifies topic/key and resolves the
durable session mapping. An acknowledgement must also match that session.

Every inbound message is verified with the common JWT verifier and caller
allowlist: MCP on execution input, IPC on responses and `ready`, manager on barrier
coordination. No user holder is bound. Every forwarding hop mints a fresh STE token:
manager-to-IPC from the inbound MCP JWT, manager-to-MCP from the inbound IPC JWT.
No token, command, or output is stored in the manager database or error logs.

Only `request` can provision. Requests wait for authenticated IPC `ready`, not
Kubernetes readiness. Missing/stopped sessions create/resume; other non-ready
statuses wait, bounded by `READY_SECONDS`. Failure/timeout produces an error result
using fresh STE. Follow-ups and results pass regardless of status and never create.
Forwarded results update `last_execution_at`. Ready sets status and initial
activity timestamps only after all object UIDs have committed, even without a
local waiter; duplicate ready warns without resetting activity.

Reset/abort removes only the matching tuple and subject from the local forward
buffer. A claimed provisioner continues detached, even after reset or request
timeout. A reset before claim prevents a later worker start, and a reset during
STE prevents publication of the dropped request. Process shutdown cancels local
tasks but does not delete resources or steal durable claims.

## Best-effort subscription barrier

`ads.sandbox.manager.barrier` is a pre-created, manager-only topic. Each replica has
a unique group `ads-sandbox-manager-barrier-{replica_id}`. Its listener and the
unique `ads-sandbox-manager-ready-{replica_id}` listener start and seek before that
replica joins the shared request/result group. All Kafka clients support the
configured SASL/TLS transport.

After local response subscription/seek, public
`AIOKafkaAdminClient.describe_consumer_groups` snapshots the shared group's
members. The shared consumer's `client_id` is a unique process UUID. The adapter
uses aiokafka 0.14's documented raw response shape; no private member/generation
attributes are used. It waits for a stable, self-inclusive snapshot within the
same barrier deadline, not a configured replica count.

A fresh `barrier_id` identifies each request and matching acknowledgements.
Participants acknowledge only after their response subscription callback has
completed its seeks, including replicas with an empty assignment. Requests and
acks use fresh manager client-credentials JWTs, not user tokens. Round state and
participant tasks exist only in memory and are cleaned on completion/timeout/stop.

`BARRIER_SECONDS` defaults to 3. Missing acknowledgements, discovery failure, or
coordination failure log a warning and **proceed**. Required local topic creation
and subscription preparation instead fail the create attempt on timeout/error.
The barrier is not strict consensus, generation fencing, or reliable delivery.
A replica joining after the snapshot, a timeout, crash, or subsequent partition
reassignment can still lose a response under seek-to-end semantics. MCP timeout
is the accepted fallback. No durable barrier table or second membership registry.

## Session objects

`sandbox_session` in the dedicated manager database durably maps the caller's
session UUID to a manager-generated sandbox UUID. Startup runs the Alembic
migration and common schema validation after loading TLS materials. The
repository uses caller-owned short transactions. Kubernetes/port calls never
hold a database transaction open.

The INSERT winner atomically claims `pending -> creating`; stopped rows use a
compare-and-set claim to resume. Losers return the current row for the
bounded ready waiter. They never clone, start a second worker, or steal an
interrupted `creating` claim. A worker/process interruption leaves that claim
for the later recover component. This worker must not be cancelled by execution
abort/reset: transit owns its detached lifetime.

Creation order is:

1. Persist a new PVC-lifetime UUID and the sandbox/attaching claim jointly.
   GET only `ads-sandbox-{pvc_id}`. If absent and no persisted UID, clone the
   exact released golden observation, sized at least to its actual capacity.
   A conflicting create must match the already-persisted lifetime, session,
   sandbox labels, and block contract before its UID can be recorded.
2. Commit that disk UID before any topics or compute.
3. Prepare topics, subscribe/seek the result topic, and run the best-effort barrier.
4. Create Filesystem PVC `ads-sandbox-ipc-{sandbox_id}`.
5. Recheck the named session/PVC bind, then create Kata Deployment
   `ads-sandbox-{sandbox_id}`, container `sandbox`.
6. Recheck the bind, then create application-node Deployment
   `ads-sandbox-ipc-{sandbox_id}`, container `ipc`.

Both Deployments have one replica, `Recreate` strategy (no rolling surge), and
matching sandbox labels on both object and Pod template. The selectors also
include component labels, so guest and IPC selectors cannot overlap.
The guest uses only its session Block volume, with no network annotations,
projected token, service links, host namespace sharing, or credentials.
Its readiness probe checks the boot script's `/run/ads-sandbox-ready` marker;
object existence and Kubernetes readiness do **not** set the database to `ready`.
That transition belongs only to the authenticated IPC Kafka-ready listener.

IPC uses the shared, Helm-owned ServiceAccount and bound token, its own
Filesystem PID store, referenced configuration/credential Secrets, and TLS-only
probes. The PID volume has the image user's filesystem group for write access.
The manager does not create any namespace, RBAC, Secret, ConfigMap, or Service.
Pod-bound exec admission remains a deployment prerequisite, not permission
granted by a label alone.

Resume requires the persisted session PVC UID, matching immutable session label,
golden version, Block mode, and `sandbox-block` class. A missing/replaced/foreign/
deleting/incompatible disk fails closed, without clone, attach, or delete.
Resume recreates only the compute/IPC resources and does not need a current
golden source. A reaped session gets a fresh PVC UUID and golden clone.
No claim has a disposable-compute owner reference.

PVCs can remain Pending while the Deployments are created; this avoids
deadlocking a WaitForFirstConsumer provisioner. API 409 is followed by a named
GET and compatibility check, never blind adoption. The session create pass is
bounded. Failures leave a durable `failed` row and retained objects for later
recovery, with no exception bodies, tokens, or command output stored.

## Idle, retention, and orphan cleanup

Fresh installations initialize `sandbox_session`, `session_pvc`, `cleanup_work`,
and `ping_probe`.
This changes the initial schema, deliberately without a legacy migration, name
adoption, or backfill. Existing earlier-slice databases are not an in-place upgrade target.
The stable session UUID is separate from both sandbox identity and disk lifetime.
`session_pvc` tracks `attaching`, `attached`, `detaching`, `detached`, `destroying`,
and `failed`, with execution and exact transition timestamps.

All joint mutations lock the sandbox before its PVC. Execution admission checks
ready/attached and refreshes both activity clocks in one transaction. Idle
admission rechecks activity under the same locks. An already-accepted dispatch
can lose the race with shutdown and time out; it is never automatically replayed.
Ordinary completions require the captured identity, state, and exact transition
timestamp. Timestamp advancement is strict even within one database clock tick.

Idle admits ready/attached into shutting_down/detaching after 30 minutes of
inactivity by default. The manager sends authenticated shutdown with the captured
transition timestamp. IPC stops admission, drains the execution and its result,
then echoes that timestamp in its acknowledgement. Missing or stale acknowledgements
cannot authorize teardown. Results still forward while shutting down.
Cleanup removes IPC Deployment and its Filesystem PVC, then guest Deployment.
It retains the session Block PVC. Only observed compute disappearance and storage
release permit stopped/detached completion.

Retention requires both 30-minute execution inactivity and two hours continuously
detached by default. Reap exclusively claims the exact lifetime into destroying;
resume and stopped-sandbox maintenance cannot claim it concurrently. Persisted
cleanup targets contain names, UUIDs/UIDs, and storage evidence, never a mutable
alias to the current session mapping. Deletes use UID/resourceVersion preconditions.
A missing target warns; it is not by itself proof of storage reclamation.
Only positive reclamation permits removal of that exact PVC record and mapping.

Idle, retention, orphan, and PVC-watchdog scans have cluster-wide PostgreSQL
advisory locks and bounded signal batches. They only publish suggestions.
`ads.sandbox.idle`, `ads.sandbox.pvc.reap`, `ads.sandbox.orphan`, and
`ads.sandbox.recover` use manager-only verified client-credentials JWTs.
Their separate shared group `ads-sandbox-manager-maintenance` resumes committed
offsets, starts at earliest if none exist, and never seeks to end or auto-commits.
Each partition is serial and paused while its bounded batch is admitted. Other
partitions continue polling independently. Only classified rejection or durable
DB admission allows an explicit offset n+1 commit. Database failures block later
records; commit retries do not repeat successful admission while assignment lasts.
Revocation fences retries; replay is idempotent after a crash between DB and Kafka.
This durability policy does not change best-effort execution/result transport.

Orphan scans consider only manager-labeled/named guest/IPC Deployments and
IPC/session PVCs. Golden/unrelated resources and every valid retained or
attaching PVC are excluded. Grouped orphan cleanup removes compute before storage.
Unexpected resources for a stopped sandbox require an exclusive
stopped -> service -> stopped claim. Its persisted deadline is shared by all
waiting requests and is never extended per request or stolen by another worker.
No previous-state field or service claim UUID exists. Late-created resources are
found by subsequent scans. Bound true-orphan disks without retained node evidence
remain unresolved rather than being guessed safe to delete.

Cleanup/service timeout and the PVC-state watchdog publish whole-sandbox recovery.
The verdict begins at acknowledged Kafka publication, not scheduler observation;
pre-publication loss is accepted without an outbox. Admission condemns the
observed sandbox even after late success, advances its sandbox ID, and durably
retains every old cleanup target for recovery. Replaced IDs and active-recovery
duplicates are ignored. Timed-out recovery rotates again and carries unfinished
targets forward rather than forgetting a partially destroyed generation.
Ordinary idle/reap never deletes Kafka topics.

## IPC ping and recovery

A separately locked cluster scheduler pings only ready sandboxes every 10 seconds
by default. Each request uses fresh manager client credentials and fresh STE to IPC;
the IPC reply uses fresh STE back to the manager. No user holder or token cache is
used. Shutdown likewise uses fresh service identity. The ready broadcast listener
also receives ping replies. Database `ping_probe` rows correlate UUIDs across
replicas; consumed or unknown UUIDs cannot
refresh liveness. Out-of-order outstanding replies remain valid within the deadline.
Ready initializes the liveness baseline; only an authenticated matching reply
updates it. Ping tests IPC's Kafka loop, never guest health or execution activity.

Each probe starts unconfirmed; `published_at` is committed only after the broker
acknowledges the send. Credential, STE, send and cancellation failures remove
that attempt, propagate an operational failure, and do not prove IPC death.
A crash before recording publication likewise leaves no death evidence; the next
scan sends a fresh probe. A fast reply may consume the correlation before that
commit. Old unconfirmed, superseded and inactive-sandbox probes are reclaimed.
The additive migration leaves pre-upgrade probes unconfirmed.

After a confirmed publication has gone 30 seconds without a newer valid reply,
the scheduler publishes recovery with a
fresh manager service JWT. Publication is the failure verdict even if a late reply
arrives before admission. Durable admission changes identity before any external
cleanup; recovery work survives manager restarts. The worker has a per-session
advisory lock and fences progress by sandbox ID, recovering state, and exact
transition timestamp. No execution is replayed.

Recovery first deletes the old request/result topics and observes their absence.
It captures exact old object/storage evidence durably, removes old Deployments,
then releases and reclaims IPC/session PVCs. Missing known disks without retained
release evidence remain blocked. Late-created objects with no committed UID must
match the condemned identity; foreign resources are never adopted or deleted.
Orphan cleanup cannot steal targets owned by recovery. All carried generations
must be reclaimed before their records are removed.

Only then does one transaction claim a fresh PVC lifetime under the already-new
sandbox ID. The ordinary golden-clone builder prepares new topics/subscriptions
before new compute. Authenticated IPC ready, not the recovery worker, marks ready.
Failures preserve targets and publish another recovery verdict. The watchdog
covers failed and timed-out creating/shutting-down/recovering states, including
rows with no current PVC. The recovery deadline defaults to 600 seconds.

`ADS_SANDBOX_MANAGER_PING_INTERVAL_SECONDS`,
`ADS_SANDBOX_MANAGER_PING_TIMEOUT_SECONDS`, and
`ADS_SANDBOX_MANAGER_RECOVERY_SECONDS` configure these defaults.
Timeout must exceed interval; recovery must exceed the cleanup deadline.
The deterministic cross-service proof stops IPC, admits the resulting recovery,
rebuilds from golden, and completes the next execution with fresh IDs. PostgreSQL
and signed JWT/STE adapters are real; broker, identity endpoint, Kubernetes and
guest process frames are simulated. Live kill-IPC/Kata/CSI proof remains deferred
until the full plan is implemented. Helm settings remain slice 14.

### Release and reclamation evidence

Before teardown, persist each bound PV UID, claim identity, consuming nodes, and
CSI volume key. Require no remaining Pods referencing the claim, no VolumeAttachment,
and fresh Ready node observations after capture with no matching attached/in-use
volume. Pending never-bound claims need no nonexistent node evidence, but a concurrent
bind fails the captured-binding gate and delete resourceVersion precondition.
Idle release evidence survives in the retained PVC record for later reaping.
Reclamation additionally requires observed PVC and PV disappearance under the
captured Delete policy and CSI external-provisioner deletion-protection finalizer.
Unknown/missing evidence, stale nodes, remaining consumers, permission failures,
and API errors fail closed. Cleanup deadlines retain targets for recovery.

This is a Kubernetes/CSI-controller observation contract, not a physical-storage
probe or fencing against administrator force deletion or a faulty node/driver.
The adapter never force-deletes Pods or mutates Nodes/PVs. Live validation of the
lab driver's finalizer/reclamation behavior is deferred, not asserted by tests.

## Golden lifecycle

The process serves TLS-only `/health/live` and `/health/ready`. Golden ensure runs
in a bounded background polling loop even while readiness is false. Liveness
does not depend on Kubernetes, the bake, PostgreSQL, or Kafka.

The Job name `ads-sandbox-golden-v0-0-10` is the replica lock for release
`v0.0.10`; labels retain the dotted release. The manager creates the Job first,
then its same-name Block PVC. A second replica can finish PVC creation if the
first process stops between those operations. The Job may remain Pending until
the claim is created and provisioned. A Pending Job is not mistaken for failure.

The claim is labeled with the bake Job UID. A Failed Job retains the name lock
while the manager waits for release, deletes the partial PVC, waits for its
deletion, then foreground-deletes the Job and recreates the pair. A completed
Job with no PVC is also recreated. An orphan PVC is never promoted to ready:
it is deleted only when release can be established. A Bound orphan with no
retained Pod/node evidence fails closed for operator investigation.
Never-bound Pending claims can be cleaned up after pre-scheduling failure when
all referencing Pods are terminal, without requiring nonexistent VM/node evidence.
They can never satisfy readiness, and deletion preconditions fence a concurrent bind.

Every delete has UID and resourceVersion preconditions. Conflicts, disappearing
resources, API outages, and denied observations produce not-ready and retry on
the next poll. Foreign or incompatible same-name objects are never adopted or
deleted. The manager does not remove other releases.

## Live release predicate

“Unbound” in the original plan means **not in use**, not the PVC phase.
A clone-source PVC must remain `Bound`
([Kubernetes CSI cloning](https://kubernetes.io/docs/concepts/storage/volume-pvc-datasource/)).

Ready requires all of:

- Job `Complete=True`, no active or terminating Job work.
- Same bake-UID claim, Block, `sandbox-block`, expected size, PVC phase `Bound`.
- Namespace-wide Pod observation, not just label-selected Pods: every Pod
  referencing the claim is terminal and not deleting.
- Retained successful Pod evidence belonging to this Job, with
  `PodReadyToStartContainers=False` and a finished container timestamp.
  This condition reports the absence of a ready runtime sandbox; terminal
  container exit alone is insufficient
  ([Kubernetes Pod conditions](https://kubernetes.io/docs/concepts/workloads/pods/pod-condition/)).
- A fresh `Ready=True` Node observation after each consumer's finish, no matching
  CSI volume in `volumesInUse` or `volumesAttached`, and the PV still bound to this
  exact PVC UID.
- No VolumeAttachment referencing that PV, including deleting, errored, or
  `attached=False` records. Absence alone is not release proof because CSI drivers
  can skip attachment
  ([CSIDriver API](https://kubernetes.io/docs/reference/kubernetes-api/storage/csi-driver-v1/)).
- Unchanged Job and PVC UID/resourceVersion after the observation.
- PostgreSQL `SELECT 1` and a successful fresh Kafka metadata request.

The health checker bootstraps one application-owned Kafka client and reuses its
broker connections across polls, rather than authenticating a new client every
poll. Metadata checks remain bounded by `control_seconds`; failed refreshes,
exceptions, and cancellation discard the client so a subsequent poll can recover.
Application shutdown closes the client. This changes neither Kafka transport
security nor the producer/consumer lifecycle.

Missing permissions, unknown fields, stale Nodes, missing retained bake evidence,
or uncertain release keep readiness false. Do not force-delete Pods or introduce
a Job TTL. This is Kubernetes-observed release, not storage fencing against an
administrator force-deleting resources or a faulty node/CSI driver. Node
`volumesInUse` describes attachable volumes, so it is not used alone to infer
release of attach-less storage
([Node API](https://kubernetes.io/docs/reference/kubernetes-api/cluster-resources/node-v1/)).

The explicit read-only RBAC amendment adds namespace Pod `list`, cluster PV/Node
`get`, and VolumeAttachment `list`. Existing object writes remain unchanged.
No exec, Pod writes, Node writes, or RBAC writes are granted to the manager.
The manifest amendment is not the later Helm service-wiring slice.

## Configuration

All names below have prefix `ADS_SANDBOX_MANAGER_`, except `ADS_SESSION_SIZE`.
TLS materials are loaded on the main thread before any client creation.

| Setting | Contract |
| --- | --- |
| `GOLDEN_VERSION`, `GOLDEN_IMAGE` | Required published release coordinates, never guessed |
| `ADS_SESSION_SIZE` | Required release-baked quantity; no runtime fallback |
| `GOLDEN_SLACK` | Default/minimum `2Gi`; claim size is session size plus slack |
| `NAMESPACE` | Default `ads-sandbox` |
| `NODE_SELECTOR`, `TOLERATIONS` | JSON object/array, shared placement contract with future session objects |
| `IMAGE_PULL_SECRETS` | Comma-separated Secret names |
| `RESOURCES` | Job container resource requests/limits JSON object |
| `DATABASE_URL` | Required `postgresql+psycopg://…`; dedicated manager database with startup migration |
| `SESSION_OBJECTS` | Required JSON object described below |
| `KAFKA_BOOTSTRAP_SERVERS` | Required; producer, consumers, admin, and health use the same transport settings |
| `KEYCLOAK_ISSUER`, `KEYCLOAK_WELL_KNOWN_URL`, `KEYCLOAK_CLIENT_SECRET` | Required HTTPS identity/discovery and manager client secret |
| `READY_SECONDS` | Request/ready wait timeout, default 120 |
| `BARRIER_SECONDS` | Best-effort round timeout, including membership discovery, default 3 |
| `IDLE_SECONDS` | Execution inactivity gate for idle and retention, default 1800 |
| `DETACHED_SECONDS` | Minimum continuous detached age before reap, default 7200 |
| `CLEANUP_SECONDS` | Persisted cleanup/service deadline interval, default 120 |
| `PVC_TIMEOUT_SECONDS` | Watchdog timeout for attaching/detaching/destroying, default 120 |
| `LIFECYCLE_BATCH` | Positive scheduler/work batch limit, default 50 |
| `TOPIC_REPLICATION_FACTOR` | Dynamic request/result topics, default 1; each has one partition |
| `KAFKA_SECURITY_PROTOCOL` | `PLAINTEXT`, `SSL`, `SASL_PLAINTEXT`, or `SASL_SSL` |
| `KAFKA_SASL_MECHANISM` | Default `SCRAM-SHA-512` |
| `KAFKA_SASL_USERNAME`, `KAFKA_SASL_PASSWORD` | Required for SASL |
| `KAFKA_CA_BUNDLE` | Optional Kafka TLS trust bundle |
| `TLS_CERT_PATH`, `TLS_KEY_PATH` | Required TLS serving materials |
| `TLS_CA_BUNDLE` | Optional validated additional trust material |
| `POLL_SECONDS`, `CONTROL_SECONDS` | Default 10 each; polling interval and individual control/DB bounds |
| `BAKE_SECONDS` | Job active deadline, default 1800 |
| `NODE_FRESH_SECONDS` | Maximum Node heartbeat age, default 600 |
| `BIND_HOST`, `PORT` | Default `0.0.0.0`, `8080`; always TLS |

The golden container inherits the ordinary runtime capability set plus
`SYS_ADMIN` for mount, not privileged mode. Keeping ordinary file ownership
capabilities is necessary for extracting the rootfs with its original owners.
No command override, guest network annotations, SA token, or service-link
environment is injected. `dnsPolicy: None` has a loopback-only nameserver to
satisfy Kubernetes API validation; it does not create a guest NIC.

`SESSION_OBJECTS` is the `SessionSettings` object, populated by later Helm
wiring. Required fields: `guest_image`, `ipc_image`, `ipc_storage_class`
(application Filesystem class, never `sandbox-block`), `ipc_service_account`,
`ipc_config_map`, `ipc_secret`, `ipc_tls_secret`, and nonempty application
`ipc_node_selector`. Optional fields: `ipc_ca_secret`, `ipc_size` (default 1Gi),
`guest_resources`, `ipc_resources`, `ipc_tolerations`, and `create_seconds`
(default 120). Guest placement and pull-secret references reuse the golden
settings. All referenced objects must exist in the sandbox namespace.

The referenced ConfigMap/Secret supply the existing IPC-prefixed configuration:
Keycloak discovery URL, issuer, client secret, Kafka bootstrap, and optional
execution/handshake caps. IPC credentials are referenced, never embedded in object JSON;
the manager's own client and Kafka secrets are configured separately.
Manager-owned IPC env explicitly fixes sandbox ID, namespace, PID directory,
TLS paths, and the HTTPS probe port. The optional CA Secret provides `ca.crt`.
Kafka SASL support in IPC/MCP remains later work; manager transport support does
not misrepresent those existing plaintext-only adapters as SASL-ready.

## Verification boundary

Deterministic tests execute the real reconciler, SDK adapter, Dishka composition,
and health paths against simulated API responses and dependency failures.
Session create/resume, concurrent replica claims, persisted UID adoption, and
failure tests use real PostgreSQL and fake Kubernetes/topic preparation.
SDK-adapter tests verify named API calls, namespace, timeouts, and 404/409/403
handling. Existing golden release and probe assertions remain intact.
GitHub Actions is
the only image CI. The manager image is not published or deployed by this slice's
CI wiring; live Kata/CSI bake behavior is a separate cluster smoke using
already-built artifacts, never a lab image build.
Live four-object/guest-boot acceptance is deferred until the whole sandbox plan
is implemented. Deterministic tests do not claim Kata/CSI/guest boot passed.
Transit tests cover real PostgreSQL state, signed JWT rejection/acceptance,
fresh per-hop STE, detached provisioning, tuple correlation, subscription
callbacks, unknown replica counts, missing/stale acknowledgements, and the
documented late-joiner gap. Fake Kafka/Kubernetes boundaries are not live E2E proof.
Lifecycle tests add joint admission/idle and stopped-claim exclusion, exact timestamp
fences, retained-disk resume, retention clocks, fresh post-reap clones, shared
maintenance deadlines, late orphan cleanup, UID replacement safety, durable
partition admission/rebalance, ping correlation, and restart-safe recovery rebuilds.
The lifecycle Kafka ACL/topic additions are source-only, not installed in the lab.
All new thresholds are environment-configurable now; Helm exposure remains slice 14.
