# ads-sandbox-manager

Slices 7 through 9 implement golden ensure, session object provisioning, and authenticated Kafka transit.
This is a top-level uv workspace member,
included in all five Nox gates and CI image lint, build, and import smoke.
Idle/recover schedulers and application/Helm service wiring remain later slices.
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

1. GET only `ads-sandbox-{session_id}`. If absent and no persisted UID, clone the
   exact released golden observation, sized at least to its actual capacity.
   If it already has the matching session label and valid block contract, adopt
   its UID and recorded golden version; do not replace or upgrade its contents.
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
golden source. Normal idle/disposal/recovery deletion is not implemented here.
No claim has a disposable-compute owner reference.

PVCs can remain Pending while the Deployments are created; this avoids
deadlocking a WaitForFirstConsumer provisioner. API 409 is followed by a named
GET and compatibility check, never blind adoption. The session create pass is
bounded. Failures leave a durable `failed` row and retained objects for later
recovery, with no exception bodies, tokens, or command output stored.

## Lifecycle

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
- PostgreSQL `SELECT 1` and a successful Kafka metadata bootstrap.

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
| `TOPIC_REPLICATION_FACTOR` | Dynamic request/result topics, default 1; each has one partition |
| `KAFKA_SECURITY_PROTOCOL` | `PLAINTEXT`, `SSL`, `SASL_PLAINTEXT`, or `SASL_SSL` |
| `KAFKA_SASL_MECHANISM` | Default `SCRAM-SHA-512` |
| `KAFKA_SASL_USERNAME`, `KAFKA_SASL_PASSWORD` | Required for SASL |
| `KAFKA_CA_BUNDLE` | Optional Kafka TLS trust bundle |
| `TLS_CERT_PATH`, `TLS_KEY_PATH` | Required TLS serving materials |
| `TLS_CA_BUNDLE` | Optional validated additional trust material |
| `POLL_SECONDS`, `CONTROL_SECONDS` | Default 10 each; full pass bounded to 3 control intervals |
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
