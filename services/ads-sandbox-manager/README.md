# ads-sandbox-manager

Slices 7 and 8 implement golden ensure and session object provisioning. This is a top-level uv workspace member,
included in all five Nox gates and CI image lint, build, and import smoke.
There is no Kafka transit, STE, ready listener, idle/recover scheduler, or
application/Helm service wiring yet. The session lifecycle worker has an explicit
`TopicPreparation` port with a test implementation only. Production does not
silently supply a no-op port or expose an unauthenticated provisioning endpoint.
Slice 9 will connect the authenticated Kafka ingress and detached worker lifetime.

## Session objects

`sandbox_session` in the dedicated manager database durably maps the caller's
session UUID to a manager-generated sandbox UUID. Startup runs the Alembic
migration and common schema validation after loading TLS materials. The
repository uses caller-owned short transactions. Kubernetes/port calls never
hold a database transaction open.

The INSERT winner atomically claims `pending -> creating`; stopped rows use a
compare-and-set claim to resume. Losers return the current row for the future
bounded ready waiter. They never clone, start a second worker, or steal an
interrupted `creating` claim. A worker/process interruption leaves that claim
for the later recover component. This worker must not be cancelled by execution
abort/reset: detachment belongs to the future ingress/runtime, not this API.

Creation order is:

1. GET only `ads-sandbox-{session_id}`. If absent and no persisted UID, clone the
   exact released golden observation, sized at least to its actual capacity.
   If it already has the matching session label and valid block contract, adopt
   its UID and recorded golden version; do not replace or upgrade its contents.
2. Commit that disk UID before any topics or compute.
3. Prepare topics and subscribe/seek the result topic via `TopicPreparation`.
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
That transition remains the later authenticated IPC Kafka-ready listener.

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
| `SESSION_OBJECTS` | Optional JSON object described below; required before invoking session provisioning |
| `KAFKA_BOOTSTRAP_SERVERS` | Required; metadata check only, no topic/group operations |
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
execution/handshake caps. No credential value is part of manager configuration.
Manager-owned IPC env explicitly fixes sandbox ID, namespace, PID directory,
TLS paths, and the HTTPS probe port. The optional CA Secret provides `ca.crt`.
Kafka SASL support in IPC and transit implementation remain later work; this
slice does not misrepresent the existing plaintext-only IPC adapter as SASL-ready.

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
