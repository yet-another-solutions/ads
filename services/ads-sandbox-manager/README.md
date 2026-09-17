# ads-sandbox-manager

Slice 7 implements golden ensure only. This is a top-level uv workspace member,
included in all five Nox gates and CI image lint, build, and import smoke.
There is no session state machine, clone creation, Deployment creation, Kafka
transit, STE, idle, recover, or application/Helm service wiring yet.

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
| `DATABASE_URL` | Required `postgresql+psycopg://…`; connectivity only, no slice-8 schema |
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

## Verification boundary

Deterministic tests execute the real reconciler, SDK adapter, Dishka composition,
and health paths against simulated API responses and dependency failures.
Existing workspace PostgreSQL tests remain real PostgreSQL. GitHub Actions is
the only image CI. The manager image is not published or deployed by this slice's
CI wiring; live Kata/CSI bake behavior is a separate cluster smoke using
already-built artifacts, never a lab image build.
