# Sandbox lab identity

Slice 6 provisions lab infrastructure, not the manager implementation or an ADS
release. The scripts reconcile the existing lab and run real identity proofs.
Builds and CI remain exclusively in GitHub Actions; the lab only runs published
images and disposable proof workloads.

## Boundaries

| Component | Database / owner | Keycloak client | ServiceAccount |
| --- | --- | --- | --- |
| MCP | `ads_sandbox_mcp` | `ads-sandbox-mcp` | No new workload in this slice |
| Manager | `ads_sandbox_manager` | `ads-sandbox-manager` | `ads/ads-sandbox-manager` |
| IPC | None | Shared `ads-sandbox-ipc` | Shared `ads-sandbox/ads-sandbox-ipc` |

Database operations target **ads-postgres**, never Keycloak's separate `postgres`
namespace. Each new database rejects PUBLIC connections, is owned by its matching
non-superuser login, and is checked using a real password-authenticated TCP login.
No migrations run here.

The manager Role can create/delete/get/list/watch Jobs, Deployments, and PVCs only
in `ads-sandbox`. It has no exec or RBAC-management permission. IPC can read Pods
and get/create `pods/exec`, but cannot mutate labels, create workloads, mint tokens,
or access exec in `ads`.

## Reapply

Use the current project wiki for host addresses, forwarded SSH ports, and issuer;
do not store Computer egress addresses in these files. Follow the project's SSH
allowlist procedure and copy approved keys into the runtime key directory.

Before mutation, obtain approval for the brief Kafka interruption and disposable
object cleanup. Verify existing ADS, Kafka, PostgreSQL, and Keycloak are healthy.
Do not run this against an unrelated cluster.

1. Copy this directory's scripts/manifests to `/opt/src/ads-sandbox-identity` on the
   Kubernetes admin node, excluding `send_credentials.py` and tests.
2. Apply `kubernetes.yaml` using the admin kubeconfig.
3. Install the pinned admission controller, then the policy:

   ```sh
   helm repo add kyverno https://kyverno.github.io/kyverno/
   helm repo update kyverno
   helm upgrade --install kyverno kyverno/kyverno --version 3.9.1 \
     --namespace kyverno --create-namespace --wait --timeout 5m \
     -f /opt/src/ads-sandbox-identity/kyverno-values.yaml
   kubectl apply -f /opt/src/ads-sandbox-identity/exec-policy.yaml
   kubectl wait clusterpolicy/ads-sandbox-ipc-exec --for=condition=Ready --timeout=120s
   ```

4. Run `keycloak.py` through `run_keycloak.py --url <https-issuer-origin>` on the
   admin node. This executes a one-off Python script inside the existing ADS pod,
   using its installed ADS JWT verifier and trusted CA bundle. It does not change
   the application process. Supply the canonical secrets by JSON stdin.
5. Run `databases.py` on the admin node with its secret subset on stdin.
6. Run `kafka.py` on the admin node with its secret subset on stdin. This updates
   the JAAS Secret, enables broker authorization, waits for rollout, restores the
   existing engine-only anonymous ACLs, and applies scoped sandbox ACLs. The
   effective nonsecret StatefulSet is persisted at `/opt/src/kafka/statefulset.yaml`;
   do not later replace it with an older listener manifest.
7. Run `smoke_exec.py` and `smoke_kafka.py` on the admin node. Both clean up their
   uniquely named proof objects in `finally`. Check for leftovers after any hard
   interruption; do not delete objects by a broad sandbox prefix.
8. Check ADS pods, broker, Keycloak, database, and admission controller health.
   Engine may restart during the broker interruption. No ADS rollout is requested.

`send_credentials.py` runs only in the Computer sandbox and streams selected
canonical `testlab_creds/<name>.md` files through SSH stdin. The password generator
stays in the project file repo and must never be copied to the lab or source repo.
Never print credentials, JWTs, Secret `.data`, or generated database URLs.

```sh
python send_credentials.py --credentials "$CANONICAL_CREDS" \
  --names kafka-credentials ads-sandbox-mcp-kafka-credentials \
  ads-sandbox-manager-kafka-credentials ads-sandbox-ipc-kafka-credentials \
  -- ssh "${SSH_OPTIONS[@]}" "$ADMIN_NODE" \
  'python3 /opt/src/ads-sandbox-identity/kafka.py'
```

`SSH_OPTIONS` must include the wiki-derived forwarded port, runtime key,
`BatchMode=yes`, `IdentitiesOnly=yes`, `ConnectTimeout=15`, `CheckHostIP=no`,
and the node's `HostKeyAlias`. Never use an unverified host or disable TLS checks.

Required secret names, without `.md`:

| Script | Names |
| --- | --- |
| Keycloak | `keycloak-admin`, `ads-oidc-client`, `ads-engine-oidc-client`, `ads-test-user`, `ads-sandbox-mcp-oidc-client`, `ads-sandbox-manager-oidc-client`, `ads-sandbox-ipc-oidc-client` |
| Databases | `ads-sandbox-mcp-db-credentials`, `ads-sandbox-manager-db-credentials`, and all three sandbox `*-oidc-client` names |
| Kafka | `kafka-credentials` and all three sandbox `*-kafka-credentials` names |

## Identity proof

The user-subject chain is:

```text
ads -> ads-engine -> ads-sandbox-mcp -> ads-sandbox-manager
    -> ads-sandbox-ipc -> ads-sandbox-manager -> ads-sandbox-mcp
```

Every hop performs fresh Standard Token Exchange V2, verifies the signature,
issuer, exact downscoped audience, preserved user UUID/role, `azp`, and a token
lifetime greater than 120 seconds. Forwarded inbound tokens and unexpected
callers are rejected; an unrelated client cannot exchange a token not addressed
to it. Temporary direct grant on the test login client is restored in `finally`.
New clients do not enable browser/direct-grant/implicit flows.

IPC and manager client-credentials tokens use the **Keycloak client UUID** as
`sub`, not the service-account user's UUID. An admin-only user-profile attribute
and mapper implement that service-only subject; normal user exchanges preserve
the user UUID. These lifecycle tokens are not user-role authorization.
Existing engine client settings and audience mappers are preserved.

See [Keycloak Standard Token Exchange](https://www.keycloak.org/securing-apps/token-exchange)
for the requester/audience contract.

## Admission proof

Kyverno reads verified bound-token `pod-name` and `pod-uid` extras, fetches the
live caller Pod, checks its UID and ServiceAccount, and compares its nonempty
`ads.io/sandbox-id` label against the live target. Only the `sandbox` container
is allowed. Missing identity, lookup failure, mismatched labels, same Pod, or an
IPC target is denied. `failurePolicy: Fail` and enforcement are explicit.

The shared IPC ServiceAccount has no label mutation rights. This boundary
assumes the manager/admin creating the labels is trusted; it does not claim
to constrain cluster-admin or protect against a compromised manager.

The smoke uses real API-server-issued Pod-bound tokens in memory-only kubeconfigs:
matching pairs succeed; cross-sandbox in both directions, unlabeled callers or
targets, unbound tokens, self IPC exec, and the wrong container are denied by the
named policy. Separate RBAC checks deny workload, RBAC, token, and cross-namespace
escalation. These are published BusyBox Pods on the application node, not a Kata
guest or an end-to-end tool execution claim.

The lab pins Kyverno chart 3.9.1 / app v1.19.1 with one admission replica and no
background/cleanup/reports controllers. A singleton is deliberate for this lab,
not an HA production recommendation. The live admission proof passed on the
lab's Kubernetes v1.36.4; this does not expand upstream's published compatibility
matrix. `ClusterPolicy` remains supported here but emits a deprecation warning.

References:
[bound-token Pod identity](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/),
[Kyverno exec admission example](https://kyverno.io/policies/other/block-pod-exec-by-pod-label/block-pod-exec-by-pod-label/),
[Kyverno releases](https://kyverno.io/docs/installation/releases/).

## Kafka authorization

`StandardAuthorizer` denies unmatched access. Only authenticated `User:ads` is a
superuser. Loopback administration and the KRaft controller now use SASL/PLAIN;
ANONYMOUS is never a superuser. The existing anonymous ADS compatibility listener
is retained with only engine topic Read/Write/Describe and the existing `ads` /
`ads-engine` consumer groups. No synthetic engine records are published.

| Principal | Read | Write | Consumer-group scope |
| --- | --- | --- | --- |
| MCP | `ads.sandbox.exec.reply` | `ads.sandbox.exec.request` | `ads-sandbox-mcp-` prefix |
| Manager | `ads.sandbox.exec.request`, `ads.sandbox.ping.res`, `sandbox.res.` prefix | `ads.sandbox.exec.reply`, `ads.sandbox.ping.req`, `sandbox.req.` prefix | `ads-sandbox-manager` prefix |
| IPC | `sandbox.req.` prefix, `ads.sandbox.ping.req` | `sandbox.res.` prefix, `ads.sandbox.ping.res` | `ads-sandbox-ipc-` prefix |

Manager also reads/writes `ads.sandbox.ready`, `ads.sandbox.idle`, and
`ads.sandbox.recover`. IPC reads/writes `ads.sandbox.ready`. Describe accompanies
the topic/group rights. Only the manager may Create/Delete dynamic topics, and
only under `sandbox.req.` and `sandbox.res.`; no cluster-wide Create permission.
All seven static topics have one partition and replication factor one.

The three scoped Kafka Secrets are `ads/ads-sandbox-mcp-kafka`,
`ads/ads-sandbox-manager-kafka`, and `ads-sandbox/ads-sandbox-ipc-kafka`, each with
`username` and `password`. The broker's mounted client properties are for admin
proof execution only and must not be mounted into service workloads.

The smoke proves request/reply traffic in both service pairs, manager dynamic
topic create/delete, out-of-prefix denial, IPC recovery denial, foreign consumer
group denial, MCP dynamic-topic denial, and anonymous sandbox denial. Unauthorized
topics may be hidden by the CLI as nonexistent; the out-of-prefix delete proof
also verifies the topic remains present as admin. Repeated smoke runs append
nonsecret markers to the unused static sandbox request/reply topics; they never
truncate shared topics. Run this provisioning smoke before real consumers exist.

The shared IPC Kafka credential is deliberately prefix-wide, not a per-instance
identity. Per-sandbox exec isolation is the admission policy, not this Kafka ACL.
SASL/PLAIN runs on the existing private lab network without Kafka TLS; this is
identity/authorization, not transport confidentiality. Later runtime and Helm
slices must wire these scoped credentials; the earlier fake-based IPC/MCP code
does not become live-integrated merely because the lab credentials now exist.

See [Kafka authorization and ACLs](https://kafka.apache.org/42/security/authorization-and-acls/).

## Validation and recovery

Offline command:

```sh
python -m unittest discover -s deploy/lab/sandbox-identity/tests -v
```

These regression tests are also in the workspace pytest testpaths and therefore
the existing Nox test gate. Real Keycloak, PostgreSQL, Kafka, and admission proofs
remain mandatory; mocked tests do not replace them.

For a failed reconciliation, repair and reapply the affected step, then rerun its
proof. Do not remove the fail-closed admission policy as a workaround. Do not
delete databases, Secrets, or the namespace as automatic rollback. During a
Kafka outage, use the authenticated loopback admin properties; restoring an older
manifest without authorization is a separate security-sensitive rollback that
requires explicit approval.

No manager service, golden/session objects, runtime Kafka handshake, ADS upgrade,
image publish, or later sandbox slice is implemented by this directory.
