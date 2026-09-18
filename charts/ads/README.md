# ADS Helm chart

## Install

Keep Helm's release record in the existing `default` namespace. The chart
creates both workload namespaces as normal templates: `namespace` (default
`ads`) and `sandbox.namespace` (default `ads-sandbox`). All application resources,
certificate service DNS names, and manager ServiceAccount references use
`namespace`, not the release-record namespace.

```sh
helm upgrade --install ads ./charts/ads \
  --namespace default -f <site-values.yaml> --wait
```

No namespace-creation flag or separate namespace apply is needed for ADS. Supply
real site values, including published image versions, credentials, and TLS
configuration. Externally managed dependencies and their namespaces (database,
Kafka, Keycloak, Gateway, cert-manager, Kyverno) remain outside this release.

The chart ships the sandbox exec ClusterPolicy, ServiceAccounts, Roles, and
RoleBindings, MCP and manager Deployments, and the internal HTTPS MCP Service.
It supplies the IPC ConfigMap, credentials, and TLS material in `sandbox.namespace`;
the manager, not Helm, creates golden/session/IPC workloads and PVCs.
It does not install the Kyverno engine or other infrastructure.
The policy reads verified Pod-bound token identity and the live caller/target
Pods; its Kyverno expressions are data, never evaluated by Helm's `tpl`.

## Kyverno prerequisite

Install Kyverno before ADS. Online install/upgrade and server-side dry runs
require its established `clusterpolicies.kyverno.io` CRD, an admission Deployment
with at least one available replica, and the configured admission ServiceAccount.
Lookup permission errors fail the operation rather than bypassing the check.
Online operations also require existing `sandbox-block` and the configured
`sandbox.ipc.storageClass`. These lookups are independent of the Node-list check.
Existence is not proof of CSI Block clone capability or backing-store reclamation.
RuntimeClass `kata-qemu` is fixed in v1, matching the manager's object builders.
Configure the existing installation using `sandbox.admission.kyvernoNamespace`,
`deploymentName`, and `serviceAccountName`; the policy name is `policyName`.
These are presence/availability checks, not an end-to-end webhook health probe.

The installing identity must be allowed to read Namespaces, CRDs, the configured
Kyverno Deployment and ServiceAccount, plus the existing topology prerequisites.
It must also be allowed to manage the chart's namespaces, ClusterPolicy, and RBAC.
StorageClass `get` is required as well.

Offline `helm template` and `helm lint` cannot inspect a cluster and therefore
skip live lookups. They are not prerequisite validation. Use the target cluster
for the preflight (treat the rendered output as secret-bearing):

```sh
helm upgrade --install ads ./charts/ads \
  --namespace default -f <site-values.yaml> --dry-run=server --hide-secret
```

## Sandbox configuration

- `sandbox.golden.slack` defaults to `2Gi` and must be at least that many bytes.
  Integer Kubernetes quantities only, matching the golden entrypoint; `2048Mi`
  works, `0`, `1Gi`, and `2G` fail even offline. Golden and clone capacity is
  release session size plus slack.
- Session size is **not a Helm value**. CI's `session_size` input (default `20Gi`)
  is stamped into `files/sandbox-release.yaml`, included in the chart artifact,
  and passed unchanged as `ADS_SESSION_SIZE`. `Chart.appVersion` supplies the
  golden version with a `v` prefix; the manager makes DNS-safe object names.
  `package_release.py` aligns all image tags with that same release. Manual
  workflow runs also produce the chart artifact; tagged pushes attach it to the
  release. No golden upgrade or existing-volume resize is implemented.
- MCP/manager use application placement, resources, replicas, HTTPS probes and
  optional application CA. The engine URL and MCP allowed-host list derive from
  the chart's actual service name and port; there is no public sandbox route.
- `sandbox.golden.resources`, `sandbox.guest.resources`, `sandbox.tolerations`,
  and `nodes.sandbox` configure manager-created Kata objects. IPC uses application
  placement/tolerations, `sandbox.ipc.resources`, Filesystem `storageClass` and
  `size`. `sandbox.imagePullSecrets` is a list of Secret **names already present
  in the sandbox namespace**; application workloads use `imagePullSecrets`.
- `sandbox.manager` exposes polling, bake/create/ready/barrier/control deadlines,
  node freshness, replication factor, and lifecycle settings: `idleSeconds=1800`,
  `detachedSeconds=7200`, `pvcTimeoutSeconds=120`, `lifecycleBatch=50`,
  `cleanupSeconds=120`, `pingIntervalSeconds=10`, `pingTimeoutSeconds=30`,
  `recoverySeconds=600`. The batch applies to the existing lifecycle schedulers.
- MCP and IPC expose timeout and input/stdout/stderr caps; IPC additionally exposes
  startup, ACK, polling and control deadlines. Engine exposes `mcpTimeoutSeconds`
  and `maxToolCalls`. Choose coordinated deadlines and Keycloak access-token TTL
  for provisioning plus execution; Helm does not change identity policy.

## Credentials, TLS, and external dependencies

MCP and manager require separate pre-created PostgreSQL databases. Helm never
creates databases, Keycloak clients/STE policy, Kafka topics/ACLs, CSI, Kata,
cert-manager, or Kyverno. All `change-me` values are development placeholders.
Supply real values using protected inputs or each component's `existingSecret`.
Those Secrets use the service's environment-key names:
`ADS_SANDBOX_<MCP|MANAGER|IPC>_KEYCLOAK_CLIENT_SECRET`, plus
`ADS_SANDBOX_<MCP|MANAGER>_DATABASE_URL`. Existing Secrets are not copied between
namespaces. Rendered manifests and Helm release values may contain secrets.

With cert-manager the chart issues three additional Certificates. A namespaced
Issuer must exist in both workload namespaces; a ClusterIssuer is usually simpler.
With BYO TLS, set all three `sandbox.<component>.tlsSecretName` values in addition
to the existing application/preferences TLS references. MCP and manager mount
`tls.caBundle`; IPC separately references `sandbox.ipc.caSecretName` in the
sandbox namespace, with key `ca.crt`. The IPC certificate serves HTTPS probes;
there is no shared IPC Service or guest HTTPS interface.

`sandbox.kafka.bootstrapServers` configures all three services. Each component's
`kafka.securityProtocol`, `saslMechanism`, `saslUsername`, and `saslPassword`
configure its own scoped Kafka identity. MCP/IPC support PLAINTEXT and
SASL_PLAINTEXT; manager additionally supports SSL/SASL_SSL and a separate Kafka CA.
SASL credentials are emitted only into Secrets, never ConfigMaps. An
`existingSecret` must supply the component-prefixed `KAFKA_SASL_USERNAME` and
`KAFKA_SASL_PASSWORD` environment keys when SASL is selected. Missing credentials
fail startup instead of falling back to anonymous access. SASL_PLAINTEXT does not
encrypt transport. Existing ADS/engine clients still use PLAINTEXT, so removal
of their compatibility listener and complete Kafka TLS remain separate work.
JWT/STE message authorization is unchanged.

Local deterministic proof uses real Helm rendering/server-side lookup requests
against a simulated API, plus the real service settings/object builders:

```sh
helm lint charts/ads
uv run --group test python -m unittest discover -s charts/ads/tests -v
```

These checks do not deploy anything or prove the live Kafka/Keycloak/Kata/CSI path.

## Uninstall and existing releases

```sh
helm uninstall ads --namespace default
```

Uninstall deletes **both workload namespaces and their contents**, including
manager-created sandbox PVCs. There is no namespace retention annotation.
Backing-disk deletion follows the storage provisioner's reclaim policy; the
lab's `sandbox-block` class uses `Delete`. The external Kyverno engine and other
infrastructure releases are not removed. Do not place unrelated workloads or
data in these chart-owned namespaces.

An existing release whose record is in `ads` cannot be upgraded in place with
this namespace layout. Installing another release in `default` is not a
migration: existing resources have incompatible ownership, and Helm must reject
them instead of silently adopting them. Likewise, existing manually provisioned
sandbox RBAC/policy/namespace resources require explicit ownership migration.
Do not uninstall the current release, use automatic ownership takeover, or
remove release records as an unreviewed shortcut.

Plan and approve a controlled migration separately, preserving the exact site
values, Secrets, resource ownership, and recovery material. This chart change
alone does not relocate an existing release or change a running installation.
