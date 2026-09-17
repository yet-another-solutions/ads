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
RoleBindings. It does not install the Kyverno engine or sandbox workloads.
The policy reads verified Pod-bound token identity and the live caller/target
Pods; its Kyverno expressions are data, never evaluated by Helm's `tpl`.

## Kyverno prerequisite

Install Kyverno before ADS. Online install/upgrade and server-side dry runs
require its established `clusterpolicies.kyverno.io` CRD, an admission Deployment
with at least one available replica, and the configured admission ServiceAccount.
Lookup permission errors fail the operation rather than bypassing the check.
Configure the existing installation using `sandbox.admission.kyvernoNamespace`,
`deploymentName`, and `serviceAccountName`; the policy name is `policyName`.
These are presence/availability checks, not an end-to-end webhook health probe.

The installing identity must be allowed to read Namespaces, CRDs, the configured
Kyverno Deployment and ServiceAccount, plus the existing topology prerequisites.
It must also be allowed to manage the chart's namespaces, ClusterPolicy, and RBAC.

Offline `helm template` and `helm lint` cannot inspect a cluster and therefore
skip live lookups. They are not prerequisite validation. Use the target cluster
for the preflight (treat the rendered output as secret-bearing):

```sh
helm upgrade --install ads ./charts/ads \
  --namespace default -f <site-values.yaml> --dry-run=server --hide-secret
```

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
