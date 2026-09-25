# Credential-preserving ADS fresh-schema reset

This is an operator-run tool, not an application startup side effect. It uses
explicit ADS database/workload targets, encrypted external records, UID-bound
writer fencing, ordinary Alembic initialization and the supported preferences
API. No live reset, provider invocation or Kubernetes operation is implied by
the source/test evidence.

## Safety boundary

The explicit application service set is `ads`, `ads-engine`, `ads-preferences`,
`ads-sandbox-manager` and `ads-sandbox-mcp`. Database names, URLs, role names,
Kubernetes context, namespace and workload names are operator inputs, not
discovered permission to reset other databases. Keycloak and unrelated services
are outside the tool's reset target set.

Only the `public` schema used by normal ADS initialization is supported. The
tool preserves the schema itself, its owner and ACL, database roles and grants.
It drops the complete explicit application table set, including the version
ledger, in one `DROP TABLE ... RESTRICT` transaction, then runs the same
`prepare_schema` initialization used by application startup. It does not
truncate rows or use unchecked `DROP SCHEMA ... CASCADE`. Unknown tables,
routines, custom types, partitions, non-table objects, column grants,
third-party grantors, external dependencies and connected writers block the
reset. Supported table grants are captured, restored and verified.

Workloads must be explicit Deployments or StatefulSets with exact label
selectors and no operator owner or HPA. Original UIDs and desired replicas
commit to the encrypted checkpoint before scaling. Zero desired/observed
replicas and no remaining matching Pods are required before SQL. Workload
replacement, namespace replacement, changed selectors or reappearing writers
block progress. An independent administrator or GitOps system must not
concurrently override the maintenance fence.

## Protected external records

Use an external directory owned by the operator, mode `0700`, outside the
checkout. Its recovery key is mode `0600`, generated once. Records use AES-GCM
with record-specific authenticated context and atomic fsynced replacement.
Symlinked, hard-linked, wrong-owner or unsafe-mode files are rejected.

Keep the recovery directory and key for the entire development/test effort.
Back up the key through approved protected credential storage. Do not put
the directory, decrypted inputs, URLs with credentials, owner refresh tokens or
model credentials in Git, CI artifacts, chat, shared documents or command-line
arguments. No key replacement or record-deletion command is exposed.

Run from the repository's normal uv environment:

```text
uv run python deploy/reset/cli.py --directory <external-private-directory> initialize-store
uv run python deploy/reset/cli.py --directory <external-private-directory> import --record configuration --input <external-mode-0600-configuration>
uv run python deploy/reset/cli.py --directory <external-private-directory> import --record owner-auth --input <external-mode-0600-owner-auth>
uv run python deploy/reset/cli.py --directory <external-private-directory> run
uv run python deploy/reset/cli.py --directory <external-private-directory> status
```

Input files must also be private, operator-owned, non-symlinked and outside the
checkout. Import encrypts them but does not erase the operator's originals.
Delete any unnecessary plaintext staging copies through the approved protected
credential workflow after independently verifying recovery.

The configuration record contains:

* `targets`: a list of objects with `service`, exact `database`, exact database
  `owner`, protected SQLAlchemy PostgreSQL `url`, and `schema: "public"`.
  Only the listed targets reset. Duplicate service or database targets fail.
* `namespace`, `context`: explicit Kubernetes namespace and kubeconfig context,
  with TLS verification enabled.
* `workloads`: objects with `service`, `kind` and `name`. Include all five ADS
  writer/controller services even when resetting fewer databases.
* `ca_bundle`: approved CA bundle path for Keycloak/preferences HTTPS, or null
  to use normal system trust. Insecure verification and redirects are disabled.

The `owner-auth` record contains `issuer`, `client_id: "ads"`, the protected
`client_secret`, `preferences_url`, and `owners`, keyed by each original
canonical owner UUID. Each owner's value has its protected `refresh_token`.
These are operator-provisioned valid delegated/offline refresh chains, not
borrowed service identities or a hardcoded test user.

Each API operation obtains a refreshed user token, verifies the exact subject
through TLS userinfo, performs fresh Standard Token Exchange for
`ads-preferences`, and then calls the supported API. Refresh-token rotation is
persisted before another network operation. Expired/ambiguous authorization
blocks progress; it never erases the preserved provider credential.

## Reset and restoration sequence

The coordinator persists the original database/schema identity, table grants,
workload scope and desired state before mutations. It fences writers, exports
complete model rows including real authentication and original owners, verifies
the encrypted roundtrip, proves delegated owner API access, fences again and
rejects configuration changes during preservation. Manager/MCP association
rows are encrypted outside any corresponding reset target.

A nonempty live model set refreshes the protected backup before each new
cycle. Empty live data reuses only a verified nonempty recovery copy; it never
overwrites that copy. Backup failure blocks all destructive SQL.

After scoped table reset and ordinary initialization, only preferences starts
for restoration. Models are recreated under their original owner through
`POST /v1/models`; full authenticated `GET` verifies every field. Generated ID
changes are recorded without changing owner or payload. Matching records are
reused; conflicting or ambiguous records block rather than overwrite or
duplicate. Lost successful create replies are recoverable by exact-payload
matching.

The tool performs a minimal tool-free authenticated provider call through the
ADS LangChain adapter for every restored model, then repeats restoration as an
idempotency check. Provider content, credentials and HTTP/SQL bodies are not
printed. Restoration or validation failure leaves dependent writers fenced.

## Restart, repetition and controller quarantine

Rerun `run` without `--new-cycle` to resume the same encrypted checkpoint.
Before/after-drop, initialization, restoration and workload-resumption failures
are retryable without discarding the original credential backup. A finished
cycle is idempotent. `run --new-cycle` starts another authorized reset only
after the previous cycle completed and refreshes preservation first.

Manager and sandbox-MCP remain at zero replicas after completion. This explicit
quarantine prevents a fresh registry from interpreting historical Kubernetes
objects as orphans eligible for deletion. The safe result reports this state;
it does not claim that sandbox execution has resumed. Other recorded ADS
workloads regain their intended replica counts after model validation.

Controller resumption requires a separately authorized reconciliation of the
encrypted original associations and actual retained resources. A database
reset, an empty registry, or an absent object is not deletion/ownership-transfer
authority. This tool does not dispose historical PVCs, native/Kata processes,
CA sources, Keycloak resources, infrastructure Secrets or namespaces.

Helm rollback does not restore a reset database. Recovery uses a compatible
application schema and this protected model restoration path; full historical
application-data recovery requires an independently verified full backup.

## Evidence

Synthetic-credential tests exercise real PostgreSQL reset/initialization,
production preferences service/repositories, encrypted backup refresh,
empty-source protection, idempotent owner restoration, grant preservation,
cross-scope refusal and failures after committed operations. Kubernetes,
identity-provider HTTP and provider invocation are the external test seams.
Live repeated reset, real Keycloak/provider authorization and actual workload
quiescence remain deployment validation obligations.
