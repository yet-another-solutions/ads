# ADS Keycloak realm import sample

This is a standalone `k8s.keycloak.org/v2beta1` **KeycloakRealmImport resource**,
not a CRD definition and not an ADS Helm template. Install the Keycloak Operator
and its CRDs separately. The sample targets Keycloak 26.7.2 and the matching
Operator, including the lab's stripped-keycloak distribution.

It is a bootstrap example for a **new** realm. It does not change the sandbox
slice plan, reconcile an existing realm, deploy ADS, or contain lab secrets.

## Adapt and apply

1. Copy `ads-realm-import.sample.yaml`. Set `metadata.namespace` to the namespace
   watched by your Operator and `spec.keycloakCRName` to the existing Keycloak CR.
   Set `spec.realm.realm` for a new realm if `ads` already exists.
2. Replace every `https://ads.example.com` browser URL with your exact public ADS
   HTTPS origin. Keep the redirect URI restricted to `/auth/callback`; do not
   use wildcard redirects. The example does not require PKCE because the current
   confidential ADS browser client does not send a PKCE challenge.
3. Select unique UUIDs for the manager and IPC client `id` fields. Update each
   matching service-account `ads_service_client_uuid` attribute to the same value.
   The published UUIDs are examples, not live IDs. Do not reuse them for multiple
   realms on one Keycloak instance.
4. Provision Secret `ads-realm-client-secrets` in the **Keycloak namespace**, with
   keys `ads`, `ads-engine`, `ads-preferences`, `ads-sandbox-mcp`,
   `ads-sandbox-manager`, and `ads-sandbox-ipc`. Supply independently generated
   confidential-client secrets using your approved secret-management process.
   There is intentionally no Secret manifest with example passwords.
5. Review the full realm and perform a server-side dry run, then apply the
   reviewed resource. Do not run `envsubst` or resolve the placeholders in CD:
   the Operator's `spec.placeholders` maps each `${...}` to a Secret key at import.

```sh
kubectl apply --dry-run=server -f ads-realm-import.sample.yaml
# Only after reviewing the target realm and Secret provisioning:
kubectl apply -f ads-realm-import.sample.yaml
kubectl -n keycloak get keycloakrealmimport ads-realm-sample -o yaml
```

Inspect the import status and associated Job; a CRD schema dry run does not prove
the realm data can be imported. After a successful import, remove the import CR
to clean up its Job/Pod. Removing the CR does not delete the realm. If a realm
with the same name already exists, the Operator does **not** overwrite it;
edits to this CR are not ongoing realm reconciliation.

See the [Operator realm-import guide](https://www.keycloak.org/operator/realm-import)
for create-only semantics, status conditions, placeholder security, and cleanup.
Only trusted administrators should create import resources: placeholder
replacement can expose the import Job's environment variables.

## Included identity configuration

| Client | Browser code flow | STE V2 | Access-token audiences |
| --- | --- | --- | --- |
| `ads` | Yes | Yes | `ads`, `ads-engine`, `ads-preferences` |
| `ads-engine` | No | Yes | Default: `ads-sandbox-mcp`; optional `ads-engine-ack` scope: `ads` |
| `ads-preferences` | No | No | `ads-preferences` |
| `ads-sandbox-mcp` | No | Yes | `ads-sandbox-manager` |
| `ads-sandbox-manager` | No | Yes | `ads-sandbox-manager`, `ads-sandbox-ipc`, `ads-sandbox-mcp` |
| `ads-sandbox-ipc` | No | Yes | `ads-sandbox-manager` |

All six clients are confidential with service accounts. Direct/password and
implicit grants are disabled. Access tokens have a 300-second lifespan, preserving
the sandbox's greater-than-120-second requirement. The browser gets normal
session-bound refresh tokens; no client is assigned `offline_access`.

The realm declares `user` but does not grant it by default or ship a human/test
account. Provision users separately and explicitly assign `user` to authorized
people. All client scopes are restricted (`fullScopeAllowed: false`) with explicit
realm-role scope mappings; these permit an already-authorized user's role to
survive exchange without granting that role to service accounts.

The manager and IPC `sub` mappers read `ads_service_client_uuid`, an attribute
editable/viewable only by administrators. Their service-account records contain
the matching client UUID. Client-credentials lifecycle tokens therefore have
the client UUID subject, while user-subject exchanges retain the user's UUID.
Do not replace this with an unconditional hardcoded-subject mapper.

Audiences enable the intended exchange paths but are **not** a substitute for
ADS caller allowlists. Each callee still verifies signature, issuer, expiry,
UUID subject, audience, and permitted `azp`; user operations require `user`.
Lifecycle tokens are service identity, not a user security context. Hops use a
fresh [Standard Token Exchange V2](https://www.keycloak.org/securing-apps/token-exchange),
except the run-local engine-to-MCP pair described below.

Configure ADS issuer/discovery/JWKS URLs for the imported realm and distribute
the matching client secrets to the relevant application namespaces. The import
Secret is not the runtime Secret and is not automatically copied across namespaces.
The current Helm chart does not yet wire all later sandbox runtime credentials.
Record the imported manager/IPC client UUIDs for later lifecycle verification.

## Engine MCP refresh and existing realms

The engine initially exchanges the inbound user token for an MCP access/refresh
pair, then uses only refresh grants for that run. Enable the engine client
attribute `standard.token.exchange.enableRefreshRequestedTokenType=SAME_SESSION`;
the sample keeps access-token lifespan at 300 seconds, exceeding twice the
default 120-second MCP timeout. Refresh recomputes claims from client scopes and
mappers, so `audience` on the initial STE alone is not a durable restriction.
See [Keycloak token exchange](https://www.keycloak.org/securing-apps/token-exchange).

The engine has only `basic` and metadata-only `service_account` as default scopes, a direct MCP audience mapper, a
direct realm-role mapper, `fullScopeAllowed=false`, and explicit `user` role
scope mapping. It has no default `roles`, audience-resolve, service-account role,
offline, or broad client-role mapper. The separate `ads-engine-ack` optional
scope adds only `ads`; engine ACK STE explicitly requests it, while MCP STE never
does. Do not attach that scope as default or request it for the MCP refresh pair.
Because declaring custom scopes suppresses automatic built-in scope creation on
realm import, the sample also includes explicit Keycloak 26.7.2 definitions for
`basic`, `roles`, `profile`, `email`, and `service_account`, exported without IDs
from a disposable realm. Keycloak automatically attaches `service_account` for
service-account-enabled clients; its session-note mappers add no roles or audiences.

For an existing lab realm, **do not apply the create-only import to reconcile it**.
At the deferred deployment stage, use an authenticated Keycloak Admin REST client
over trusted TLS. Obtain the realm and client UUID by discovery, not from the
sample UUIDs. Preserve a protected pre-change export and reconcile these exact
resources from `spec.realm` in the sample:

1. `GET /admin/realms/{realm}/clients?clientId=ads-engine`: require exactly one
   match. On that client, `PUT /clients/{id}` the existing representation with
   `fullScopeAllowed=false` and the sample engine attributes merged into
   `attributes`. Preserve its live secret, UUID and other unrelated fields.
2. `GET /client-scopes`: upsert the `ads-engine-ack` scope with exactly the sample
   scope's mapper/config via `POST /client-scopes` or `PUT /client-scopes/{id}`;
   reconcile its `/protocol-mappers/models` explicitly as well. This shared
   scope must have no additional mappers or role mappings.
3. For `/clients/{id}/default-client-scopes`, remove every attached scope except
   `basic` and `service_account` with `DELETE .../{scope-id}`. Attach either if missing using
   `PUT .../{scope-id}`. Inspect both scopes for unexpected custom role or
   audience mappers before proceeding; do not silently modify a shared scope.
4. Reconcile `/clients/{id}/optional-client-scopes` to only `ads-engine-ack`
   using the same GET/DELETE/PUT membership endpoints.
5. Reconcile `/clients/{id}/protocol-mappers/models` to the two engine mappers
   in the sample: `audience-ads-sandbox-mcp` and `scoped-user-role`. Delete superseded
   ADS/engine audience mappers, audience-resolve, or other widening mappers.
   Create/update by mapper name using POST or PUT with the observed mapper ID.
6. Reconcile `/clients/{id}/scope-mappings/realm` to the real `user` role
   representation (`GET /roles/user`). Remove other realm and client-role scope
   mappings, inspect composites, and verify service accounts have no user role.
   Keep human role assignments unchanged.
7. Read all resources back and compare against these desired fields. Verify a
   browser-user token → engine STE → MCP pair, then at least two refreshes:
   unchanged UUID subject, `azp=ads-engine`, singleton `ads-sandbox-mcp` audience,
   only `user` realm role, no `resource_access`, and usable expiry. Separately
   verify ACK STE with `scope=ads-engine-ack` targets `ads` and still supports the
   return ADS→engine exchange. Fail deployment on any extra authority.

All paths after the first step are relative to `/admin/realms/{realm}`.
Review deletions against the protected export before approval; never print
client secrets or access/refresh tokens. These are reproducible desired-state
changes, not a claim that the existing lab was modified. Live reconciliation
and sustained refresh/expiry/revocation smoke are deferred until the full plan.

## CD artifacts and verification

The existing `publish` workflow uploads an `ads-keycloak-realm-<version>` Actions
artifact, including on manual dry-run runs. Tagged CD also attaches the versioned
sample YAML and this guide to the GitHub Release beside the Helm chart.
Packaging copies the sample unchanged: it never reads cluster Secrets, substitutes
credentials, invokes Keycloak, or applies the CR. No tag or publish is triggered
merely by adding this sample.

CI checks the manifest contract and imports its `spec.realm` into disposable
Keycloak 26.7.2 over TLS. It verifies the user STE routes, negative exchanges,
service UUID subjects, and protected profile configuration. This is separate
from live Operator reconciliation; no test realm is created in the lab.
