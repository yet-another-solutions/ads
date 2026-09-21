# Egress binding and publication

## Ownership and provisioning

ADS owns the session/project association. Manager resolves it through a narrow
`GET /internal/sessions/{session_id}/project` before creating a pending row or
Kubernetes object. This implements the verified provisioning input without
adding a model-selected project field to the execution DTO.

That lookup is one additional read-only service hop: manager obtains fresh own
client credentials and own-token STE for audience `ads`. ADS verifies issuer,
audience, `azp=ads-sandbox-manager`, and the configured native manager service-user
UUID. It returns only the two IDs. Browser cookies alone never authorize it.

Manager persists nonnullable `project_id` in its fresh initial schema. A changed
association fails closed; there is no legacy migration, backfill or adoption.
`GET /v1/sandboxes/{sandbox_id}/binding` accepts only the configured native ADS
service subject and `azp=ads`. Pending, creating and ready rows are eligible;
retiring, stopped, failed, recovering and missing/superseded IDs are not.
The read is available before manager readiness, avoiding an IPC-startup cycle.
It exposes no credentials, execution or policy assembly.

## Startup requests and saves

ADS verifies config-request JWTs on receipt through commons, with exact IPC
caller and configured native service subject. It fetches the manager binding,
checks sandbox/project/eligibility, and independently checks its own session's
project. Only then does it read preferences and publish a project snapshot.
Each manager read, preferences read and publication gets a fresh service-origin
token exchange. Incoming credentials are never forwarded or reused.

Preferences service reads are a separate client operation. Delegated user writes
and model operations retain their existing token path. The deployed preferences
authorization must restrict ADS service identity to project-egress GET.

After an owner-authorized UI save, ADS publishes the returned persisted revision
and settings. The Kafka payload expands semantic defaults while preserving rule
order. Broker/token failure returns HTTP 503 with the saved revision and an
explicit "saved, but update publication failed" dialog. There is no rollback,
outbox, ack topic or claim of installation at every sandbox.

The application-owned producer and competing request consumer use the configured
Kafka transport, including SASL and optional TLS. IPC subscriptions remain
per-sandbox fan-out groups. Consumer death latches this application's egress
gateway unhealthy; publication fails and readiness returns 503. An empty broker
configuration retains offline HTTPS liveness only, never ready publication.

## Deployment inputs and remaining boundary

ADS requires `ADS_SANDBOX_MANAGER_BASE_URL`, `ADS_MANAGER_SERVICE_SUBJECT` and
`ADS_IPC_SERVICE_SUBJECT`. Manager requires `ADS_SANDBOX_MANAGER_ADS_BASE_URL`
and `ADS_SANDBOX_MANAGER_ADS_SERVICE_SUBJECT`. These are platform-owned values,
not message-selected addresses. Client URLs are verified HTTPS and may not
contain credentials, query strings or fragments.

Helm renders these IDs from `keycloak.serviceSubjects` (ADS, manager and IPC
native user UUIDs), derives both internal HTTPS URLs, and exposes a manager
ClusterIP Service with its existing TLS certificate. Empty subject defaults
cannot authorize operations; runtime loaders require the binding subjects.
Preferences receives the same ADS subject for read-only service authorization.
Application Kafka accepts a referenced username/password Secret or generated
Secret entries, plus an optional broker CA mount; credentials never enter ConfigMaps.

Fresh application schemas, scoped audience permissions, Kafka principal/ACLs
and the configured Helm inputs must be installed together before live use. This component
does not claim paired CNI denial or an operational egress data-plane receiver.
Those remain separate implementation/live proof gates in the canonical tracker.
