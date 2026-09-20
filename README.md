# ADS

Autonomous Development System: a Litestar service with Keycloak OIDC login serving Threadline (projects, sessions, streaming transcript), plus a stub egress control plane, an S2S model catalog, and a Kafka ads-engine worker.

Unauthenticated browsers are sent to Keycloak. After login the shell renders the project/session rail, the transcript, and the composer. Mutating routes are `AuthenticatedController` POST/PATCH/DELETE; services are guarded with wrapt `@require_role("user")` reading `SecurityContextHolder`. `ads` owns memory and streaming; `ads-engine` runs the bounded LangChain executor and calls sandbox tools through the official MCP SDK.

## Layout

- `libraries/ads-commons` — shared Kafka DTOs, dataclasses, and plain common logic
- `libraries/ads-commons-beans` — shared Dishka beans
- `libraries/ads-commons-schema` — shared Alembic upgrade and schema validation
- `services/ads` — Threadline UI, domain memory (SQLAlchemy + Alembic), engine request/output, preferences facade
- `services/ads-engine` — Kafka LangChain executor with sequential MCP sandbox tools
- `services/ads-preferences` — S2S user model catalog (Litestar JWT resource server)
- `services/ads-egress-controlplane` — dummy egress control plane (idle process)
- `services/ads-sandbox-manager`: golden-ensure service, included in workspace Nox gates and CI image builds; application deployment wiring follows in a later slice
- `charts/ads` — Helm chart (ADS + engine + preferences + egress-controlplane Deployments, ClusterIP Services, ConfigMap, Secret, ads HTTPRoute)
- Nox sessions: `lint`, `deps`, `typecheck`, `test`, `package`

Images:

- `ghcr.io/yet-another-solutions/ads`
- `ghcr.io/yet-another-solutions/ads-engine`
- `ghcr.io/yet-another-solutions/ads-preferences`
- `ghcr.io/yet-another-solutions/ads-egress-controlplane`

## Configuration

The ADS process reads `ADS_*` environment variables (Helm ConfigMap and Secret mount them):

- Keycloak: `ADS_KEYCLOAK_WELL_KNOWN_URL`, `ADS_KEYCLOAK_ISSUER`, `ADS_KEYCLOAK_CLIENT_ID`, `ADS_KEYCLOAK_CLIENT_SECRET`, `ADS_KEYCLOAK_AUDIENCE`, `ADS_KEYCLOAK_ROLE`
- Session: `ADS_SESSION_SECRET` (at least 16 bytes)
- Public URL: `ADS_PUBLIC_BASE_URL` (HTTPS)
- TLS: `ADS_TLS_CERT_PATH`, `ADS_TLS_KEY_PATH`, optional `ADS_TLS_CA_BUNDLE`
- Bind: `ADS_BIND_HOST`, `ADS_PORT`

TLS is required. Invalid certificate, key, or CA bundle material fails process startup instead of leaving a listening zombie.

Public probes: `/health/live`, `/health/ready`.

ads-engine is a Kafka worker (no HTTP). It reads `ADS_ENGINE_*`:

- Kafka: `ADS_ENGINE_KAFKA_BOOTSTRAP_SERVERS`, `ADS_ENGINE_REQUEST_TOPIC`, `ADS_ENGINE_OUTPUT_TOPIC`, `ADS_ENGINE_CONSUMER_GROUP`
- Store: `ADS_ENGINE_DATABASE_URL` (required; `postgresql+psycopg://` in production for the in-flight session table)
- Ping: `ADS_ENGINE_PING_INTERVAL_SECONDS` (default 10)
- Keycloak: `ADS_ENGINE_KEYCLOAK_WELL_KNOWN_URL`, `ADS_ENGINE_KEYCLOAK_ISSUER`, `ADS_ENGINE_KEYCLOAK_AUDIENCE`, `ADS_ENGINE_KEYCLOAK_CLIENT_SECRET`
- MCP: `ADS_ENGINE_MCP_URL` (default `https://ads-sandbox-mcp:8443/mcp`), `ADS_ENGINE_MCP_TIMEOUT_SECONDS` (default 120), `ADS_ENGINE_MAX_TOOL_CALLS` (default 32)
- TLS trust for Keycloak and MCP: `ADS_ENGINE_TLS_CA_BUNDLE` (optional additional CA bundle; HTTPS is mandatory)

The request `authorization` field is required on the wire. See
[engine execution and credential lifecycle](services/ads-engine/README.md) and
[Keycloak refresh configuration](deploy/keycloak/README.md#engine-mcp-refresh-and-existing-realms).

ads-preferences is a TLS-only JSON resource server (`python -m ads_preferences`). ClusterIP only: no HTTPRoute and no WAN slug. It does not import ads-engine. It reads `ADS_PREFERENCES_*`:

- Keycloak: `ADS_PREFERENCES_KEYCLOAK_WELL_KNOWN_URL`, `ADS_PREFERENCES_KEYCLOAK_ISSUER`, `ADS_PREFERENCES_KEYCLOAK_AUDIENCE` (default `ads-preferences`), `ADS_PREFERENCES_KEYCLOAK_CLIENT_ID` (default `ads`)
- Callers: `ADS_PREFERENCES_ALLOWED_CALLERS` (default `ads`)
- Database: `ADS_PREFERENCES_DATABASE_URL` (`postgresql+psycopg://` in production)
- TLS: `ADS_PREFERENCES_TLS_CERT_PATH`, `ADS_PREFERENCES_TLS_KEY_PATH`, optional `ADS_PREFERENCES_TLS_CA_BUNDLE`
- Bind: `ADS_PREFERENCES_BIND_HOST`, `ADS_PREFERENCES_PORT`

## Supported model names

`ads_commons.model_catalog.SUPPORTED_MODEL_TYPES` is the system-owned catalog,
not a user preference. Currently `openai-stream` supports `glm-5.3` and `glm-5.2`.
Other services can import this catalog without importing an application module.

Both authenticated discovery routes (`ads-preferences` `/v1/model-types` and
`ads` `/settings/model-types`) return:

```json
{"types": [{"type": "openai-stream", "names": ["glm-5.3", "glm-5.2"]}]}
```

This replaces the former list of type strings. Settings renders type/name
dropdowns from that response. The separate `name` field remains a user-defined
catalog label; `options.model-name` is the exact provider invoke id. Shared
`OpenAiStreamOptions` validates it on construction and wire decoding, so
preferences writes and engine Kafka requests cannot introduce arbitrary names.
Both engine paths pass the selected id unchanged to LangChain.

Deploy commons consumers (`ads`, `ads-preferences`, and `ads-engine`) together
for this contract change. Existing supported values need no data migration;
unsupported stored invoke names are not silently remapped to another model and
must be corrected explicitly before rollout.

## Session view continuity

Live updates follow the transcript tail when the reader is within 24 pixels of
the bottom. Otherwise they preserve the visible message's screen position,
including when the run bar disappears. Same-session refreshes also retain
expanded reasoning, the composer draft/caret, and the current model choice.
Notifications are coalesced, and responses targeting a replaced pane are ignored.

Each session restores the model from its latest persisted run, including an
active run, on navigation and reload. No schema change is needed. An unsent model
choice survives live updates but is not persisted until a turn is sent; a deleted
or unavailable model leaves the selector blank rather than choosing a substitute.

## Tests

The workspace declares public PyPI as its single default Python package index.
Local uv/Nox commands, GitHub CI/CD, and image builds use that same configuration;
they do not depend on lab DNS, a private package proxy, or index credentials.

```sh
uv sync --group test
uv run --group test playwright install --with-deps chromium
uv run --group test pytest
# Full lifecycle:
uv run --group dev nox -s lint deps typecheck test package
```

Litestar `TestClient` talks to the ASGI app in-process. Live uvicorn coverage is HTTPS. Keycloak testcontainers tests run when Docker is available (`quay.io/keycloak/keycloak:26.7.2`). GitHub CI has Docker; this sandbox does not.

Chromium regressions exercise the shipped HTMX, templates, CSS and JavaScript
against the in-process application with a fake engine and SQLite. They cover
desktop/mobile tail-following, reader position, delayed updates/navigation,
drafts, and session model selection without provider calls or lab access.
Nox installs Chromium; Linux system dependencies must be installed separately
with the Playwright command above (GitHub Actions does this automatically).

ads-engine tests mock Kafka and the LLM. They do not start a broker.

### Sandbox handshake cross-service proof

Slice 10 connects the real MCP HTTP/SDK tool callback, execution service, manager
provisioning/transit, IPC state machine, and guest-executor adapter in one test loop.
Run the focused proof with:

```bash
uv run --group dev nox -s test -- services/ads-sandbox-manager/tests/test_handshake_e2e.py
```

The test uses separate real PostgreSQL databases for MCP and manager, signed JWTs,
the production verifier and token-exchange adapters, and production wire publishers
and controllers. Testcontainers provides PostgreSQL by default. The existing
`ADS_MCP_TEST_DATABASE_URL` and `ADS_MANAGER_TEST_DATABASE_URL` overrides must point
to separate disposable databases: fixtures clear their state.

The encoded-message broker, token endpoint, Kubernetes API and guest process
streams are simulated. This is **not** a live Kafka/Keycloak/Kata or shell/Python
interpreter proof. The test checks both tool payloads and successful results,
eight fresh user-token exchanges per call, session reuse, PID and database
cleanup, pre-ack reset, post-ack abort, and invalid ack-reply rejection. Explicit
record delivery proves no guest command starts before IPC receives the matching
authorized `ack-reply`; the startup `true` ping is separate.

Live `exec_shell` and `exec_python` checks through deployed MCP → manager → IPC →
Kata guest remain deferred until the complete sandbox plan is implemented.
Existing component and race tests remain in place; this cross-service proof
complements them rather than replacing them.

ads-preferences tests plant JWTs and use SQLite. Catalog JSONB is stored as JSON on SQLite so this sandbox can run `nox -s test` without Docker. GitHub CI has Docker.

## Helm

See the [chart install and lifecycle guide](charts/ads/README.md). Store the release
record in the existing `default` namespace; chart templates create the dedicated
application and sandbox namespaces. Uninstall deletes both and their contents,
including sandbox PVCs. Existing releases in `ads` need a separately approved
ownership migration, not an in-place upgrade or an unreviewed uninstall.

`charts/ads/values.yaml` covers Keycloak OIDC URLs and client identity, Gateway HTTPRoute hostname for ads, and TLS via cert-manager or bring-your-own secrets (optional CA bundle). ads-preferences is an in-cluster ClusterIP TLS service (`preferences.*`, including `preferences.database.url`). Engine Kafka bootstrap, topics, Postgres URL (`engine.database.url`, mounted from the engine Secret), and unused Keycloak issuer/audience live under `engine.*`. The chart does not install Kafka or Postgres.

Install requires:

- at least one node labeled `ads.io/application-node=true`
- at least one node labeled `ads.io/sandbox-node=true` with Kata (`RuntimeClass` `kata-qemu`)
- Kyverno already installed with an established ClusterPolicy CRD and available admission controller. ADS ships its exec policy and scoped RBAC, not the Kyverno engine.
- Keycloak already serving the realm and confidential client in `keycloak.*` (`https://<httpRoute.hostname>/auth/callback`). The operator, instance, realm, and client are not installed by this chart.

Application pods (ADS, engine, preferences, and egress-controlplane) schedule on application nodes.

A standalone [Keycloak Operator realm-import sample](deploy/keycloak/README.md)
provides the six ADS clients and identity configuration for a new realm. CD
publishes it beside the chart, but Helm never applies it or owns the realm.
