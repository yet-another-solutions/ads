# ADS

Autonomous Development System: a Litestar service with Keycloak OIDC login serving Threadline (projects, sessions, streaming transcript), plus a stub egress control plane, an S2S model catalog, a Kafka ads-engine worker, and the governance layer (policy decisions, run lifecycle, append-only audit).

Unauthenticated browsers are sent to Keycloak. After login the shell renders the project/session rail, the transcript, and the composer. Mutating routes are `AuthenticatedController` POST/PATCH/DELETE; services are guarded with wrapt `@require_role("user")` reading `SecurityContextHolder`. `ads` owns memory and streaming; `ads-engine` runs the bounded LangChain executor and calls sandbox tools through the official MCP SDK.

## Layout

- `libraries/ads-commons` — shared Kafka DTOs, dataclasses, and plain common logic
- `libraries/ads-commons-beans` — shared Dishka beans
- `libraries/ads-commons-schema` — shared Alembic upgrade and schema validation
- `services/ads` — Threadline UI, domain memory (SQLAlchemy + Alembic), engine request/output, preferences facade
- `services/ads-engine` — Kafka LangChain executor with sequential MCP sandbox tools
- `services/ads-preferences` — S2S user model catalog (Litestar JWT resource server)
- `services/ads-policy` — decision point: capability matrix, tool-call bindings, run lifecycle, isolation levels
- `services/ads-audit` — append-only journal of decisions, deny budget
- `services/ads-guardrail` — enforcement point outside every sandbox: MCP proxy and decision API
- `services/ads-injection-scanner` — prompt-injection classifier on ONNX Runtime for tool results (in `review` until a model is chosen)
- `services/ads-mcp-probe` — harmless MCP server whose tools trip every check, for end-to-end checks
- `services/ads-egress-controlplane` — dummy egress control plane (idle process)
- `services/ads-sandbox-manager`: golden-ensure service, included in workspace Nox gates and CI image builds; application deployment wiring follows in a later slice
- `charts/ads` — Helm chart (ADS + engine + preferences + policy + audit + egress-controlplane Deployments, optional guardrail, injection scanner, MCP probe and engine tools, sandbox namespace and workloads, ClusterIP Services, ConfigMaps, Secrets, ads HTTPRoute)
- Nox sessions: `lint`, `deps`, `typecheck`, `test`, `package`

Images:

- `ghcr.io/yet-another-solutions/ads`
- `ghcr.io/yet-another-solutions/ads-engine`
- `ghcr.io/yet-another-solutions/ads-preferences`
- `ghcr.io/yet-another-solutions/ads-policy`
- `ghcr.io/yet-another-solutions/ads-audit`
- `ghcr.io/yet-another-solutions/ads-guardrail`
- `ghcr.io/yet-another-solutions/ads-injection-scanner`
- `ghcr.io/yet-another-solutions/ads-mcp-probe`
- `ghcr.io/yet-another-solutions/ads-egress-controlplane`

## Configuration

The ADS process reads `ADS_*` environment variables (Helm ConfigMap and Secret mount them):

- Keycloak: `ADS_KEYCLOAK_WELL_KNOWN_URL`, `ADS_KEYCLOAK_ISSUER`, `ADS_KEYCLOAK_CLIENT_ID`, `ADS_KEYCLOAK_CLIENT_SECRET`, `ADS_KEYCLOAK_AUDIENCE`, `ADS_KEYCLOAK_ROLE`, `ADS_KEYCLOAK_AUDITOR_ROLE` (`auditor`; that role reads another person's chat, and every such reading is journalled)
- Journal: `ADS_AMQP_URL` — where an auditor's reading is published; `ADS_AUDIT_URL` and `ADS_AUDIT_API_TOKEN` — where an auditor reads and lifts a chat's block. Without them those endpoints answer that the journal is not configured
- Session: `ADS_SESSION_SECRET` (at least 16 bytes)
- Public URL: `ADS_PUBLIC_BASE_URL` (HTTPS)
- TLS: `ADS_TLS_CERT_PATH`, `ADS_TLS_KEY_PATH`, optional `ADS_TLS_CA_BUNDLE`
- Bind: `ADS_BIND_HOST`, `ADS_PORT`

TLS is required. Invalid certificate, key, or CA bundle material fails process startup instead of leaving a listening zombie.

Public probes: `/health/live`, `/health/ready`.

An auditor works through ads, where the role and the login already are, and ads asks the
journal with a service token: `GET /auditor/sessions/{id}/block` says whether a chat is
blocked, `DELETE` of the same path lifts the block and names the auditor as the one who
did. Without the role both are 403.

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

The governance services are HTTPS APIs behind a bearer token, reachable only from inside the cluster:

- ads-policy: `ADS_POLICY_API_TOKEN`, `ADS_REDIS_URL` (run state), `ADS_AMQP_URL` (decisions out), `ADS_POLICY_DIR`, `ADS_POLICY_MODE` (`enforce`/`review`), `ADS_POLICY_DENY_ON_ERROR`, `ADS_SANDBOX_AVAILABLE`, `ADS_RUN_WORKDIR`, `ADS_RUN_TTL_SECONDS`, `ADS_EGRESS_ALLOWLIST`, `ADS_PROTECTED_BRANCHES`
- ads-audit: `ADS_AUDIT_API_TOKEN`, `ADS_DATABASE_URL` (PostgreSQL journal), `ADS_AMQP_URL` (decisions in), `ADS_POLICY_URL` and `ADS_POLICY_API_TOKEN` (chat blocks out), `ADS_AUDIT_CONVERSATION_BUDGET_LIMIT` (`audit.conversationBudgetLimit`, 30)
- ads-guardrail (optional, `guardrail.enabled`): `ADS_GUARDRAIL_API_TOKEN`, `ADS_POLICY_URL`, `ADS_POLICY_API_TOKEN`, `ADS_AMQP_URL`, `ADS_ATTRIBUTES`, `ADS_MCP_SERVERS` (JSON `[{name, url, site, audience}]`; an agent reaches each at `/mcp/<name>`, and a call's isolation level follows from that server's `site`. A server that names an `audience` is reached with a token the guardrail mints for it through `ADS_KEYCLOAK_CLIENT_ID`/`ADS_KEYCLOAK_CLIENT_SECRET`, never with the caller's own; the session sandbox is such a server and the chart adds it as `sandbox` whenever the guardrail is enabled), `ADS_APPLICATIONS` (JSON `[{name, key_sha256, workspace}]`: applications such as hermes that call with their own key; their runs are opened by the guardrail), `ADS_MCP_AUDIENCE` (`guardrail.personTokenAudience`) with `ADS_KEYCLOAK_WELL_KNOWN_URL` and `ADS_KEYCLOAK_ISSUER` (whose tokens identify people; empty accepts none), `ADS_INJECTION_SCANNER_URL` with `ADS_INJECTION_SCANNER_API_TOKEN` (without them results whose injection check is enforced are withheld), `ADS_MCP_TIMEOUT_SECONDS`, `ADS_RUN_HEADER`. A person's run is opened by whoever creates the sandbox: `POST /guardrail/runs` with the person's token and the workspace.

All three take the same `ADS_TLS_*` and `ADS_BIND_HOST`/`ADS_PORT` as the ADS process.

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

## Tests

The workspace declares public PyPI as its single default Python package index.
Local uv/Nox commands, GitHub CI/CD, and image builds use that same configuration;
they do not depend on lab DNS, a private package proxy, or index credentials.

```sh
uv sync --group test
uv run --group test pytest
# Full lifecycle:
uv run --group dev nox -s lint deps typecheck test package
```

Litestar `TestClient` talks to the ASGI app in-process. Live uvicorn coverage is HTTPS. Keycloak testcontainers tests run when Docker is available (`quay.io/keycloak/keycloak:26.7.2`). GitHub CI has Docker; this sandbox does not.

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

`charts/ads/values.yaml` covers Keycloak OIDC URLs and client identity, Gateway HTTPRoute hostname for ads, and TLS via cert-manager or bring-your-own secrets (optional CA bundle). ads-preferences is an in-cluster ClusterIP TLS service (`preferences.*`, including `preferences.database.url`). Engine Kafka bootstrap, topics, Postgres URL (`engine.database.url`, mounted from the engine Secret), and unused Keycloak issuer/audience live under `engine.*`. The capability matrix, tool-call bindings, run TTL, egress allowlist and protected branches live under `policy.*`; the journal database and broker under `audit.*`; the optional enforcement point under `guardrail.*`. With `guardrail.enabled` the engine reaches the session sandbox through that enforcement point instead of directly, so every `exec_shell` and `exec_python` is decided, inspected and journalled; the sandbox then serves only the guardrail, and the engine needs `engine.workspace.*` (the run the guardrail opens for it) and `tls.caBundle.secretName`. The chart installs none of Kafka, Redis, RabbitMQ or Postgres.

Connection strings and secrets have no defaults: a value that works by accident is worse
than an install that stops. `charts/ads/values-ci.yaml` fills them with placeholders so
the chart can be rendered without a cluster, and `helm lint`/`helm template` in CI pass
it; `charts/ads/values-local.yaml` does the same for the throwaway stand.

Install requires:

- at least one node labeled `ads.io/application-node=true`
- Services `ads-redis`, `ads-rabbitmq` and `ads-postgres` (none of them installed by this chart)
- at least one node labeled `ads.io/sandbox-node=true` with Kata (`RuntimeClass` `kata-qemu`)
- Kyverno already installed with an established ClusterPolicy CRD and available admission controller. ADS ships its exec policy and scoped RBAC, not the Kyverno engine.
- Keycloak already serving the realm and confidential client in `keycloak.*` (`https://<httpRoute.hostname>/auth/callback`). The operator, instance, realm, and client are not installed by this chart.

Application pods (ADS, engine, preferences, policy, audit, and egress-controlplane) schedule on application nodes.

A standalone [Keycloak Operator realm-import sample](deploy/keycloak/README.md)
provides the six ADS clients and identity configuration for a new realm. CD
publishes it beside the chart, but Helm never applies it or owns the realm.
