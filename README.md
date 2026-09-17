# ADS

Autonomous Development System: a Litestar service with Keycloak OIDC login serving Threadline (projects, sessions, streaming transcript), plus a stub egress control plane, an S2S model catalog, a Kafka ads-engine worker, and the governance layer (policy decisions, run lifecycle, append-only audit).

Unauthenticated browsers are sent to Keycloak. After login the shell renders the project/session rail, the transcript, and the composer. Mutating routes are `AuthenticatedController` POST/PATCH/DELETE; services are guarded with wrapt `@require_role("user")` reading `SecurityContextHolder`. v1 is a chat wrapper: `ads` owns memory and streaming, `ads-engine` wraps the model.

## Layout

- `libraries/ads-commons` — shared Kafka DTOs, dataclasses, and plain common logic
- `libraries/ads-commons-beans` — shared Dishka beans
- `libraries/ads-commons-schema` — shared Alembic upgrade and schema validation
- `services/ads` — Threadline UI, domain memory (SQLAlchemy + Alembic), engine request/output, preferences facade
- `services/ads-engine` — Kafka chat wrapper (LangChain OpenAI stream)
- `services/ads-preferences` — S2S user model catalog (Litestar JWT resource server)
- `services/ads-policy` — decision point: capability matrix, tool-call bindings, run lifecycle, isolation levels
- `services/ads-audit` — append-only journal of decisions, deny budget
- `services/ads-guardrail` — enforcement point outside every sandbox: MCP proxy and decision API
- `services/ads-injection-scanner` — prompt-injection classifier on ONNX Runtime for tool results (in `review` until a model is chosen)
- `services/ads-mcp-probe` — harmless MCP server whose tools trip every check, for end-to-end checks
- `services/ads-egress-controlplane` — dummy egress control plane (idle process)
- `charts/ads` — Helm chart (ADS + engine + preferences + policy + audit + egress-controlplane Deployments, optional guardrail, injection scanner, MCP probe and engine tools, ClusterIP Services, ConfigMaps, Secrets, ads HTTPRoute)
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
- Keycloak (loaded, unused until JWT verification): `ADS_ENGINE_KEYCLOAK_WELL_KNOWN_URL`, `ADS_ENGINE_KEYCLOAK_ISSUER`, `ADS_ENGINE_KEYCLOAK_AUDIENCE`

The request `authorization` field is required on the wire.

ads-preferences is a TLS-only JSON resource server (`python -m ads_preferences`). ClusterIP only: no HTTPRoute and no WAN slug. It does not import ads-engine. It reads `ADS_PREFERENCES_*`:

- Keycloak: `ADS_PREFERENCES_KEYCLOAK_WELL_KNOWN_URL`, `ADS_PREFERENCES_KEYCLOAK_ISSUER`, `ADS_PREFERENCES_KEYCLOAK_AUDIENCE` (default `ads-preferences`), `ADS_PREFERENCES_KEYCLOAK_CLIENT_ID` (default `ads`)
- Callers: `ADS_PREFERENCES_ALLOWED_CALLERS` (default `ads`)
- Database: `ADS_PREFERENCES_DATABASE_URL` (`postgresql+psycopg://` in production)
- TLS: `ADS_PREFERENCES_TLS_CERT_PATH`, `ADS_PREFERENCES_TLS_KEY_PATH`, optional `ADS_PREFERENCES_TLS_CA_BUNDLE`
- Bind: `ADS_PREFERENCES_BIND_HOST`, `ADS_PREFERENCES_PORT`

The governance services are HTTPS APIs behind a bearer token, reachable only from inside the cluster:

- ads-policy: `ADS_POLICY_API_TOKEN`, `ADS_REDIS_URL` (run state), `ADS_AMQP_URL` (decisions out), `ADS_POLICY_DIR`, `ADS_POLICY_MODE` (`enforce`/`review`), `ADS_POLICY_DENY_ON_ERROR`, `ADS_SANDBOX_AVAILABLE`, `ADS_RUN_WORKDIR`, `ADS_RUN_TTL_SECONDS`, `ADS_EGRESS_ALLOWLIST`, `ADS_PROTECTED_BRANCHES`
- ads-audit: `ADS_AUDIT_API_TOKEN`, `ADS_DATABASE_URL` (PostgreSQL journal), `ADS_AMQP_URL` (decisions in), `ADS_POLICY_URL` and `ADS_POLICY_API_TOKEN` (chat blocks out), `ADS_AUDIT_CONVERSATION_BUDGET_LIMIT` (`audit.conversationBudgetLimit`, 30)
- ads-guardrail (optional, `guardrail.enabled`): `ADS_GUARDRAIL_API_TOKEN`, `ADS_POLICY_URL`, `ADS_POLICY_API_TOKEN`, `ADS_AMQP_URL`, `ADS_ATTRIBUTES`, `ADS_MCP_SERVERS` (JSON `[{name, url, site}]`; an agent reaches each at `/mcp/<name>`, and a call's isolation level follows from that server's `site`), `ADS_APPLICATIONS` (JSON `[{name, key_sha256, workspace}]`: applications such as hermes that call with their own key; their runs are opened by the guardrail), `ADS_MCP_AUDIENCE` (`guardrail.personTokenAudience`) with `ADS_KEYCLOAK_WELL_KNOWN_URL` and `ADS_KEYCLOAK_ISSUER` (whose tokens identify people; empty accepts none), `ADS_INJECTION_SCANNER_URL` with `ADS_INJECTION_SCANNER_API_TOKEN` (without them results whose injection check is enforced are withheld), `ADS_MCP_TIMEOUT_SECONDS`, `ADS_RUN_HEADER`. A person's run is opened by whoever creates the sandbox: `POST /guardrail/runs` with the person's token and the workspace.

All three take the same `ADS_TLS_*` and `ADS_BIND_HOST`/`ADS_PORT` as the ADS process.

## Tests

```sh
UV_DEFAULT_INDEX=https://pypi.org/simple uv sync --group test
UV_DEFAULT_INDEX=https://pypi.org/simple uv run --group test pytest
```

Litestar `TestClient` talks to the ASGI app in-process. Live uvicorn coverage is HTTPS. Keycloak testcontainers tests run when Docker is available (`quay.io/keycloak/keycloak:26.7.2`). GitHub CI has Docker; this sandbox does not.

ads-engine tests mock Kafka and the LLM. They do not start a broker.

ads-preferences tests plant JWTs and use SQLite. Catalog JSONB is stored as JSON on SQLite so this sandbox can run `nox -s test` without Docker. GitHub CI has Docker.

## Helm

`charts/ads/values.yaml` covers Keycloak OIDC URLs and client identity, Gateway HTTPRoute hostname for ads, and TLS via cert-manager or bring-your-own secrets (optional CA bundle). ads-preferences is an in-cluster ClusterIP TLS service (`preferences.*`, including `preferences.database.url`). Engine Kafka bootstrap, topics, Postgres URL (`engine.database.url`, mounted from the engine Secret), and unused Keycloak issuer/audience live under `engine.*`. The capability matrix, tool-call bindings, run TTL, egress allowlist and protected branches live under `policy.*`; the journal database and broker under `audit.*`; the optional enforcement point under `guardrail.*`. The chart installs none of Kafka, Redis, RabbitMQ or Postgres.

Install requires:

- at least one node labeled `ads.io/application-node=true`
- Services `ads-redis`, `ads-rabbitmq` and `ads-postgres` (none of them installed by this chart)
- Keycloak already serving the realm and confidential client in `keycloak.*` (`https://<httpRoute.hostname>/auth/callback`). The operator, instance, realm, and client are not installed by this chart.

Sandbox nodes are not required to install. The chart looks for the `RuntimeClass` named in `nodes.sandbox.runtimeClassName` on nodes labeled `ads.io/sandbox-node=true` and tells the policy service what it found; without Kata no run is ever assigned the `vm` isolation level, and the capabilities the matrix grants only there stay out of reach.

Application pods (ADS, engine, preferences, policy, audit, and egress-controlplane) schedule on application nodes.
