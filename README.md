# ADS

Autonomous Development System: a Litestar service with Keycloak OIDC login serving Threadline (projects, sessions, streaming transcript), plus a stub egress control plane, an S2S model catalog, and a Kafka ads-engine worker.

Unauthenticated browsers are sent to Keycloak. After login the shell renders the project/session rail, the transcript, and the composer. Mutating routes are `AuthenticatedController` POST/PATCH/DELETE; services are guarded with wrapt `@require_role("user")` reading `SecurityContextHolder`. v1 is a chat wrapper: `ads` owns memory and streaming, `ads-engine` wraps the model.

## Layout

- `libraries/ads-commons` — shared Kafka DTOs, dataclasses, and plain common logic
- `libraries/ads-commons-beans` — shared Dishka beans
- `libraries/ads-commons-schema` — shared Alembic upgrade and schema validation
- `services/ads` — Threadline UI, domain memory (SQLAlchemy + Alembic), engine request/output, preferences facade
- `services/ads-engine` — Kafka chat wrapper (LangChain OpenAI stream)
- `services/ads-preferences` — S2S user model catalog (Litestar JWT resource server)
- `services/ads-egress-controlplane` — dummy egress control plane (idle process)
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
- Keycloak (loaded, unused until JWT verification): `ADS_ENGINE_KEYCLOAK_WELL_KNOWN_URL`, `ADS_ENGINE_KEYCLOAK_ISSUER`, `ADS_ENGINE_KEYCLOAK_AUDIENCE`

The request `authorization` field is required on the wire.

ads-preferences is a TLS-only JSON resource server (`python -m ads_preferences`). ClusterIP only: no HTTPRoute and no WAN slug. It does not import ads-engine. It reads `ADS_PREFERENCES_*`:

- Keycloak: `ADS_PREFERENCES_KEYCLOAK_WELL_KNOWN_URL`, `ADS_PREFERENCES_KEYCLOAK_ISSUER`, `ADS_PREFERENCES_KEYCLOAK_AUDIENCE` (default `ads-preferences`), `ADS_PREFERENCES_KEYCLOAK_CLIENT_ID` (default `ads`)
- Callers: `ADS_PREFERENCES_ALLOWED_CALLERS` (default `ads`)
- Database: `ADS_PREFERENCES_DATABASE_URL` (`postgresql+psycopg://` in production)
- TLS: `ADS_PREFERENCES_TLS_CERT_PATH`, `ADS_PREFERENCES_TLS_KEY_PATH`, optional `ADS_PREFERENCES_TLS_CA_BUNDLE`
- Bind: `ADS_PREFERENCES_BIND_HOST`, `ADS_PREFERENCES_PORT`

## Tests

```sh
UV_DEFAULT_INDEX=https://pypi.org/simple uv sync --group test
UV_DEFAULT_INDEX=https://pypi.org/simple uv run --group test pytest
```

Litestar `TestClient` talks to the ASGI app in-process. Live uvicorn coverage is HTTPS. Keycloak testcontainers tests run when Docker is available (`quay.io/keycloak/keycloak:26.7.2`). GitHub CI has Docker; this sandbox does not.

ads-engine tests mock Kafka and the LLM. They do not start a broker.

ads-preferences tests plant JWTs and use SQLite. Catalog JSONB is stored as JSON on SQLite so this sandbox can run `nox -s test` without Docker. GitHub CI has Docker.

## Helm

`charts/ads/values.yaml` covers Keycloak OIDC URLs and client identity, Gateway HTTPRoute hostname for ads, and TLS via cert-manager or bring-your-own secrets (optional CA bundle). ads-preferences is an in-cluster ClusterIP TLS service (`preferences.*`, including `preferences.database.url`). Engine Kafka bootstrap, topics, Postgres URL (`engine.database.url`, mounted from the engine Secret), and unused Keycloak issuer/audience live under `engine.*`. The chart does not install Kafka or Postgres.

Install requires:

- at least one node labeled `ads.io/application-node=true`
- at least one node labeled `ads.io/sandbox-node=true` with Kata (`RuntimeClass` `kata-qemu`)
- Keycloak already serving the realm and confidential client in `keycloak.*` (`https://<httpRoute.hostname>/auth/callback`). The operator, instance, realm, and client are not installed by this chart.

Application pods (ADS, engine, preferences, and egress-controlplane) schedule on application nodes.
