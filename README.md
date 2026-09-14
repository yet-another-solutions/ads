# ADS

Autonomous Development System starter: a Litestar service with Keycloak OIDC login, a hello-world page, and a role-gated button, plus a stub egress control plane and a Kafka ads-engine worker.

Unauthenticated browsers are sent to Keycloak. After login, the page shows `hello world`. Submitting the button calls a controller that builds a `SecurityContext`, then a service method guarded with wrapt `@require_role("user")` that logs `button was pressed`.

## Layout

- `libraries/ads-commons` — shared Kafka DTOs and common types
- `services/ads` — Litestar controllers, Dishka services, OIDC, health
- `services/ads-engine` — Kafka chat wrapper (LangChain OpenAI stream)
- `services/ads-egress-controlplane` — dummy egress control plane (idle process)
- `charts/ads` — Helm chart (ADS + engine + egress-controlplane Deployments, Service, ConfigMap, Secret, HTTPRoute, PV/PVC)
- Nox sessions: `lint`, `deps`, `typecheck`, `test`, `package`

Images:

- `ghcr.io/yet-another-solutions/ads`
- `ghcr.io/yet-another-solutions/ads-engine`
- `ghcr.io/yet-another-solutions/ads-egress-controlplane`

## Configuration

The ADS process reads `ADS_*` environment variables (Helm ConfigMap and Secret mount them):

- Keycloak: `ADS_KEYCLOAK_WELL_KNOWN_URL`, `ADS_KEYCLOAK_ISSUER`, `ADS_KEYCLOAK_CLIENT_ID`, `ADS_KEYCLOAK_CLIENT_SECRET`, `ADS_KEYCLOAK_AUDIENCE`, `ADS_KEYCLOAK_ROLE`
- Session: `ADS_SESSION_SECRET` (at least 16 bytes)
- Public URL: `ADS_PUBLIC_BASE_URL` (HTTPS)
- Data directory: `ADS_DATA_DIR` (default `/data`)
- TLS: `ADS_TLS_CERT_PATH`, `ADS_TLS_KEY_PATH`, optional `ADS_TLS_CA_BUNDLE`
- Bind: `ADS_BIND_HOST`, `ADS_PORT`

TLS is required. Invalid certificate, key, or CA bundle material fails process startup instead of leaving a listening zombie.

Public probes: `/health/live`, `/health/ready`.

ads-engine is a Kafka worker (no HTTP). It reads `ADS_ENGINE_*`:

- Kafka: `ADS_ENGINE_KAFKA_BOOTSTRAP_SERVERS`, `ADS_ENGINE_REQUEST_TOPIC`, `ADS_ENGINE_OUTPUT_TOPIC`, `ADS_ENGINE_CONSUMER_GROUP`
- Store: `ADS_ENGINE_DATABASE_URL` (sqlite is enough for the in-flight session table)
- Ping: `ADS_ENGINE_PING_INTERVAL_SECONDS` (default 10)
- Keycloak (loaded, unused until JWT verification): `ADS_ENGINE_KEYCLOAK_WELL_KNOWN_URL`, `ADS_ENGINE_KEYCLOAK_ISSUER`, `ADS_ENGINE_KEYCLOAK_AUDIENCE`

The request `authorization` field is required on the wire. This turn does not verify the JWT.

## Tests

```sh
UV_DEFAULT_INDEX=https://pypi.org/simple uv sync --group test
UV_DEFAULT_INDEX=https://pypi.org/simple uv run --group test pytest
```

Litestar `TestClient` talks to the ASGI app in-process. Live uvicorn coverage is HTTPS. Keycloak testcontainers tests run when Docker is available (`quay.io/keycloak/keycloak:26.7.2`). GitHub CI has Docker; this sandbox does not.

ads-engine tests mock Kafka and the LLM. They do not start a broker.

## Helm

`charts/ads/values.yaml` covers Keycloak OIDC URLs and client identity, Gateway HTTPRoute hostname, TLS via cert-manager or bring-your-own secrets (optional CA bundle), and local-path PVC mounted at `/data`. Engine Kafka bootstrap, topics, sqlite URL, and unused Keycloak issuer/audience live under `engine.*`. The chart does not install Kafka or Postgres.

Install requires:

- StorageClass `local-path` (or the configured `persistence.storageClass`)
- at least one node labeled `ads.io/application-node=true`
- at least one node labeled `ads.io/sandbox-node=true` with Kata (`RuntimeClass` `kata-clh`)
- Keycloak already serving the realm and confidential client in `keycloak.*` (`https://<httpRoute.hostname>/auth/callback`). The operator, instance, realm, and client are not installed by this chart.

Application pods (ADS, engine, and egress-controlplane) schedule on application nodes.
