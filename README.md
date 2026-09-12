# ADS

Autonomous Development System starter: a Litestar service with Keycloak OIDC login, a hello-world page, and a role-gated button, plus a stub egress control plane.

Unauthenticated browsers are sent to Keycloak. After login, the page shows `hello world`. Submitting the button calls a controller that builds a `SecurityContext`, then a service method guarded with wrapt `@require_role("user")` that logs `button was pressed`.

## Layout

- `services/ads` — Litestar controllers, Dishka services, OIDC, health
- `services/ads-egress-controlplane` — dummy egress control plane (idle process)
- `charts/ads` — Helm chart (ADS + egress-controlplane Deployments, Service, ConfigMap, Secret, Ingress, PV/PVC)
- Nox sessions: `lint`, `deps`, `typecheck`, `test`, `package`

Images:

- `ghcr.io/yet-another-solutions/ads`
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

## Tests

```sh
UV_DEFAULT_INDEX=https://pypi.org/simple uv sync --group test
UV_DEFAULT_INDEX=https://pypi.org/simple uv run --group test pytest
```

Litestar `TestClient` talks to the ASGI app in-process. Live uvicorn coverage is HTTPS. Keycloak testcontainers tests run when Docker is available (`quay.io/keycloak/keycloak:26.7.2`). GitHub CI has Docker; this sandbox does not.

## Helm

`charts/ads/values.yaml` covers Keycloak URLs, ingress class and hostname, TLS via cert-manager or bring-your-own secrets (optional CA bundle), and local-path PVC mounted at `/data`.

Install requires:

- StorageClass `local-path` (or the configured `persistence.storageClass`)
- at least one node labeled `ads.io/application-node=true`
- at least one node labeled `ads.io/sandbox-node=true` with Kata (`RuntimeClass` `kata-clh`)

Application pods (ADS and egress-controlplane) schedule on application nodes.
