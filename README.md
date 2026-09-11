# ADS

Autonomous Development System starter: a Litestar service with Keycloak OIDC login, a hello-world page, and a role-gated button.

Unauthenticated browsers are sent to Keycloak. After login, the page shows `hello world`. Submitting the button calls a controller that builds a `SecurityContext`, then a service method guarded with wrapt `@require_role("user")` that logs `button was pressed`.

## Layout

- `src/ads` — Litestar controllers, Dishka services, OIDC, health
- `charts/ads` — Helm chart (Deployment, Service, ConfigMap, Secret, Ingress, PV/PVC)
- `Containerfile` — image published to `ghcr.io/yet-another-solutions/ads`
- Nox sessions: `lint`, `deps`, `typecheck`, `test`, `package`

## Configuration

The process reads `ADS_*` environment variables (Helm ConfigMap and Secret mount them):

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
