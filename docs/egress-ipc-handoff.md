# Immutable IPC pair handoff

The fixed manager constructor reuses the ordinary-runtime IPC container spec
in a directly manager-owned Pod, with `restartPolicy: Always`, existing
PID/revision disk, credential references, TLS, projected ServiceAccount,
budgets and health endpoints. It adds exact
session/project/sandbox/generation labels for generation-bound policy selection, plus
explicit pair addresses, trusted ADS service-account subject and recorded guest
Pod name/UID/generation. Explicit environment entries override shared envFrom.
No wrapping key, egress private CA volume or host privilege reaches IPC.

Production IPC configuration with egress enabled requires that complete guest
identity. Partial inputs and egress configuration without an exact guest fail
before network startup. The real Kubernetes client also enforces that condition
for programmatically supplied Settings; there is no silent legacy fallback.
Unpaired legacy configuration retains its existing behavior.

For paired operation, discovery filters sandbox, generation, project and guest
component, then verifies exact name, UID and namespace. A lone old/replaced Pod
is not a fallback. Every exec independently checks the requested identity and
re-reads the exact Pod before opening its authenticated Kubernetes WebSocket.
Current projected ServiceAccount authentication and TLS remain unchanged; no
Keycloak token is sent to Kubernetes.

This is construction and runtime identity consumption, not create authority.
The lifecycle publisher must commit the exact Pod and verify recorded
compute/control/PID-volume dependencies before its one-shot dispatch. It must
track that writer through cleanup just like the other pair writers. No IPC
publication, readiness shortcut, retirement, schema reset or live acceptance is
introduced here. Existing configuration installation and latched health remain
independent and unchanged.
