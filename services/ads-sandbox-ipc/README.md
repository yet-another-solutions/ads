# ads-sandbox-ipc

Slice 5: a DB-less per-sandbox Kafka handshake peer and Kubernetes execution bridge.
Run `python -m ads_sandbox_ipc`. The manager is its only Kafka caller; there is no
business HTTP API, MCP endpoint, database, manager implementation, or guest code here.

## Lifecycle and execution

- Seek `sandbox.req.{sandbox_id}` and `ads.sandbox.ready` to end on process start.
  Hold the request partition paused until Kafka `ready` has been produced.
- Select exactly one non-terminating pod with `ads.io/sandbox-id={sandbox_id}`,
  container `sandbox`, and a true Pod Ready condition, not a Deployment's status.
- Reap only recorded guest process trees and the crash-window guest PID file.
  Records include pod UID so stale PIDs cannot target a replacement PID namespace.
  Empty/absent PID state is success; corrupt PVC records fail startup closed.
- Ping with `ads-session-exec shell true`, latch HTTP readiness, then emit Kafka
  `ready`. Timeout emits one startup `error` and stays live. Shutdown during startup
  cancels startup and wins over ready/error.
- `request` acknowledges without executing. Matching `ack-reply` starts execution;
  reset, abort-before-ack, and ack timeout drop the waiting unit.
  `acknowledge`, `ack-reply`, `ack-reset`, and `abort` require the full
  `execution_id`, `session_id`, `message_id` tuple. Controls must match all three
  IDs and the authenticated subject, including terminal-result replay.
- Keep one current unit and one terminal slot. Duplicate requests never start the
  current/last execution again. A terminal result can be redelivered after a
  produce failure. A different authenticated subject cannot take over a unit.
- Shell argv is `ads-session-exec shell <verbatim-command>`; Python argv is
  `ads-session-exec python`, with UTF-8 code on stdin. Kubernetes exec uses the
  `v5.channel.k8s.io` protocol for explicit stdin EOF, with no TTY.
- Input caps are UTF-8 byte limits. Oversize input returns `is_error` without exec.
  Stdout/stderr retain bounded byte prefixes and keep draining until process exit.
  Invalid or incomplete UTF-8 bytes are omitted rather than expanding the limit.
  Nonzero process exit is not an infrastructure error.
- A second, cat-only exec reads `/run/ads-session-exec.pid`; PID storage uses atomic
  replacement plus file and directory fsync on the IPC Filesystem PVC. No JWT,
  command, code, stdout, or stderr is written there.
- Abort/timeout reaps that tree only. Successful execution never reaps background
  work. Cleanup failure preserves PID state and blocks further guest execution.
- Ping consumption starts at the current end only after ready and stays independent
  of the exec worker. Ping proves IPC Kafka-loop responsiveness, not guest health.
- Shutdown stops new work/ping, drains current execution, emits result before
  shutdown-ack, and acknowledges repeated shutdowns. A failed result publication
  cannot be bypassed by shutdown-ack.

## Authentication and transport

The controller uses the shared JWT verifier, requiring `aud=ads-sandbox-ipc`,
`azp=ads-sandbox-manager`, and a UUID subject. It never binds the security holder.
Every invalid JWT produces a redacted warning and no business action; the consumed
record position still advances.

Every acknowledge/result/shutdown-ack/ping reply mints fresh STE to
`ads-sandbox-manager` at publication time. Result STE uses the ack-reply JWT held in
memory. Ready/error use verified client-credentials JWTs with UUID subjects, not
STE and not a verifier bypass. Short ack-reply TTL warns and does not reject exec.
No refresh chain or token cache is added.

The Kubernetes adapter uses only in-cluster projected ServiceAccount credentials,
verified TLS, and the pinned Kubernetes client's projected-token refresh hook.
It rechecks the target pod UID, sandbox label, and container before every exec.
This is defense in depth, not a replacement for the planned admission boundary.
Kubernetes API transport uses the SDK for pod reads and bounded asyncio WebSocket
channels for exec, avoiding a blocking stream loop or unbounded SDK output capture.

## Configuration

All variables have prefix `ADS_SANDBOX_IPC_`. Required:

- `SANDBOX_ID`: UUID.
- `PID_DIRECTORY`: writable IPC PVC mount directory.
- `KAFKA_BOOTSTRAP_SERVERS`.
- `KEYCLOAK_WELL_KNOWN_URL`, `KEYCLOAK_ISSUER`, `KEYCLOAK_CLIENT_SECRET`.
- `TLS_CERT_PATH`, `TLS_KEY_PATH`.

Optional:

| Suffix | Default |
| --- | --- |
| `NAMESPACE` | `ads-sandbox` |
| `TLS_CA_BUNDLE` | absent |
| `BIND_HOST` | `0.0.0.0` |
| `PORT` | `8080` |
| `STARTUP_SECONDS` | `120` |
| `TIMEOUT_SECONDS` | `120` |
| `ACK_SECONDS` | `10` |
| `POLL_SECONDS` | `0.1` |
| `CONTROL_SECONDS` | `10` |
| `STDOUT_BYTES` | `65536` |
| `STDERR_BYTES` | `65536` |
| `INPUT_BYTES` | `262144` |

TLS cert/key/optional CA are loaded on the main thread before startup. The only
HTTP endpoints are unauthenticated HTTPS `/health/live` and `/health/ready`.
Ready is a latch and deliberately does not probe the guest after startup.

## Proof boundary

`nox -s lint deps typecheck test package` includes this workspace service.
Tests use fake Kafka and fake Kubernetes, real JWT signature validation, and
temporary filesystem PID storage. CI additionally lints/builds/import-smokes the
service image; it does not publish it.

No lab deployment, STE clients, Kafka ACLs/SASL provisioning, RBAC/admission,
manager transit, Helm values, or Kata end-to-end proof belongs to this slice.
The real guest/Podman process-tree and stream behavior still require the planned
handshake E2E slice; fake-based proof does not claim those integrations are proven.
