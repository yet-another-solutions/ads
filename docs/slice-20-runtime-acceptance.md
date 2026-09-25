# Slice 20 runtime implementation evidence

Scope: runtime and complete data plane only. Slice 21 transport/lab proof and
slice 22 live acceptance are excluded. No merge, tag, publication, deployment,
reset or shared infrastructure change is authorized. This is an implementation
map, not a second canonical tracker or a completion claim.

Baseline: `18f5dc4795e31b87a7a996bb799ac3e996418c87`.
Branch: `feature/slice-20-egress-runtime`.

## Requirement and proof map

| Obligation | Owning code / planned proof | Evidence state |
| --- | --- | --- |
| Immutable snapshot, process UUID, authenticated apply | Existing configuration/control; receiver tests | Existing component regression passed; production health integration open |
| Complete ordered policy, names, absent identity, paths, transitions | `policy.py`, `test_policy.py` | Component tested; no production request handler yet |
| Mandatory address classification and trusted infrastructure inventory | `destinations.py`, `test_destinations.py` | Component tested; manager provisioning still open |
| Connection-local TTL evidence, shared misses, no stale fallback | `membership.py`, asynchronous destination tests | Cache component tested; real evidence adapter still open |
| Strict HTTP framing and trailers | `framing.py`, `http1.py`; raw headers/chunks, pipeline, real RST tests | HTTP/1 component tested; full two-leg orchestration and HTTP/2 open |
| Disposable NGINX normalization and real protocol adapters | `normalization.py`, installed NGINX/Lua socket tests | HTTP/1 helper tested; HTTP/2/extended CONNECT adapter open |
| HTTP/1.1 and HTTP/2 streaming, resets, upgrades and ALPN | HTTP/1 event channel only | Full handlers, HTTP/2, WebSocket, h2c and ALPN preservation open |
| DNS traversal, all-endpoint inspection, budgets and UDP/TCP | `resolution.py`, `dns_transport.py`; real sockets and explicit external view fixture | Acquisition and transport tested; complete relationship evidence/view integration open |
| Synthetic DNSSEC, flags, defects and independent validation | DNSSEC; independent validators | Open |
| ECH termination, durable publication and retained keys | `identity_store.py` implements storage primitives; no ECH adapter | Encrypted/authenticated persistence tested; ECH termination/publication open |
| TLS certificate pairs and defect mirroring | TLS inspection; real validation clients | Open |
| State custody, block mounts, startup/teardown and health | Local SQLite owner/integrity tests, not block-device custody | VM/bootstrap/fencing/enforcement integration open |
| Entrypoint and source-only packaging integration | Runtime and Containerfile/workflow definitions | Open |
| Full local regression and review | Nox lint/deps/typecheck/test/package | Five local gates pass for component increment; full run 4,585 passed, two skipped, four subtests passed |

## Component verification and review

Final focused local Nox selection: **208 passed, zero skips**, 5.20 seconds.
Local Nox lint, deps, typecheck and package passed. The package gate builds the
existing Python packages only; no project image, native binary, rootfs or chart
was built. No CI was initiated or treated as this branch's evidence.

The full local regression passed **4,585 tests and four subtests**, with
**two skips**, 2,088 warnings, in 1,822.76 seconds (Nox session: 32 minutes).
It was launched before later source additions/tests and cannot be described
as an exact-final-head collection of every new test. The final 208-test
component selection additionally passed under Python 3.12.13 in 13.36 seconds.

The skips are the existing Docker-gated Keycloak tests
`test_keycloak_login_shows_the_threadline_shell` and
`test_published_realm_sample_import_and_identity`. No Docker executable is
installed. Rootless Podman supplied PostgreSQL through supported fixture URL
overrides, not a fake Docker command or a weakened Keycloak test gate.

Disposable PostgreSQL removal and isolated VFS `system reset --force` succeeded.
The test driver's final assertion incorrectly required the empty VFS directory
itself to disappear; manual inspection verified no layers, containers, image
metadata, volumes, helper processes or test listeners. The remaining 88 KiB
runtime/lock skeleton and temporary Python 3.12 environment were removed.
Cleanup is verified, not inferred from the reset exit code.

Real boundary tests cover installed NGINX/Lua, TCP RST without an HTTP response,
chunk/trailer wire parsing, duplicate-length pipelining, UDP-to-TCP DNS retry,
UDP truncation, whole-TCP denial, shared UDP/TCP admission, frame/queue deadlines,
shutdown cancellation and encrypted file-backed SQLite recovery.

Named external fakes remain: the DNS synthetic-view provider, selected
upstream acquisition fixtures, and the connection evidence resolver.
They do not prove DNSSEC, ECH, signed answer synthesis or full destination
relationship construction. `DNSTransport` requires an explicit synthetic-view
dependency and has no raw-acquisition forwarding default.

Review fixes retained as tests:

- One path-matching work budget per request, not per pattern; invalid normalized
  paths cannot pass a rule with an empty path list.
- Inspect raw chunk lines/trailers before h11 normalizes them.
- Keep DNS owner syntax separate from HTTP authorities; service labels work.
- Do not count an answer from the wrong address family as queried membership.
- Explicitly set TC when UDP output exceeds the selected payload; never truncate
  an oversized TCP response into apparent success.
- Idempotent reset on already-closed sockets, exact admission accounting even
  when tasks are cancelled before starting, and abort active clients before
  awaiting asyncio server closure.
- Bind public configurations to encrypted private keys, authenticate the whole
  persistent row inventory including dependency/retention metadata, and encode
  SQLite URI paths rather than interpreting path punctuation as URI options.

Persistence does not establish manager/VM ownership. Its local flock excludes
cooperating writers on the mounted filesystem; an authenticated inventory
detects altered/deleted records but cannot detect whole-volume rollback to an
older authentic snapshot. External custody/fencing remains mandatory.

## Feasibility observations

The initial Computer interpreter is Python 3.14.3 linked to OpenSSL 3.5.5.
Its `ssl.SSLContext` has no ECH API. This is a concrete observation about the
available interpreter, not a claim that ECH cannot be implemented.
[OpenSSL's ECH design](https://github.com/openssl/openssl/blob/master/doc/designs/ech-api.md)
documents OpenSSL 4.0 ECH; selecting and proving a Python-compatible server
binding remains required. Ordinary TLS, GREASE or rejection is not ECH proof.

An isolated inspection of pyOpenSSL 26.4.0 with cryptography 50.0.1 reported
bundled OpenSSL 4.0.2 but no exposed ECH or ClientHello callback APIs.
Its native extension did not export the ECH functions as usable dynamic
symbols. No private-symbol/address manipulation was attempted. The configured
system package repositories offer OpenSSL 3.5.5. A selected, tested Python
server adapter with pre-handshake inner-name/ALPN inspection and actual ECH
client interoperability is still missing.

An actual `nft list ruleset` inside a fresh privileged local network namespace
failed with `Unable to initialize Netlink socket: Protocol not supported`,
exit 3. Installing nftables/iproute2 did not supply NETLINK_NETFILTER.
No host kernel/security/device changes were made. This is a specific future
kernel-smoke CI fallback candidate, not permission to move runnable tests to CI.

Installed NGINX's HTTP/1 parser rejected the attempted literal CONNECT/path
normalization request. This is not proof about its native HTTP/2 extended
CONNECT behavior. A real protocol adapter is still required; changing CONNECT
to GET or passing raw paths is not an acceptable fallback.

Current CI triggers are pull requests and pushes to main/master; feature-only
preservation without a PR does not trigger that workflow. Inspect all workflows
again before a push. No CI fallback is yet justified or initiated.

PR #135 is unrelated publication-timeout work and must not be folded into this
branch. The latest read-only recheck found it open, unmerged, auto-merge off.
Its [inherited CI succeeded](https://github.com/yet-another-solutions/ads/actions/runs/36116839268);
the [v0.0.35 publication was cancelled](https://github.com/yet-another-solutions/ads/actions/runs/36116011091).
Neither was retried or merged. Their results are not this branch's proof.

## Exact remaining integration work

The slice is **open**, not a runnable egress deployment. No `__main__.py`,
runtime image definition, transparent interception, production enforcement
health, HTTP/2 handler, WebSocket/h2c handler, two-leg TLS certificate substitution,
DNSSEC validator/synthetic signer or ECH terminator is claimed.

Before assembly, resolve the Python-compatible ECH server capability and its
non-publishing proof path without unauthorized local native/project builds.
Independently finish service-target/port/TTL evidence construction and DNSSEC
classification/synthesis; wire these into the mandatory view/evidence interfaces,
then complete handlers, bootstrap/custody and real health. Trusted resolver
inventory and unambiguous new-versus-retained state authority are not currently
delivered by the manager environment and require narrowly scoped provisioning.

Slice 21 remains responsible for transport/manager lab proof. Slice 22 remains
responsible for live acceptance. Neither has started here. Final merge,
publication, deployment and auto-merge remain outside current authorization.
