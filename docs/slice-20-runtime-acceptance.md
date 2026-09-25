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
| Complete ordered policy, names, absent identity, paths, transitions | `policy.py`, `request_authorization.py`, request-owner tests | Ordinary request owners tested; absent-authority helper compatibility and transition owners open |
| Mandatory address classification and trusted infrastructure inventory | `destinations.py`, `test_destinations.py` | Component tested; manager provisioning still open |
| Connection-local TTL evidence, shared misses, no stale fallback | `membership.py`, asynchronous destination tests | Cache component tested; real evidence adapter still open |
| Strict HTTP framing and trailers | `framing.py`, `http1.py`, `http2.py`, two-leg owners; raw framing and real sockets | Ordinary streaming owners tested; complete transition/bootstrap integration open |
| Disposable NGINX normalization and real protocol adapters | `normalization.py`, installed NGINX/Lua socket tests | HTTP/1 and ordinary HTTP/2 adapters tested; empty Host, asterisk and extended CONNECT compatibility open |
| HTTP/1.1 and HTTP/2 streaming, resets, upgrades and ALPN | `http1_proxy.py`, `http2_proxy.py`, `websocket.py`, `h2c.py`, native TLS integration | Ordinary request owners, HTTP/1 WebSocket, h2c and real ECH/H2 integration tested; H2 WebSocket and graceful GOAWAY open |
| DNS traversal, all-endpoint inspection, budgets and UDP/TCP | `resolution.py`, `dns_transport.py`; real sockets and explicit external view fixture | Acquisition and transport tested; complete relationship evidence/view integration open |
| Synthetic DNSSEC, flags, defects and independent validation | DNSSEC; independent validators | Open |
| ECH termination, durable publication and retained keys | `tls.py`, `tls_transport.py`, identity store and actual native clients | Production transport component implemented; DNS publication/key lifecycle integration remains open |
| TLS certificate pairs and defect mirroring | `origin_tls.py`, `certificates.py`, `certificate_mirror.py`, `crl.py`, `crl_http.py`; real validators/sockets/TLS clients | Stable success pairs, selected defects and durable local CRL component tested; remaining status/combinations and runtime ownership open |
| State custody, block mounts, startup/teardown and health | Local SQLite owner/integrity tests, not block-device custody | VM/bootstrap/fencing/enforcement integration open |
| Entrypoint and source-only packaging integration | Runtime and Containerfile/workflow definitions | Open |
| Full local regression and review | Nox lint/deps/typecheck/test/package | Five local gates pass for component increment; full run 4,585 passed, two skipped, four subtests passed |

## Component verification and review

### h2c transition ownership

The HTTP/1 owner now authorizes h2c as an initial HTTP/1 transition, completes
the original upload and validates the genuine origin 101 before transferring
both legs to the H2 owner. Stream 1 receives the original request's response;
no request headers/body are replayed. The frontend applies the client's
HTTP2-Settings while the origin advertises the proxy's own settings. Original
method, target and request content are preserved. Parser leftovers are handed
off once through bounded prefixed readers, including coalesced origin
101/SETTINGS/response bytes.

Every later stream uses the ordinary H2 authorization path and independent
stream-ID mapping. Denied upgrade requests never open an origin; an origin
rejection remains HTTP. Actual stock h2 endpoint tests cover GET, HEAD,
uploaded POST, separate settings, initial response, later isolated denial,
policy updates, malformed settings and malformed 101. A forced scheduling
regression proves an ordinary origin opened while frontend startup yields
cannot be mistaken for an adopted h2c origin or initialized twice.

All five local Nox gates pass: **795 affected tests, zero skips**, 26.99 seconds,
`slice20-h2c-reviewed-nox.log`. This includes concrete NGINX compatibility
probes for path-form CONNECT and OPTIONS asterisk: they currently reject, and
are explicitly blockers rather than passing support. The earlier real empty
Host probe remains a blocker too. A helper-only method adapter requires an
explicit contract decision; no silent CONNECT-to-GET rewrite was added.

No full-workspace rerun, CI, image/rootfs/native/chart build, merge,
publication or lab operation. The complete slice remains open: H2 WebSocket,
graceful GOAWAY, helper compatibility, DNSSEC/ECH publication, remaining status
and certificate integration, executable bootstrap, enforcement, custody,
real health and source-only packaging still need implementation/proof.

### HTTP/1.1 WebSocket session ownership

The dedicated transition validates the GET/version/key/upgrade handshake,
forbids request bodies and unsafe connection nominations, and applies the
initial HTTP/1 rule's upgrade permission before any upstream bytes. A valid
origin 101 must contain the matching Accept digest and only offered
subprotocol/extension names. Syntax and singleton rules are checked before
switching; unsupported extension-specific parameter semantics remain with the
endpoints because ADS neither decodes nor transforms their frames. See
[RFC 6455 opening handshake and intermediary requirements](https://www.rfc-editor.org/rfc/rfc6455.html).

The bounded duplex handler retains the same original endpoints and preserves
masked frames, fragmentation, negotiated compression and payload bytes.
There is no message-content policy inspection, decompression, refragmentation,
generic CONNECT fallback or new-destination capability. Successful activity in
either direction renews idle time; stalled writes and complete inactivity
remain bounded. A parser handoff consumes leftovers exactly once and prevents
re-entry into HTTP parsing. Origin rejection/redirect remains HTTP and never
enters upgraded mode; later HTTP requests are independently authorized.

Independent websockets 17.1 endpoints prove negotiated compression,
fragmentation, ping/pong, close, coalesced 101/frame input, a one-megabyte
message and active-session survival across a policy update. Additional
regressions cover invalid requests before origin contact, malformed origin
101 without response leakage, forbidden upgrades, redirects, idle reset,
one-direction activity, and one-time parser custody transfer.

All five local Nox gates pass: **781 affected tests, zero skips**, 26.28 seconds,
`slice20-websocket-nox.log`. Earlier focused collection found an extension
regex error and a changed test-client enum API; both were corrected before
the successful full gate rerun. No CI, full-workspace rerun, project image
build, publication or lab action. HTTP/2 WebSocket normalization/ownership,
h2c transition, graceful GOAWAY and the remaining slice obligations stay open.

### Multiplexed two-leg owner and real ECH integration

`HTTP2Proxy` composes the strict codec with per-request authorization, separate
frontend/origin stream-ID maps, bounded per-stream queues, flow-controlled
duplex forwarding and explicit stream custody. Denied requests emit no upstream
HTTP bytes. Cancellation, authorization timeout, malformed responses and queue
floods reset only the paired stream and return discarded DATA credit. Completed
responses parsed before an origin EOF remain usable; truncated ones are reset.
New requests never reconnect through an uninspected TLS session.

Tests use stock h2 clients/origins over real sockets and real NGINX. Coverage
includes a one-megabyte upload, policy changes during a held response, isolated
frontend/origin resets, early finals, duplex response headers, cancellation
before the task starts, queue floods, pending authorization with early body,
and separate stream-ID spaces. The EOF test identifies requests by path rather
than assuming concurrent helper completion preserves frontend stream order.

A native OpenSSL ECH client also exercises actual frontend TLS, decrypted inner
SNI and ordered ALPN offers, actual origin TLS, durable certificate substitution,
NGINX, policy and the H2 owner. The owner adopts the exact origin session used
for inspection; the denied first stream sends no origin request. A continuous
download outlasting the TLS read-idle interval proves successful output renews
idle activity without weakening separate handshake/header/stream deadlines.
Only socket admission/original-destination binding and DNS acquisition are
named external fixtures; this is not a kernel, bootstrap or lab proof.

Review fixed empty END_STREAM serialization with a negative flow window after
SETTINGS reduction, without granting data credit. Regression preserves the
native state machine and uses its dedicated end-stream API.

All five local Nox gates pass: **754 affected tests, zero skips**, 23.97 seconds,
`slice20-h2-owner-nox.log`. No CI or full-workspace rerun at this milestone.
Graceful GOAWAY/draining, h2c, WebSockets, helper compatibility cases and the
remaining runtime/DNSSEC/custody obligations remain open. A reset for one of
those unsupported cases is not evidence that the feature is implemented.

### Request authorization and two-leg HTTP/1 owner

`RequestAuthorizer` composes the shared PolicyStore, original destination,
TLS/HTTP authority agreement, connection-owned DNS membership, real NGINX
normalization and final current-revision policy decision. The normalized path
is only for matching; original target/authority/query remain unchanged.
DNS evidence is acquired after the potentially slow helper, immediately before
the final no-await policy decision. Pending requests do not retain an older
allowance across a policy update. IP literals do not fabricate DNS identities,
and bogus/indeterminate DNSSEC status alone is not an extra proxy prohibition.

`HTTP1Proxy` authorizes each request before opening a plaintext upstream
connection or writing application bytes on a prepared inspected TLS leg.
The connector receives only the immutable original destination; it remains an
explicit external boundary, not a claim of completed kernel/interface binding.
The owner relays interim/final responses, streams bodies/trailers under
backpressure, reauthorizes keep-alive/pipelined requests and never follows
redirects. Denial, framing errors and cancellation reset both owned legs.
Genuine early-final responses are relayed without fabricating 100 or draining
an unwanted upload. Ordinary duplex uploads continue after response headers;
early termination happens on completed response or final-before-100, not on
every status header. Active authorized responses survive policy updates.

Real NGINX plus two socket legs prove named-request authorization/forwarding,
original target preservation, zero upstream contact on denial, chunked bodies
and trailers, 100-continue, early final, duplex upload, policy/revision behavior,
failed membership refresh, redirects and malformed upstream responses.
Only socket admission/connector and resolver acquisition are fixture boundaries.
No production TLS/kernel/bootstrap integration is claimed by these plain-socket
tests; existing TLS tests remain separate.

All five local Nox gates pass: **740 affected tests, zero skips**, 22.92 seconds,
`slice20-http1-owner-nox.log`, including 28 new owner/authorization cases.
No full workspace rerun or CI.

Known incomplete cases are explicit: the current NGINX helper rejects legally
empty Host, so absence is not repaired with an invented name or raw-path
fallback. Extended WebSocket CONNECT normalization, full Upgrade owners and
server-wide asterisk-target normalization still require implementation.
HTTP/2 ordinary request-to-helper adaptation is tested, but its multiplexed
two-leg owner is the next step. Slice 20 remains open.

### HTTP/2 framing and stream isolation

`HTTP2Connection` uses exactly pinned h2 4.4.1, hpack 4.2.0 and hyperframe 6.1.0.
The dependency audit found that h2's public receive API terminates a connection
for several HTTP message errors, including malformed content lengths. A narrow
version-guarded adapter therefore changes the header/DATA dispatch hooks while
retaining the library's frame parser, HPACK state, SETTINGS, flow windows and
serialization. This uses identified private h2 hooks and state transitions,
not a promise of a stable public API; dependency upgrades deliberately fail
until that compatibility boundary is reviewed and retested. See the
[h2 API and protocol errors](https://python-hyper.org/projects/hyper-h2/en/latest/api.html).

ADS checks raw decoded fields without normalization hiding duplicate lengths.
Malformed requests/responses/trailers reset their stream before invalid events
are returned. HPACK is still consumed on reset streams; in-flight cancelled
DATA preserves connection credit. Compression/frame failures remain
connection-wide. Policy denial uses standard CANCEL, no synthetic status/body.
Actual socket tests prove another stream completes after denial.

The profile covers pseudo-header order/duplicates/role, unsupported CONNECT,
Host/authority agreement, content lengths, header/count limits, HEAD/204/304,
bounded informational responses, safe trailers and late truncation. DATA reads
and writes are at most 16 KiB; consumer acknowledgment controls receive credit,
and send-window retries cannot double-count content. Initial per-stream and
connection windows bound unconsumed data; maximum concurrent streams is bounded.
Sensitive credential/cookie fields are serialized using never-indexed HPACK,
not inserted into the shared dynamic table.

An explicitly authorized h2c owner can seed completed stream 1 on either leg,
including HEAD semantics and bounded validated HTTP2-Settings. Later streams
remain independent events. Extended WebSocket CONNECT parsing requires its
negotiated setting and the exact supported protocol; parsing is NOT permission
and no WebSocket session/tunnel is implemented by this codec.

All five local Nox gates pass: **712 affected tests, zero skips**, 21.83 seconds,
`slice20-http2-nox.log`, including 54 HTTP/2 cases. Focused type errors found
during implementation were corrected before this complete gate run. No full
workspace rerun, CI, image/native build or lab acceptance. Source review covered
private-hook scope, compression continuity, invalid-event suppression, DATA
credit, metadata cleanup, h2c HEAD and never-indexed credential serialization.

Still open: socket/task/deadline owner, per-request policy/destination/helper
integration, two-leg stream mapping/forwarding/cancellation, full h2c HTTP/1
transition and WebSocket handler. The component is not the complete data plane.

### Durable local CRLs and certificate constraints

`CRLRepository` signs only with explicitly supplied egress-owned authorities.
Issuer-scoped, monotonically numbered CRLs are authenticated and committed
before wire publication. Refresh retains all revoked serials; expiry cannot
reset the number or forget revocations. Superseded generations are removed only
after expiration, and the head remains even when expired. Reclaimed SQLite
pages are reusable without relaxing the physical or logical capacity limits.
Public parent/root CRLs are separate inputs, never manufactured with copied
parent private keys. DNS/ECH publication dependencies are unchanged.

`LocalCRLService` accepts a bootstrap-supplied specific private listener and
only the paired sandbox source. It serves bounded GET/HEAD for the exact
literal Host and `/crl/<issuer fingerprint>.der`, with signed DER and bounded
cache lifetime. Unknown/stale publications, invalid paths/headers/body and
capacity overflow reset without an HTTP response. Internal persistent/database
faults latch its health false; shutdown resets live clients and drains tasks.
This is not an arbitrary private-address exception or a proxy. Interface
binding, routing and full readiness remain bootstrap integration obligations.

The composer now preserves leaf/intermediate revocation, including combined
expiry/name failures, with publication before candidate acceptance. Real
CA-Job hierarchy tests require the public signing-chain CRLs and prove that
missing issuer CRLs cannot be concealed. Independent installed OpenSSL and a
CRL-aware TLS client reject the fetched revoked substitution. Tests explicitly
load the fetched CRL: automatic fetching by arbitrary clients is NOT claimed.

Additional native-observed cases cover CA/basic-constraints, CA/leaf key usage,
missing CA key usage and path-length errors. Path-length failure is compared
as an error class because the added local hierarchy may report it at additional
depths; other non-trust conditions retain exact error depth. The minted
path_length=0 remains unchanged. Review found that OpenSSL 4 accepts a
noncritical CA basic-constraints extension which OpenSSL 3 strict mode rejects.
Origin and candidate verification therefore retain an explicit built-chain
compatibility finding, and the mirror preserves that field. Tests demonstrate
both validators' actual behavior rather than claiming identical diagnostics.
See the [OpenSSL 4 verification profile](https://docs.openssl.org/4.0/man1/openssl-verification-options/).

All five local Nox gates pass: lint, deps, typecheck, test and Python package.
Affected egress/CA/commons/bootstrap selection: **658 passed, zero skips**,
20.93 seconds, `slice20-crl-reviewed-nox.log`. The first gate attempt passed
643 tests but found a reused-variable type error; it was corrected and all
five gates rerun. The latest selection includes real origin TLS compatibility,
CRL source/capacity/shutdown/reset, database-failure redaction, durable refresh,
bounded-store reuse and authenticated corruption regressions.

Open: upstream CRL/OCSP acquisition and stapling, remaining defect combinations,
stable-pair revocation propagation, refresh scheduling and readiness ownership,
and complete runtime integration. No full workspace rerun, CI, merge,
publication or lab proof is claimed. Slice 20 remains open.

### Non-revocation certificate mirroring

`CertificateMirror` now composes replacements for observed leaf expiry/future,
hostname mismatch, EKU, unsupported critical extension, invalid certificate
signature, unknown issuer and incomplete path; it also composes intermediate
time defects using self-issued, differently-keyed bridges. The minted CA's
path_length=0 is unchanged. The independent process-local unknown issuer is
supplied by the owner, checked for matching key/expiry and never persisted.
Successful observations must use stable pairs rather than this ephemeral path.

Before returning a certificate, native verification must reproduce all expected
error codes/depths. Self-signed trust failures and incomplete-issuer failures
are separate classes; neither can substitute for the other.
Missing/extra errors reject the candidate, never return a clean replacement.
At that checkpoint incomplete supported mappings, including revocation,
constraints/path length, key usage and stapled status, remained explicit exceptions,
not relabelled as genuinely unmappable to claim success.

Tests use actual native certificate observations, independent OpenSSL CLI checks,
and real stdlib-client/native-server handshakes for expiry, hostname and invalid
issuer signature. Simultaneous expiry/name failures are retained.
No production origin/DNS/policy coordinator or full mirroring coverage is claimed.

Review discovered different OpenSSL 3/4 handling of self-issued bridges carrying
only an authority key ID. Supplying the correct authority certificate issuer and
serial as well as the key ID makes both validators reproduce only the intended
intermediate time failure. This changes no minted CA or trust setting.
The certificate-level authority binding is applied to mirror construction;
successful retained pairs keep their existing key-bound identity behavior.

All five reviewed local Nox sessions passed. Affected egress/CA/commons/bootstrap
selection: **620 passed, zero skips**, 13.41 seconds, including 21 mirror tests.
The mirrored intermediate cases also pass under actual CA-Job minted/full-chain
trust. The full workspace suite has not been rerun at this increment.
No CI, merge, publication, lab operation or later slice was started.

### Approved full signing-chain trust

The user approved sandbox trust of the complete configured signing hierarchy
on 2026-09-25 at 16:05 MSK, instead of the proposed same-key self-signed view.
The CA-Job output/key/expiry remain unchanged. `load_public` now validates the
existing ordered chain through its root and exports it with the minted CA.
Private keys and the unrelated egress-only extra bundle remain excluded.
This deliberately broadens sandbox trust to that configured root hierarchy.

Bootstrap streams this validated bundle into the rootless sandbox, where a
base-owned Python installer creates one `.crt` per certificate and refreshes
both CAfile and CApath representations. It removes only old ADS-owned entries.
Failed validation or installation cannot reach readiness.

Local proof uses actual CA-Job mint/output, shared loader, production pair
generation and the real installer with isolated update-ca-certificates paths.
Independent installed OpenSSL verifies via BOTH the generated bundle and hash
directory without partial-chain mode; native OpenSSL 4 verifies the same chain.
With issuer CRLs supplied, full-chain revocation verification passes. Missing
issuer CRLs still fail and a revoked egress CA is still detected at depth 1.
Issuer CRLs are fixture inputs here, not a claim of production acquisition.
No host trust store, deployed CA, lab resource or publication changed.

All five local Nox gates passed: lint, deps, typecheck, test and package.
The affected egress, CA, commons and bootstrap selection passed **599 tests,
zero skips**, 12.72 seconds. Shell syntax passed. Full workspace regression
has not been rerun at this increment. The old minted-only negative and
self-signed-candidate proof remain regression tests, not the selected solution.
Review confirmed the installer runs only inside rootless `podman exec`, leaves
baseline files intact, fails startup on update errors and receives no private
material. No CI fallback was necessary for these gates.

### Earlier minted-anchor compatibility decision

`certificate_validation.py` supplies bounded native candidate-chain verification
with only the supplied minted trust anchor, not origin extra trust. It reports
all collected validation defects rather than treating a permissive observation
callback as successful validation.

Testing the actual CA-Job `mint()` output exposed a compatibility gap:

- Installed OpenSSL verification with only the intermediate-signed minted CA
  as its trust file fails at that CA with `unable to get issuer certificate`.
- Explicit partial-chain trust allows the leaf, but CRL checking across the
  chain reports missing issuer CRL at the intermediate-signed anchor.
- A candidate self-signed public trust certificate using the SAME minted
  egress key, subject, validity and path_length=0 passes ordinary and full-chain
  CRL checks in the independent installed OpenSSL validator and the OpenSSL 4
  native candidate validator. The original parent-signed certificate remains
  intact and still verifies under its parent.

The self-signed candidate is retained only as a historical regression proof in
`test_minted_anchor.py`, not a production CA output change.
Adoption was superseded by the full-chain trust approval above.
The reset-only unmappable-outcome approval is unrelated
and remains valid; it is not permission to conceal this valid-chain gap.

All five local Nox sessions passed after adding these checks: **299 egress
tests passed, zero skips**, 11.08 seconds. No full workspace rerun or CI.

### Stable success pairs and approved unmappable outcomes

The user approved reset-only handling for genuinely unmappable upstream TLS
failures on 2026-09-25. `UnmappableTLS` accepts only fixed reason enum values.
Actual origin handshake failures are classified separately from local invalid
configuration; frontend termination emits a TCP reset without an HTTP response
or clean/generic-untrusted certificate fallback. Its warning contains only the
fixed bounded reason, with no raw exception text, traceback or private material.
Real socket tests verify reset, no response/repair, and cleanup. Supported
certificate defects still require the dedicated mirroring path.

`CertificatePairs` now persists successful certificate/private-key mappings in
the authenticated encrypted identity store. The mapping includes original
IP/port, effective TLS name, full upstream leaf fingerprint and minted signer
fingerprint. A/B/A returns the original A substitution, including after store
recovery. Current origin validation precedes every lookup; a newly revoked or
otherwise defective observation cannot receive its retained clean pair.
Missing, corrupt and retired mappings have distinct outcomes. Interrupted
prepared/published generations complete without changing the certificate/key.
Changed CRL locators, signer/key mismatch and expired material fail closed.
No replacement root or silent quota-driven eviction is introduced.

The actual ECH two-leg test now uses this production pair service: it verifies
the original origin certificate, durably generates the substitution, completes
client TLS under a different explicitly trusted fixture CA, and exchanges data.
Request authorization and the original-destination network boundary remain
explicit fixture boundaries. CRL URLs are present in substituted certificates,
but the local CRL publication/listener is not yet implemented.

Independent installed OpenSSL validation proves a self-issued, differently-keyed
synthetic intermediate can retain the existing CA's path_length=0 and still
express expired/future intermediate errors without adding a path-length error.
This is consistent with RFC 5280 sections 4.2.1.9 and 6.1.4, which count
non-self-issued intermediates: https://www.rfc-editor.org/rfc/rfc5280 .
The production intermediate-defect composer is not yet implemented; this proof
does not relax the minted CA contract or change shared PKI.

All five local Nox gates passed for this increment. Egress selection:
**296 passed, zero skips**, 10.68 seconds. Full workspace and local-client trust
installation compatibility are not claimed by the component run. No CI,
merge, publication, local project-image/native/chart build or later slice work.

### TLS transport increment

The runtime now has a public-ABI OpenSSL 4.0.2 TLS engine and async socket
owner, not only the earlier test probe. Exact runtime CFFI pin: 2.1.1.
Private ECH keys are generated and loaded entirely in memory, with an
authenticated public/private mapping in the existing encrypted identity store.
Prepared keys cannot be served; published/active/retiring keys can be recovered.
No temporary private-key files or CPython/private-library pointers are used.

The engine exposes decrypted SNI and opaque ordered ALPN, pauses before server
certificate selection, then installs an explicitly supplied certificate/key
and actual-origin ALPN result. Its bounded transport includes an absolute
handshake deadline, bounded input/output/plaintext queues, connection admission,
idle deadlines, cancellation cleanup and real reset-only abort. Normal owner
completion separately emits close_notify. Context replacement prevents new
sessions without freeing callbacks still owned by in-flight sessions.
Tickets, resumption, early data and renegotiation cannot bypass inspection.

Actual native ECH clients exercised ECH/plain/GREASE/foreign configurations
and h2/http/1.1/absent ALPN selection. A separate stdlib/OpenSSL 3 client tested
TLS 1.2 and 1.3, ALPN absence, application records and close_notify. This does
not prove HTTP/2 framing, browser interoperability, certificate substitution,
foreign-configuration retry compatibility or end-to-end production readiness.
The certificate/origin-result coordinator is an explicitly named external
fixture in the first transport tests. A further actual two-leg test now uses
`origin_tls.py` to establish and verify a separate origin TLS connection, carry
the decrypted SNI and unchanged ALPN offers there, and feed its actual selected
ALPN back into frontend resume. Both TLS legs carry real application records.
At that earlier milestone, certificate substitution and request authorization
were explicit fixture boundaries. The successful-substitution boundary is
removed by the subsequent pair increment described above.

`origin_tls.py` retains the presented and built chains plus per-certificate
validation findings. Its observation callback continues a defective handshake
only to acquire the chain on that same connection; `OriginCertificate.verified`
is false for every retained issue. No application request is generated by
inspection. Tests distinguish valid, expired, future, mismatched hostname,
unknown issuer, invalid certificate signature, invalid EKU, unsupported critical
extension, revoked and unavailable-CRL outcomes under all three ALPN results.
No client credentials are installed at origin. Extra trust is egress-only.
CRL acquisition and synthetic local CRL distribution remain separate open work.

All five local Nox sessions passed for this increment. Egress selection:
**244 passed, zero skips**, 9.53 seconds. The full workspace regression has not
been rerun on this increment. No CI, native/image/chart build, publication,
merge, deployment or slice 21/22 work was performed.

Review fixed listener teardown ordering so a live peer is aborted before
awaiting server closure, and added a cumulative handshake-input limit in
addition to pending-BIO bounds. After that review fix, the 244-test egress
selection passed again in 9.64 seconds. Origin inspection subsequently added
34 passing real validation/two-leg tests. A final review added three
authenticated-outer/unknown-key ECH cases. The client receives a trusted
certificate valid for its outer name, but the native protocol still aborts
with `ech required` before application exchange. This is distinct from the
fixture's earlier explicit foreign-key rejection and does not establish
automatic retry or browser compatibility. Test fixture representations redact
private key material, including when pytest reports an assertion failure.

Final combined local Nox evidence: all five sessions passed; **281 egress tests
passed, zero skips**, 10.31 seconds. The 62 TLS tests present before the final
three review cases also passed on Python 3.12.13 in 1.73 seconds. No full
workspace rerun or CI run was performed on this increment.

The initially unapproved outcome for genuinely unmappable TLS failures was
subsequently approved and implemented as described above. That approval does
not convert an unimplemented supported defect into an unmappable case.

### Earlier component verification

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

Follow-up: the user asked to solve the Python ECH problem first. A public-ABI
CFFI binding to isolated, verified prebuilt OpenSSL 4.0.2 libraries now proves
genuine ECH, inner ClientHello access, pause/resume around a real upstream TLS
connection, ALPN preservation and late certificate installation locally.
Eight native capability tests and the 216-test focused egress suite passed;
all five Nox gates passed. See [Python ECH proof](slice-20-ech-python-proof.md).
No CI exception or local native build was needed. The initial observations
below about standard wrapper methods remain true, but their implied blocker
is superseded by this demonstrated route.

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
system package repositories offer OpenSSL 3.5.5. A separate signed-package
download/extraction subsequently supplied OpenSSL 4.0.2 for the Python CFFI
proof, without changing those system packages.

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

The Python-compatible ECH server capability is proved; next turn the tested
public-ABI sequence into the bounded production TLS adapter.
Independently finish service-target/port/TTL evidence construction and DNSSEC
classification/synthesis; wire these into the mandatory view/evidence interfaces,
then complete handlers, bootstrap/custody and real health. Trusted resolver
inventory and unambiguous new-versus-retained state authority are not currently
delivered by the manager environment and require narrowly scoped provisioning.

Slice 21 remains responsible for transport/manager lab proof. Slice 22 remains
responsible for live acceptance. Neither has started here. Final merge,
publication, deployment and auto-merge remain outside current authorization.
