# Python ECH capability proof

Date: 2026-09-25. Scope: resolve the Python ECH interface prerequisite, not
complete slice 20 or start transport/lab acceptance.

## Result

**The required Python-controlled ECH sequence works locally.** Use a small
ADS-owned CFFI binding to public APIs in an explicitly loaded OpenSSL 4 shared
library. A CPython fork, pyOpenSSL private-symbol access, TLS sidecar or change
of implementation language is not necessary for the demonstrated capability.

The initial conclusion that the installed standard wrappers required a CI
capability prototype was too broad. Their missing methods are real, but
verified prebuilt OpenSSL 4 libraries plus CFFI ABI mode supplied a local route
without compiling native code or replacing the system OpenSSL.

OpenSSL explicitly documents that successful ECH decryption makes the inner
ClientHello visible to the ClientHello callback; failed decryption exposes the
outer hello instead. The same callback can suspend the handshake and be invoked
again when it resumes:
[SSL_CTX_set_client_hello_cb documentation](https://docs.openssl.org/4.0/man3/SSL_CTX_set_client_hello_cb/).

## Tested sequence

```text
Separate OpenSSL 4 CLI client
  genuine RFC 9849 ECH, inner SNI secret.example
  inner ALPN [h2, http/1.1], outer ALPN [http/1.1]
        |
        v
Python + CFFI + libssl.so.4
  decrypt ECH
  callback reads inner SNI and exact ordered ALPN bytes
  callback returns SSL_CLIENT_HELLO_RETRY (-1)
  SSL_accept returns SSL_ERROR_WANT_CLIENT_HELLO_CB (11)
  no server certificate has been installed yet
        |
        v
Python opens a separate, certificate-validated TLS connection
  to the local origin fixture, using the original ALPN offers
  obtains origin certificate and selected ALPN
        |
        v
Python installs a per-connection certificate/key
  resumes SSL_accept; callback returns success
  server selects origin's ALPN choice, including no ALPN
        |
        v
Validated client TLS and encrypted application data on both legs
```

This proof does not authorize any external destination. Both endpoints bind
loopback on OS-selected ports, use temporary fixture credentials and have
bounded waits and cleanup.

## Public API surface demonstrated

- **Key generation and persistence:** `OSSL_ECHSTORE_new`,
  `OSSL_ECHSTORE_new_config`, `OSSL_ECHSTORE_write_pem`; Python generates an
  X25519/HKDF-SHA256/AES-128-GCM configuration with ECHConfig version `0xfe0d`,
  writes it privately, frees the generation store, and reloads it.
- **Server configuration:** `OSSL_ECHSTORE_read_pem`,
  `OSSL_ECHSTORE_num_keys`, `SSL_CTX_set1_echstore`.
- **Inner hello and suspension:** `SSL_CTX_set_client_hello_cb`,
  `SSL_client_hello_get0_ext`, `SSL_ech_get1_status`, and retry return codes.
- **Deferred certificate and ALPN:** `SSL_use_certificate_chain_file`,
  `SSL_use_PrivateKey_file`, `SSL_check_private_key`,
  `SSL_CTX_set_alpn_select_cb`, `SSL_get0_alpn_selected`.
- **Application I/O and ownership:** normal `SSL_read_ex` / `SSL_write_ex`,
  `SSL_free`, `SSL_CTX_free`, BIO and ECH-store frees; OpenSSL-allocated
  status strings are released using the matching library's `CRYPTO_free`.

These are public header declarations, not pointers extracted from CPython or
cryptography internals. The tested ECH store interfaces are described in
[OpenSSL's ECH design](https://github.com/openssl/openssl/blob/master/doc/designs/ech-api.md);
the installed 4.0.2 headers govern the actual signatures in the proof.

## Tests and evidence

Source:

- `services/ads-sandbox-egress/tests/ech_probe.py`
- `services/ads-sandbox-egress/tests/test_ech_capability.py`

Eight capability tests passed with actual OpenSSL 4.0.2 libraries and CLI:

| Case | Verified outcome |
| --- | --- |
| Genuine ECH, origin selects HTTP/1.1 | Inner hello, pause, verified origin leg, deferred certificate, resume and two-leg data exchange |
| Genuine ECH, origin selects h2 | Same sequence; selected ALPN remains h2 |
| Genuine ECH, origin selects no ALPN | No ALPN is invented |
| Plain TLS | Works but is not labeled ECH |
| ECH GREASE | Works but is not labeled successful ECH |
| Unknown ECH key | Outer identity is not mistaken for inner; rejected before upstream contact; no opaque tunnel |
| Client hostname mismatch | Client certificate verification fails; no application exchange |
| Missing native runtime | Failure before any listener starts |

The fixture uses a private, explicitly trusted self-signed certificate. This
proves hostname validation and late certificate installation, not ADS's
certificate substitution/defect-mirroring algorithm.

All five local Nox sessions passed with this proof enabled. The focused egress
suite passed **216 tests, zero skips**, in 8.87 seconds on Python 3.14 after
final review. The eight capability tests additionally passed on Python 3.12.13
in 3.96 seconds.
The earlier full-workspace result remains historical evidence and was not
rerun or relabeled as including these new tests.

The real ECH client is a separate native OpenSSL process, not a mocked TLS
client. It shares the OpenSSL implementation family with the frontend;
browser/BoringSSL/NSS interoperability is not established by this proof.
Application payloads are fixture bytes, not an HTTP/2 or WebSocket protocol
proof; the h2 cases test ALPN negotiation/preservation only.

## Reproduce without a native build

The observed test runtime was Debian's prebuilt `4.0.2-1` packages, downloaded
using APT's signed archive metadata and extracted into a private directory:
[Debian OpenSSL tracker](https://tracker.debian.org/pkg/openssl).
No experimental packages were installed into the operating system.

The Debian signing keyring itself came from the already trusted Ubuntu
repository's `debian-archive-keyring=2025.1ubuntu1` package. An isolated APT
configuration selected Debian experimental, kept its own lists/cache, and used
that extracted keyring. APT verified package hashes against signed metadata.

The observed amd64 packages were:

| Package | SHA-256 |
| --- | --- |
| `libssl4_4.0.2-1_amd64.deb` | `1e265574c02f4918092d2f09e63cf368b21f15108b667790633f038717ded260` |
| `openssl_4.0.2-1_amd64.deb` | `657b368d7ae7c57cb85e24766a6e4f756b45e4f275dc991b2697b8cc648d7f6b` |
| `libssl-dev_4.0.2-1_amd64.deb` | `aaff011fb88dff21cbd09e25f49b31ca4a69be4102c75c4d3c31b8d4f2b63c8f` |

Extract with `dpkg-deb -x` into the same isolated root. The development package
was used to inspect matching public headers, not to compile a binary.
Do not load these files into a production image merely because the proof
passed: this build declares libc >= 2.38 and other distro dependencies.
Production supply and image compatibility still require packaging work.

With that root set in `ADS_EGRESS_OPENSSL4_ROOT`, run:

```sh
ADS_EGRESS_OPENSSL4_ROOT=/absolute/path/to/extracted/root \
  uv run --group test pytest \
  services/ads-sandbox-egress/tests/test_ech_capability.py \
  --override-ini addopts= -q
```

The test harness loads `libcrypto.so.4` and `libssl.so.4` explicitly, alongside
the unchanged Python/system OpenSSL 3 library. Only child CLI processes receive
the isolated `LD_LIBRARY_PATH` and `OPENSSL_CONF=/dev/null`.
CFFI `2.1.1` is an exact test dependency; ABI mode needs no C compiler.

If the environment variable is absent, native-dependent tests explicitly skip.
If it is supplied but invalid, they fail. A skipped test is not ECH proof.
No CI workflow was added, weakened or triggered.

## Production integration still required

The committed code is a capability harness, not a production transport. The
next implementation should own:

- **Bounded nonblocking I/O:** per-connection handshake state, deadlines,
  cancellation, ciphertext/plaintext buffer bounds and backpressure.
- **Ownership and callback safety:** explicit library/context/store/session
  lifetimes, callback references, error-queue handling and no exceptions crossing
  C callbacks. The upstream work happens after returning retry, not inside
  the callback.
- **Security integration:** original-destination checks, real origin certificate
  acquisition/classification, stable substitute pairs, no HTTP before policy
  authorization, no unwanted session-resumption or renegotiation bypass.
- **Durable keys:** encrypted custody/publication/retirement, multiple retained
  generations, DNS ECHConfig publication, supported stale/foreign configuration
  behavior and retry validation. Rejecting the foreign-key fixture proves no
  bypass, not completed retry compatibility.
- **Runtime supply:** pinned compatible OpenSSL 4 shared libraries and startup
  API/version checks; any project-native/image build remains GitHub CI work.

No publication, merge, lab deployment or slice 21/22 proof occurred. Slice 20
remains open, but Python-controlled ECH is no longer an unproven prerequisite.
