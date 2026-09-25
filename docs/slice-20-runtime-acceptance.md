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
| Immutable snapshot, process UUID, authenticated apply | Existing configuration/control; existing receiver tests | Baseline present; regression pending |
| Complete ordered policy, names, absent identity, paths, transitions | Egress policy; table and negative tests | Open |
| Mandatory address classification and trusted infrastructure inventory | Egress destinations; registry-boundary tests | Open |
| Connection-local TTL evidence, shared misses, no stale fallback | Egress membership; asynchronous concurrency tests | Open |
| Strict bidirectional HTTP framing and trailers | Egress framing; raw duplicate/header/body tests | Open |
| Disposable NGINX normalization and real protocol adapters | Local helper; actual installed NGINX tests | Open |
| HTTP/1.1 and HTTP/2 streaming, resets, upgrades and ALPN | Protocol handlers; actual socket clients | Open |
| DNS traversal, all-endpoint inspection, budgets and UDP/TCP | Resolver; actual DNS clients and upstream fixtures | Open |
| Synthetic DNSSEC, flags, defects and independent validation | DNSSEC; independent validators | Open |
| ECH termination, durable publication and retained keys | TLS adapter and persistent state; actual ECH client | Open |
| TLS certificate pairs and defect mirroring | TLS inspection; real validation clients | Open |
| State custody, block mounts, startup/teardown and health | Bootstrap; real kernel/storage tests | Open |
| Entrypoint and source-only packaging integration | Runtime and Containerfile/workflow definitions | Open |
| Full local regression and review | Nox lint/deps/typecheck/test/package | Open |

## Feasibility observations

The initial Computer interpreter is Python 3.14.3 linked to OpenSSL 3.5.5.
Its `ssl.SSLContext` has no ECH API. This is a concrete observation about the
available interpreter, not a claim that ECH cannot be implemented.
[OpenSSL's ECH design](https://github.com/openssl/openssl/blob/master/doc/designs/ech-api.md)
documents OpenSSL 4.0 ECH; selecting and proving a Python-compatible server
binding remains required. Ordinary TLS, GREASE or rejection is not ECH proof.

Current CI triggers are pull requests and pushes to main/master; feature-only
preservation without a PR does not trigger that workflow. Inspect all workflows
again before a push. No CI fallback is yet justified or initiated.

PR #135 is unrelated publication-timeout work and must not be folded into this
branch. At preflight it remained open with auto-merge off; its inherited CI and
v0.0.35 publication were in progress. Their results are not this branch's proof.
