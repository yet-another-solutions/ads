# Egress CA initialization component

`ads-sandbox-ca` is a one-time runtime data initializer. Its image is built,
tested and published through the existing GitHub Actions matrices, not in the
lab. It does not build an image, rootfs, binary or chart at runtime.

## Inputs and output contract

The manager's normal-runtime Job supplies these immutable inputs:

- `/signer/tls.crt` and `/signer/tls.key`: the explicitly configured existing
  intermediate Secret in the same namespace, mounted read-only. Certificate
  order is signing intermediate through its self-signed root.
- `/additional/ca.crt`: a public-only PEM bundle, possibly empty, captured once
  from the configured additional trust ConfigMap.
- `ADS_CA_ATTEMPT`: the retained Job's UID, not the Pod UID.
- `ADS_CA_BYTES`: the exact integer byte size of each source Block PVC.
- `/dev/ads-ca-public` and `/dev/ads-ca-private`: distinct new whole block
  devices, 64Mi through 1Gi each. The manager default will be 256Mi.

No Kubernetes token or API access is needed by this image. It neither discovers
nor copies Secrets. The root private key is never input; the intermediate key
remains on its read-only Secret mount, never either output disk.

Each hierarchy certificate must be currently valid, permit the new CA depth,
have a valid direct issuer signature, use a supported strong key/hash, and have
CA/signing constraints. Unsupported critical extensions and constrained
name/EKU hierarchies fail closed rather than silently dropping restrictions.
The child uses a fresh P-384 key, critical CA/pathlen:0 and cert/CRL-signing usage.
Its `notAfter` is exactly the signing intermediate's, not a new duration.
An ancestor expiring earlier is rejected.

Public ext4 volume:

- `trusted-egress-ca.pem`: the single minted egress certificate and committed identity.
- `signing-chain.pem`: its complete public signing hierarchy through the root.
  Sandbox boot validates and installs both files' certificates alongside the
  ordinary golden baseline. This intentionally trusts the configured parents/root,
  as approved on 2026-09-25; it is not restricted to the egress subtree.
- `egress-only-trust.pem`: extra public anchors, imported by egress alone.
- `complete.json`: format, Job attempt UID, minted certificate fingerprint,
  exact expiry and role.

Private ext4 volume:

- `trusted-egress-ca.key`: only the new subordinate key, mode 0600.
- `complete.json`: the same generation, fingerprint and expiry, private role.

The private volume is never cloned or attached to the guest. Consumer clones
must be read-only; matching manifests and certificate/key must be verified at
consumer boot. The unrelated untrusted issuer belongs to each egress process
and is deliberately neither minted nor persisted by this Job.

## Failure and recovery boundary

Preflight checks only the two designated devices. It rejects regular files,
symlinks, partitions, holders, read-only devices, wrong sizes, kernel claims
across mount namespaces, existing signatures and aliased device identities.
It does not enumerate/mknod host disks or assume a Kata-specific disk layout.
Both device checks finish before either format.

New files are exclusively created and fsynced. Both completion manifests are
written only after all certificate/key data; the Job may succeed only after
both filesystems unmount. Neither manifest alone commits the pair. Mount,
write, flush or unmount failure is fatal with a sanitized error class only.
A crash may leave partial output and is never repaired by reformatting it in
place. Manager must retain the Job name lock, prove release of both outputs,
delete the failed pair with UID/resourceVersion guards, and start a new attempt.

## Manager integration

The manager now owns stable Job `ads-sandbox-ca` and Block claims
`ads-sandbox-ca-public` / `ads-sandbox-ca-private`. It acquires the Job name before
creating either PVC, repairs a crash between creates using the retained Job UID,
and handles competing replicas with ordinary API name conflicts. No source
ownerReference, release-derived name, automatic per-release reissue or Job TTL
is introduced.

`CaEnsure` follows the existing golden completion/recovery state machine and
uses the same `KubeClient.released()` positive evidence: terminal Pod with its
runtime sandbox gone, correct PV claim UID, no node volume-use/attachment entry,
and no outstanding VolumeAttachment. Bound is not interpreted as mounted or
released. Both claims and the Job are reread with UID/resourceVersion matching
after both release checks. No half pair is returned by `clone_sources()`.

A failed Job, or completed Job with one missing/deleting output, invalidates the
whole pair. Both surviving claims must pass release checks before deletion.
UID/resourceVersion-guarded deletes start first; only then may the corresponding
terminal Job Pod be deleted to release PVC protection. Job lock deletion waits
until both claims disappear. Orphans are never adopted; ambiguous release
evidence blocks destructive recovery rather than guessing.

Production manager startup requires `ADS_SANDBOX_MANAGER_CA`, a typed JSON
object supplied by Helm. `sandbox.ca.signingSecret` must name the pre-provisioned
Secret in `sandbox.namespace`; empty defaults fail closed at manager startup.
Additional public PEMs use a dedicated ConfigMap there, not the application
namespace. Helm rejects accidental private-key PEMs in this public field.
The CA Job gets no API token and a matching deny-all network policy. Slice 19
explicitly authorizes the manager to get/create/delete Secrets in
`sandbox.namespace` for paired custody, without list/watch/update/patch.
This namespace-scoped grant also permits reading the configured signer there;
that consequence was explicitly accepted. Manager application code still never
discovers, copies or relocates signing custody. Platform policies must not add a
conflicting broad network allow.

The trusted normal-runtime initializer requires `SYS_ADMIN` only for its two
designated CSI filesystems. Its AppArmor profile is explicitly `Unconfined`:
the lab's containerd default profile denied even a read-only filesystem mount
despite this capability. A comparison using the same published image, devices,
capabilities and RuntimeDefault seccomp succeeded when only AppArmor changed.
This is a per-Job setting, not a node policy change or permission to run an
untrusted guest unconfined. No privileged mode, host namespace, hostPath, API
token, extra capability, writable rootfs or privilege escalation is added.

Readiness requires golden completion, CA pair completion and ordinary
dependencies. HTTPS liveness remains independent while initialization/recovery
is pending. Unit-only settings may omit CA, but production environment loading
cannot, and configured CA with missing runtime wiring is not ready.

Local tests cover replica races, half-pair failure and release, restart recovery,
foreign objects/attempts, immutable observation fencing, terminal-Pod cleanup,
settings, readiness and actual rendered Helm wiring.

## Consumer validation and process-local issuer

`ads_commons.egress_trust` is shared security/file validation, not lifecycle
orchestration. It validates strict manifest fields, duplicate-key rejection,
expected Job attempt, fingerprint, CA constraints and expiry. Fixed leaf reads
are bounded, reject symlinks and nonregular files, and use nonblocking opens so
a corrupt FIFO cannot hang bootstrap.

The guest loader reads `complete.json`, `trusted-egress-ca.pem` and
`signing-chain.pem`, verifying ordered signatures, CA/path constraints, current
validity, root termination and exact intermediate expiry before exporting trust.
The egress loader additionally requires a matching private manifest, matching
key, valid parent signatures/path depth and exact intermediate expiry; it keeps
company anchors separate from the served signing chain. Private-key objects
are excluded from diagnostic representations.

The base-owned guest helper requires kernel block read-only and mounted
filesystem read-only state before using the public clone. The minted CA plus
validated signing hierarchy is streamed into rootless `podman exec` before readiness,
on both create and resume. Mutable rootfs programs never run as guest root.
The base-owned installer executes inside that rootless container, writes one
certificate per `.crt` under `ads-egress/`, removes only prior ADS-owned entries,
and refreshes the trust bundle/hash directory. Egress-only extra trust and keys
never enter this stream. The existing CA-Job output format and key are unchanged.
Full-chain CRL verification separately needs issuer CRLs; certificates are not
revocation evidence. No parent private keys are copied to supply that evidence.
GitHub Actions builds the base from repository-root context to copy the exact
shared verifier; the golden device checker remains unchanged.

`ads_sandbox_egress.issuers.untrusted_issuer` creates an independent self-signed
P-384 CA once per process bootstrap, with the verified intermediate's exact UTC
expiry. It is not signed by the trusted hierarchy and has no persistence path.
Tests prove different keys across calls and unchanged files; full egress runtime
bootstrap will own one instance and reuse it, not mint per failed request.

## Consumer clone lifecycle

The manager commits the CA Job attempt and both source PVC UIDs before creating
three Block clones: `ads-ca-guest-<sandbox-id>` and `ads-ca-egress-<sandbox-id>`
from the public output, and `ads-ca-key-<sandbox-id>` from the private output.
Each clone has its own durable UID binding, session/sandbox labels, source UID
and attempt labels; none owner-references disposable compute. Destination size
is at least the source's actual capacity. Pending clones are allowed because
storage is WaitForFirstConsumer, not because Pending proves usable content.

Source-pair safety is rechecked before and after each create. Name conflicts
are adopted only with matching immutable policy and identity; lost responses
leave durable cleanup intent. API quantity normalization and omitted core API
group fields are accepted, not alternate/cross-namespace data sources. A
committed clone disappearing or changing UID fails the run rather than silently
recloning. All three binds are reread before each compute creation.

The guest gets only its public clone via `volumeDevices` and a PVC
`readOnly: true` attachment, plus the committed `ADS_CA_ATTEMPT`. Production
guest construction without that attempt fails. The separate private clone is
reserved for the later egress VM and is never attached to the guest or IPC.

Idle shutdown keeps the existing drain acknowledgement and workspace retention
contract. All disposable clones are removed only after compute teardown and
positive storage release/reclamation. Resume reclones them from the same
committed source pair while preserving workspace identity. Recovery captures
all three names, including create-with-lost-response cases without committed
UIDs, before sandbox identity rotation. Orphan inventory recognizes only exact
consumer role/name/session identity; shared CA sources are not lifecycle targets.
The fresh initial schema stores only attempt/source/clone identities, no key
bytes, tokens or credentials. No legacy schema upgrade is added.

Complete guest/egress pair deployment remains the next integration boundary.
The first live CA Job failed at its first mount under default AppArmor, leaving
one formatted source and one blank source. This is not a committed CA pair.
Recovery must still positively release and replace both failed outputs through
the production controller; never reformat that partial pair in place.
Integrated trust and TLS defect-mirroring acceptance remain unproved.
