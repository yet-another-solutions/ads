# Node runtime release observation

`ads-ptp-release` is a bounded, trusted node-root command in the tooling image.
It captures live identities before teardown and later observes their release.
It does not delete resources, stop processes, execute guest code or turn a
healthy node/empty Kubernetes watch into proof of runtime release.

## Protected inputs and ordering

Stdin is one bounded JSON object with exactly `action` (`capture`, `capture-startup` or `observe`),
`attestorConfig`, `stateDir`, `generation` and `sandbox_id`. The configuration
is the protected existing node attestor configuration. All CNI calls, the
retirement command and this observer must use matched CI-built files and the
same persistent state directory. Run in the actual node's PID, mount and
network namespaces with root access to all process observations; a container's
private `/proc` is not a node inventory. Never expose this authority to a guest
or relay. API access remains the attestor's read-only namespace Pod access.

1. Fence admission with `ads-ptp-retire` while both attachments and relays are
   live, before removing compute. Busy/failed fencing is not sufficient; a
   successful durable fence prevents another CNI ADD from escaping the captured
   inventory. The fence does not stop existing interfaces.
2. Capture under that exact durable fence. The command takes the generation lock,
   validates both protected CNI journals against fresh Kubernetes/CRI/process
   attestation and actual CNI CHECK, verifies the VM CRI ownership, then captures
   four Pod UIDs, four runtime sandbox IDs, six distinct namespace identities,
   two host peer link identities, node/namespace/network and node boot ID.
3. The root-owned mode-0600 `release-<generation>.json` is atomically persisted
   and fsynced. Retries retain those identities and reassert durability, never
   adopt a replacement runtime. A missing/partial journal set or ambiguous live
   capture fails; no synthetic empty inventory is created.
   Manager creators must lose their existing claims, and their compute/controllers
   must be torn down under separate exact ownership fences. Keep control policies
   in place; capture itself does not prevent late relay/controller creation.
4. Observe only with the exact durable admission fence and captured inventory.
   Changed boot/scope, malformed input, unreadable observations, exceeded bounds
   or unavailable API/CRI are errors, not absence.

## Observation boundary

The observer checks current local namespace Pods by original UID and generation,
ready/unknown CRI sandboxes, running/created/unknown containers, matching CNI
journals and surviving or reused host link identities. It scans every process
and nonleader task for captured network namespaces, held network-namespace
descriptors, namespace mount roots and runtime IDs in command lines. Only
definitely vanished tasks/descriptors and verified zombies are skipped;
permission errors and incomplete live observations fail closed. API/CRI reads
are repeated after the bounded scan, and both observations must be clear.

Output contains counts and immutable scope, never runtime specs or command
lines. `observed_runtime_released` can become true only when every observation
is clear; `generation_retired` is always false. Existing traffic is not stopped
by an observation. The node/runtime is trusted: this is not proof against a
host-root adversary hiding kernel references or running the tool in a false
namespace. The captured node boot must be unchanged; reboot requires a separate
explicit recovery proof rather than treating stale inode values as authority.

### Exact manager evidence binding

Capture and observation now emit the `ads-node-release-v1` report with the exact
four Pod UIDs, node boot ID and a SHA-256 digest of the canonical complete
protected inventory. Capture includes `leftovers: null` and release false;
observation includes every bounded counter and a consistent release boolean.
Both retain the durable admission-fence and inventory-captured assertions.
The runtime IDs, namespace inode/device pairs and host-link identities remain
in the protected node record, not in the report.

The common strict DTO rejects unknown/duplicate fields, duplicate/missing Pod
identities, unbounded or malformed counters and inconsistent verdicts. The
manager comparison requires exact original sandbox/generation, namespace,
network, freshly observed single-node placement and all four captured Pod UIDs.
An observation must then match the original boot and inventory digest as well.
Capture responses, other generations, reboots and incomplete reports cannot
be used as release observations.

The digest is a content binding, not a signature, freshness proof or authority.
Reports must arrive over a separately trusted node-owner channel in response to
the current cleanup operation. This component does not implement that channel,
persist manager teardown progress, authorize a delete or bypass the existing
runtime-release guard. Unsupported partial inventories remain blocked.

### Interrupted attachment startup

`capture-startup` uses the same durable fence and immutable snapshot format,
but can capture interrupted ADDs whose pre-effect journals already exist.
It does not require operational links or successful CNI CHECK. Instead it
verifies both original ADD journals, their namespace identities and valid
progress fields, fresh exact Kubernetes/relay/process attestation, both VM CRI
identities in a known Ready/NotReady state, and exact host peers. After the
inventory it rereads both journals and repeats live binding, VM runtime,
namespace and exact host-peer identity checks. Missing/replaced/unknown state
fails closed.

This still captures all four Pods/runtimes, six distinct namespaces and both
host peer links. It neither claims ADD succeeded nor erases a partial journal.
Existing snapshot retries retain the first capture across both actions and
only reassert durability; startup capture cannot overwrite earlier evidence.
The unchanged `observe` path checks all references, including incomplete CNI
journals, before reporting runtime release. Capture itself always reports
release false. There is no API-absence or synthetic empty-inventory fallback.

Earlier startup failures that never produced both journals, lost runtime
evidence and relay-only startup remain blocked pending separate comprehensive
inventory support. Manager-to-node delivery, general partial-create
recovery, late Kubernetes creator fencing, compute/controller and storage
release, policy cleanup and final generation retirement remain integration
work. This observer is not invoked by the manager yet and does not bypass its
paired-cleanup guard.

## Verification

Unit tests use the real protected record and generation-lock code, with fake
Kubernetes/CRI responses and isolated process trees. They cover captured identity
validation, capture retries, mandatory fences, changed boots, each release
blocker, late observations and bounded/incomplete scans. The tooling-image CI
adds a real network namespace, process, namespace bind mount and held descriptor,
and checks that release observation stays blocked until those references are
removed. That is kernel component proof, not a live lab or manager proof.
