# Native IPC node release observer

`ads-ipc-release` is a bounded node-root command in the CI-built tooling image.
It is read-only toward Kubernetes, CRI and workload processes. Its only writes
are protected, atomic, fsynced inventory records under the configured state
directory. It cannot delete Pods or volumes, kill processes, choose arbitrary
commands, or report final generation retirement.

## Trust and requests

Run on the original IPC application node, in the actual node PID and mount
observation environment. The trusted operator provides a root-owned private
configuration file containing `node`, `namespace`, `kubeconfig`, `kubectl`,
`crictl`, `cri_endpoint`, `container`, `mount`, and `stateDir`.
The executable and kubeconfig paths must be canonical protected files; the
kubeconfig is mode 0600, local CRI uses a Unix socket, and the state directory
is private. Its Kubernetes identity needs only namespaced Pod list and the
corresponding IPC PVC read; no exec, mutation, signer or general Secret access.

Input is one bounded strict JSON object: `action` (`capture` or `observe`),
`config`, exact `generation`, `sandbox_id`, `pod_uid`, `volume_uid`, and
`inventory_sha256`. Capture requires a null digest; observation requires the
original capture digest. Paths and commands are platform inputs, never guest
or relay data. A later authenticated transport must fix the configuration path
server-side rather than exposing a caller-selectable filesystem API.

The manager must already have permanently fenced its creator and settled every
original write before invoking capture. The generation lock serializes these
protected observations; it is not itself a manager-write or kubelet fence.
This component is not that authenticated delivery channel.

## Original capture

The helper verifies the manager-owned IPC Pod's exact namespace/name/UID, node,
sandbox/generation labels and absence of a controller, host namespaces,
sidecars and subPath mounts. The exact named IPC filesystem PVC must be Bound
with the requested UID. Pod status, CRI sandbox, container labels, names and
native runtime identities must agree.

Live PID handles fence sandbox/container replacement while capture records
container network, mount and PID namespace identities and the actual IPC
filesystem's device, kernel mount root, mount target and root inode. All three
namespaces must differ from host PID 1. A dedicated non-root filesystem subtree
is required. Kubernetes, CRI, mount table, namespace and root identities are
rechecked before committing.

The root-private `ipc-release-<generation>.json` snapshot is atomically persisted
and fsynced. A retry reasserts durability without adopting a different runtime,
volume, Pod or boot. Missing original inventory, unsupported partial starts
and node reboot remain explicit errors; they do not become empty captures.

## Release observation

The helper rechecks boot and exact inventory digest, then observes local Pods,
CRI sandboxes and all containers. Original or replacement IPC objects in the
same generation block release; unknown runtime states are not treated as
exited. Kubernetes and CRI observations run before and after the process scan.

The bounded scan covers every process and nonleader task, runtime identifiers,
Pod cgroups, namespace references, held namespace descriptors, mounted
filesystem subtrees, open file descriptors, memory maps, executable mappings,
cwd and root. Positively identified kernel threads and zombies have no live
userspace memory/descriptor references; ambiguous or unreadable tasks fail closed.
Detached filesystem
references cannot be excused because a mount has disappeared from mountinfo:
descriptor mount IDs and O_PATH cwd/root handles preserve that distinction.
Unreadable or incomplete observations and exceeded deadlines fail closed.
The helper never inspects file content inside the IPC volume.

Only clear positive observations emit `observed_runtime_released: true`.
The `ads-ipc-release-v1` output exposes immutable scope, boot, inventory digest
and bounded leftover counts, not runtime specs, private paths or command lines.
The digest binds content; it is not authentication or freshness.

## Proof boundary

Deterministic tests use the real snapshot, validation and scanning code, with
fake external Kubernetes/CRI responses and temporary process-tree fixtures.
The tooling-image CI smoke uses real bind mounts, lazy unmount, held descriptors,
a detached working directory and a memory map with descriptor tracking disabled.
It requires release to remain blocked until
the final reference is removed.

Authenticated production manager-to-node delivery, interrupted startup and
reboot recovery evidence, positive storage reclamation, generation retirement
and complete live lifecycle acceptance remain separate slice-19 obligations.
This observer alone neither completes slice 19 nor proves live deployment.
