# Original IPC filesystem disposition

The local IPC filesystem path uses a separate storage observer after the
original native runtime capture and before deletion of its Pod. It supports
dedicated `local`/`hostPath` filesystem subtrees whose Linux filesystem implements
export handles; it does not reinterpret a CSI Block volume as a filesystem.

The node reads the exact original PVC/PV relationship, requires Delete policy,
correlates the backing directory's device/inode with the actual IPC mount, and
captures a bounded Linux export handle. That handle includes the filesystem's
inode-generation identity. Its ability to reopen the original directory is
verified before the protected capture is committed. Unsupported filesystems,
missing capabilities, changed nodes/boots, and incomplete captures block Pod
deletion; neither a new path nor a replacement runtime is adopted.

The manager commits the authenticated backing capture on the existing retained
PairIntent journal before removing the original IPC Pod. The report binds the
runtime capture digest, PVC UID, PV UID, generation, node and boot. Host paths
and export-handle bytes stay in protected node-owned files, not manager messages.
The existing mutual-TLS channel uses fresh request correlation and fixed helper
operations; it exposes no arbitrary path, command, or filesystem deletion API.

## Release and reclamation

After native IPC runtime/mount release, the storage stage requires another
positive node observation and conservative Kubernetes/Node/attachment checks
before committing its release receipt. It then rechecks the exact backing
identity and cleanup claim, issues a normal UID/resourceVersion-fenced PVC
delete, and waits for actual backing proof. A successful DELETE or PVC/PV API
absence does not satisfy reclamation.

The node requires the original parent filesystem identity, no remaining original
runtime or mount references, absent original pathname and a stale original
export handle (`ESTALE`). Renaming the directory keeps its handle addressable
and is not reclamation. A replacement pathname is rejected; permission errors,
unsupported handle operations, missing parent mounts and reboot are blockers.
The check brackets runtime observation so a single transient missing path is
insufficient. The original capture remains immutable across retries.

Normal and recovery entrypoints call the stage. Lost deletion responses retain
the release receipt and retry only the same UID; claim loss prevents subsequent
commits. Positive reclamation is retained independently of the work/session
rows. This stage never disposes workspace, CA clones, persistent egress state,
keys, policies or topics, and does not remove the final retirement guard.

## Installation and proof

Install `ads-ipc-storage` beside the matching node-owner and IPC-release helpers.
The node identity additionally needs PV `get`, as specified in
`deploy/node-owner/rbac.yaml`; no PV mutation, Secret access or exec is added.
The root service must retain Linux `open_by_handle_at` capability and the real
host process/mount view. Actual node filesystem support remains a live proof.

Unit tests use real temporary directories and explicitly fake kernel handles
and external Kubernetes/CRI boundaries. PostgreSQL tests exercise actual
repositories/adapters, receipt-before-delete, loss/retry, ownership replacement,
claim loss, cancellation, and retained-proof tampering. A dedicated privileged
CI ext4 smoke exercises real export handles, rename, replacement, deletion and
inode reuse. Adding that CI step is not evidence it has run; it must pass on the
complete final candidate. No live storage proof or slice completion is implied.
