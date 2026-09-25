# Original private Block release

This component captures original assigned CSI Block mappings before private
compute deletion, then composes positive runtime/device release with exact
storage disposition. It is not final generation retirement or whole-slice
acceptance. Never-started and unbound-volume disposition remain separate
obligations; missing original mapped-device history is not empty success.

## Node-owned evidence

The root-owned `ads-block-release` helper requires the permanent original CNI
admission fence and protected full or partial runtime capture. Its request
names only original PVC/Pod identities and the original runtime digest.
Configuration supplies the kubelet root, observer configuration and state root;
callers cannot supply storage paths, executables, CSI commands or credentials.

The helper checks the exact original Pod, claim and CSI PV binding and captures
the original block device identity through the kubelet's CSI mapping. The
fixed CSI kubelet mapping layout is defined by the
[Kubernetes CSI block implementation](https://github.com/kubernetes/kubernetes/blob/master/pkg/volume/csi/csi_block.go).
No rawfile provisioner directory, backing filename, loop allocation name or
driver cleanup command appears in the manager.

Protected node evidence retains device and kernel identity plus the exact
kubelet mapping locations. Only public PVC/PV/Pod bindings, original boot and
runtime/capture digests leave the node. Observation checks kubelet maps,
all task mounts and descriptor references, dependent kernel devices and
kernel mapping backing. Permission errors, unreadable live tasks, budget
exhaustion, boot changes and replacement identities fail closed. Two bounded
scans must both be clear; no API absence substitutes for either scan.

## Disposition

The repository binds immutable capture and release receipts to the sealed
creator ledger and original cleanup claim. Every resumed operation revalidates
that retained evidence; SQL transactions do not span external observation.
Runtime release must precede positive Block release and exact UID/resource-version
claim deletion.

Idle disposition retains the workspace and persistent state volumes. Other
claims require their captured CSI `Delete` policy and external-provisioner
deletion-protection finalizer, a fresh positive node observation, conservative
Pod/Node/VolumeAttachment blockers, and unchanged original PVC/PV backing.
CSI deletion protection specifies that the PV is removed only after backing
storage is deleted, as documented in
[Kubernetes persistent-volume deletion protection](https://kubernetes.io/docs/concepts/storage/persistent-volumes/).
The original PV must disappear under that captured contract before recording
reclamation; an absent PVC alone or a replacement PV is insufficient.

Lost delete replies retain the original receipt and only retry that identity.
There is no force finalizer removal, node/PV mutation, storage-driver shell,
replacement adoption or timeout-based release. Controls, credentials and
generation completion remain gated by their separate obligations.

## Verification boundaries

PostgreSQL tests use actual lifecycle repositories, retained journals and
Kubernetes adapters, faking API/node interfaces only. The image workflow also
contains a privileged, network-disabled kernel smoke using a real loop device
and open descriptor. Adding that smoke is not evidence of its CI result; the
whole-feature final-head CI gate is still required before readiness.
