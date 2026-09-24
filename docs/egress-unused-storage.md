# Original never-mounted storage

Paired cleanup uses a separate retained proof for an issued PVC whose original
consumer demonstrably never ran. It does not invent an empty node inventory or
reinterpret missing API objects as release.

The sealed creator ledger and positive unscheduled-Pod deletion receipt are
different contracts. A never-dispatched consumer can support a never-provisioned
claim under the original dynamic WaitForFirstConsumer StorageClass. An existing
but unscheduled Pod might already have initiated provisioning; an unbound claim
in that history remains ambiguous and is not deleted by this path.

## Supported contracts

* Never-provisioned: the consumer was never dispatched, the original claim is
  Pending, unbound and unselected, and its dynamic WaitForFirstConsumer class
  predates it. The captured class UID and immutable binding/provisioner contract
  are rechecked immediately before UID/resourceVersion-conditional deletion.
  Static no-provisioner classes and replacement/new classes are rejected.
* Never-mounted CSI: the original consumer is positively never-started; the
  original bound PVC/PV/CSI identity is captured before deletion. No Pod,
  VolumeAttachment or node usage may contradict that history. Destructive
  disposition requires the captured Delete policy and external-provisioner
  reclamation guard, then actual completion of that protected PV deletion.
* Started consumers continue through the original node/runtime/Block or IPC
  filesystem proof. Bound non-CSI never-mounted backing needs a positive
  backing observer; this path deliberately cannot authorize its reclamation.

Every original capture commits before deletion, each disposition commits under
the same cleanup/recovery claim, and lost replies retry only the captured
identity. Storage API queries provide vetoes, not fabricated node release.
Shared source PVCs are never targets. Idle retention cannot be replaced by a
never-provisioned deletion contract.

The Kubernetes contract is documented at
https://kubernetes.io/docs/concepts/storage/storage-classes/ and
https://kubernetes.io/docs/concepts/storage/persistent-volumes/ .
StorageClass provisioner and volumeBindingMode update immutability is enforced
in https://github.com/kubernetes/kubernetes/blob/v1.36.4/pkg/apis/storage/validation/validation.go .
This is code-level composition, not a live storage-driver or final-slice proof.
