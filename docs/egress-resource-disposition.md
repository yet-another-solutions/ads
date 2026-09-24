# Exact paired resource disposition

The resource stage follows the retained original runtime and storage proofs.
It does not infer release from resource absence, and it does not itself retire
the generation or authorize a replacement owner. Generation completion remains
a separate proof-checked transaction.

## Gates and ordering

The stage revalidates the same cleanup claim and permanently sealed creator
ledger before every external call and every receipt commit. All original runtime
roles must be positively released or positively never started, and every issued
storage obligation must have its authorized retained/reclaimed disposition.
NetworkPolicies remain in place until both gates are satisfied.

The exact targets are derived from the original control UID map, immutable relay
input UIDs, transient relay custody UID and persistent-state wrapping custody
UID. Unissued resources create no obligation; issued resources without settled
original writers and captured UIDs cannot be discarded. No caller supplies a
Secret name or arbitrary object selector.

Services, PodGroups and NetworkPolicies use original UID/resource-version
preconditions. Credential deletion also checks original ownership labels and
UID, uses a resource-version precondition, and observes actual disappearance
without stripping finalizers. A same-name replacement is refused. Credential
API exceptions are sanitized; key data never appears in the journal or output.

## Retention and retry

Idle retains the persistent wrapping Secret along with the already-released
workspace and persistent-state volumes. Retained custody must still exist under
its original UID and must not be terminating. Transient relay input and
paired-key Secrets are disposable only after their last users have released.

Idle keeps the sandbox's topic pair for subsequent use. Destructive disposition
uses the existing exact sandbox-UUID topic names and must observe broker removal
before recording completion. A sealed unissued topic operation requires no
broker deletion. Unresolved original topic creation cannot pass the seal.

Each successful resource disposition has its own retained receipt. Lost replies
retry only the same original identity; already committed receipts are not
rewritten. Claim loss or cancellation prevents later receipt commits and leaves
remaining obligations intact. A cleanup retry is not permission to regenerate
keys, adopt new UIDs, or erase the generation ledger.

## Scope

The normal and recovery callers share this stage through dependency injection.
Fully captured started storage is supported by the separate IPC and Block
components. Never-mounted/unbound storage and final retirement/resume have
additional obligations; this component does not mark those paths complete.
