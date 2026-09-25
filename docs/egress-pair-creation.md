# Paired creation and ready admission

The existing SessionProvisioner now delegates its configured paired build to
PairCreation under the original creating claim. It does not create a second
session state machine, replay execution messages or claim live egress proof.

## Trusted runtime configuration

Environment startup requires `ADS_SANDBOX_MANAGER_PAIR_INPUTS`, a nonsecret JSON
object with exactly `guest`, `relay`, `egress` and `state_bytes`. These use the
existing fixed runtime constructors. Guest and egress RuntimeClasses must be
distinct from each other and the old shared-network guest class; all transport
MTUs must match. Relay and egress images are digest-pinned. TLS values are named
Secret references, not inline keys. The native IPC service subject is a UUID.

The egress issuer and discovery URL come from manager Keycloak configuration,
not a second override inside the JSON. Malformed, missing or null inputs fail
before client startup. Direct isolated Settings fixtures can remain unpaired;
configured paired input with no creation service cannot fall back to legacy
guest/IPC Deployments. Helm `sandbox.manager.pairInputs` renders the same JSON
into only the manager ConfigMap. Its empty default fails closed at manager
startup, like the unset CA signer input. Supply reviewed platform values before
any candidate rollout; this change does not invent deployable later-slice images.

## Ordered publication

Creation executes the existing publishers in order: controls, fresh workspace
and CA clones, topics/barrier, guest and relay Pods, paired-key custody,
immutable relay inputs, persistent state, egress Pod and IPC PVC/manager-owned Pod.
Each prerequisite must have settled original writes and exact UID bindings
before dependent execution. Publishers retain their own committed payloads and
current-claim checks around external calls.

Topic preparation gains one monotonic dispatch field on the existing pair
intent. The original invocation is retained and separately settled after normal
return. Ambiguous topic preparation blocks progress and is never replayed as if
unissued. The existing best-effort replica barrier still precedes guest/IPC
compute. Cleanup snapshots carry topic dispatch; capture cannot settle it.

The outer SessionProvisioner records failure only under its existing exact
claim. Any failure stops later stages. Shutdown stops creation workers before
draining retained publishers; drain is not remote quiescence or release proof.
Paired resume requires a verified exclusive transfer from a sealed idle
retirement. Preflight verifies the original workspace/PV/CSI, persistent state
and wrapping-key identity before any new generation resources are dispatched.
The original state provenance remains immutable; the new generation receives
fresh transient controls, clones and relay custody.

## Ready transition

Creation never marks the row ready. IPC still owns its
existing real guest preparation, relay health, egress control and initial
policy-installation gates before emitting authenticated ready.
If that authenticated transition wins immediately after the final IPC UID bind,
creation may return the already-ready row after a read-only exact original
claim/generation and bound-UID check. A replacement claim is still rejected.

The existing manager ready transaction now distinguishes paired from truly
unpaired rows. A pair requires the original unfenced claim; settled topics,
controls, compute, custody, relay inputs, clones, persistent state and IPC;
matching session/PVC/CA/state/IPC identities; and no legacy guest or IPC Deployment.
Missing, replaced, incomplete or inflight evidence cannot satisfy that gate.
Only then does the existing atomic ready/attached transition proceed.

The subsequent lifecycle composes runtime/storage release, exact resource
disposition and retirement/transfer; see
[generation retirement](egress-generation-retirement.md). The separate
[protected reset coordinator](../deploy/reset/README.md) fences writers before
fresh schema initialization and restores owner-correct model configurations.
These are code-level contracts. Later-slice transport/data-plane and full live
acceptance are not claimed by simulated external ports.
