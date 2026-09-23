"""Pure persistent-resource identities shared by publication and cleanup."""

from __future__ import annotations

from ads_sandbox_manager.egress_state_store import EgressState, validate
from ads_sandbox_manager.objects import COMPONENT, Object
from ads_sandbox_manager.pair_objects import PROJECT
from ads_sandbox_manager.session_objects import SANDBOX, SESSION


def identity(state: EgressState, role: str) -> Object:
    validate(state)
    if role not in ("key", "volume"):
        raise ValueError("unsupported egress state resource")
    return {
        "apiVersion": "v1",
        "kind": "Secret" if role == "key" else "PersistentVolumeClaim",
        "metadata": {
            "name": f"ads-egress-{role}-{state.state_id}",
            "namespace": state.namespace,
            "labels": {
                COMPONENT: "ads-egress-state",
                SESSION: str(state.session_id),
                SANDBOX: str(state.sandbox_id),
                PROJECT: str(state.project_id),
                "ads.io/egress-state-id": str(state.state_id),
                "ads.io/egress-state-role": role,
                "ads.io/egress-state-format": "v1",
                "ads.io/creator-generation": str(state.creator_generation),
            },
        },
    }
