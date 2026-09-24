"""Fixed IPC handoff to one already UID-bound guest, not create authority."""

from __future__ import annotations

from uuid import UUID

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_objects import (
    PairBinding,
    ipc_pair_environment,
    pair_labels,
    pair_name,
)
from ads_sandbox_manager.session_objects import ipc_deployment


def paired_ipc_pod(
    settings: Settings, pair: PairBinding, guest_uid: str, ads_service_subject: UUID
) -> Object:
    """Reuse the ordinary-runtime IPC, credentials, PID disk and health gates.

    The publisher must commit this payload and verify recorded compute/control
    dependencies before dispatch. This constructor never publishes or marks ready.
    """
    if settings.session_objects is None:
        raise ValueError("IPC configuration is required")
    if not isinstance(guest_uid, str) or not guest_uid.strip() or guest_uid != guest_uid.strip():
        raise ValueError("exact guest Pod UID is required")
    if not isinstance(ads_service_subject, UUID):
        raise ValueError("trusted ADS native service subject is required")
    deployment = ipc_deployment(settings, pair.session_id, pair.sandbox_id, settings.golden_version)
    labels = pair_labels(settings, pair, "ipc")
    deployment["metadata"]["labels"] = labels
    template = deployment["spec"]["template"]
    spec = template["spec"]
    spec["restartPolicy"] = "Always"
    spec["terminationGracePeriodSeconds"] = 30
    # Explicit bound/rotating projection at the existing SDK path: commit the
    # complete Pod payload instead of accepting admission-injected credentials.
    spec["automountServiceAccountToken"] = False
    spec["volumes"].append(
        {
            "name": "kube-api",
            "projected": {
                "defaultMode": 0o644,
                "sources": [
                    {"serviceAccountToken": {"path": "token", "expirationSeconds": 3600}},
                    {
                        "configMap": {
                            "name": "kube-root-ca.crt",
                            "items": [{"key": "ca.crt", "path": "ca.crt"}],
                        }
                    },
                    {
                        "downwardAPI": {
                            "items": [
                                {
                                    "path": "namespace",
                                    "fieldRef": {
                                        "apiVersion": "v1",
                                        "fieldPath": "metadata.namespace",
                                    },
                                }
                            ]
                        }
                    },
                ],
            },
        }
    )
    container = spec["containers"][0]
    container["volumeMounts"].append(
        {
            "name": "kube-api",
            "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
            "readOnly": True,
        }
    )
    inputs = {
        **ipc_pair_environment(settings, pair),
        "ADS_SANDBOX_IPC_ADS_SERVICE_SUBJECT": str(ads_service_subject),
        "ADS_SANDBOX_IPC_GUEST_POD_NAME": pair_name(pair, "guest"),
        "ADS_SANDBOX_IPC_GUEST_POD_UID": guest_uid,
        "ADS_SANDBOX_IPC_ATTACHMENT_GENERATION": str(pair.generation),
    }
    # Explicit entries override shared envFrom, never the other way around.
    if set(inputs) & {entry["name"] for entry in container["env"]}:
        raise RuntimeError("immutable IPC environment conflicts with baseline")
    container["env"].extend({"name": name, "value": value} for name, value in inputs.items())
    return {"apiVersion": "v1", "kind": "Pod", "metadata": deployment["metadata"], "spec": spec}
