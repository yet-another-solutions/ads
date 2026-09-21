from __future__ import annotations

from copy import deepcopy

from ads_sandbox_manager.config import Settings, size_bytes
from ads_sandbox_manager.objects import COMPONENT, JOB_UID, Object

CA_NAME = "ads-sandbox-ca"
CA_FORMAT = "ads.io/ca-format"
CA_ROLE = "ads.io/ca-role"
CA_ROLES = ("public", "private")
JOB_UID_FIELD = "metadata.labels['batch.kubernetes.io/controller-uid']"


def ca_metadata(settings: Settings, role: str | None = None) -> Object:
    labels = {COMPONENT: CA_NAME, CA_FORMAT: "1"}
    if role is not None:
        if role not in CA_ROLES:
            raise ValueError("invalid CA output role")
        labels[CA_ROLE] = role
    return {
        "name": CA_NAME if role is None else f"{CA_NAME}-{role}",
        "namespace": settings.namespace,
        "labels": labels,
    }


def ca_pvc(settings: Settings, role: str, attempt: str) -> Object:
    if settings.ca is None:
        raise ValueError("CA inputs are required")
    meta = ca_metadata(settings, role)
    meta["labels"][JOB_UID] = attempt
    return {
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": meta,
        "spec": {
            "storageClassName": "sandbox-block",
            "volumeMode": "Block",
            "accessModes": ["ReadWriteOnce"],
            "resources": {"requests": {"storage": str(size_bytes(settings.ca.source_size))}},
        },
    }


def ca_job(settings: Settings) -> Object:
    ca = settings.ca
    if ca is None:
        raise ValueError("CA inputs are required")
    meta = ca_metadata(settings)
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": meta,
        "spec": {
            "completions": 1,
            "parallelism": 1,
            "backoffLimit": 0,
            "activeDeadlineSeconds": ca.deadline_seconds,
            # Stable name, no release tag in identity, no TTL or ownerRefs on output PVCs.
            "template": {
                "metadata": {"labels": deepcopy(meta["labels"])},
                "spec": {
                    # Deliberately no runtimeClassName: normal container runtime, not Kata.
                    "restartPolicy": "Never",
                    "nodeSelector": deepcopy(settings.node_selector),
                    "tolerations": deepcopy(settings.tolerations),
                    "imagePullSecrets": [{"name": name} for name in settings.image_pull_secrets],
                    "automountServiceAccountToken": False,
                    "enableServiceLinks": False,
                    "dnsPolicy": "None",
                    "dnsConfig": {"nameservers": ["127.0.0.1"]},
                    "containers": [
                        {
                            "name": "ca",
                            "image": ca.image,
                            "env": [
                                {
                                    "name": "ADS_CA_ATTEMPT",
                                    "valueFrom": {"fieldRef": {"fieldPath": JOB_UID_FIELD}},
                                },
                                {"name": "ADS_CA_BYTES", "value": str(size_bytes(ca.source_size))},
                            ],
                            "resources": deepcopy(ca.resources),
                            "securityContext": {
                                "runAsUser": 0,
                                "privileged": False,
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"], "add": ["SYS_ADMIN"]},
                                "seccompProfile": {"type": "RuntimeDefault"},
                            },
                            "volumeDevices": [
                                {"name": role, "devicePath": f"/dev/ads-ca-{role}"}
                                for role in CA_ROLES
                            ],
                            "volumeMounts": [
                                {"name": "signer", "mountPath": "/signer", "readOnly": True},
                                {
                                    "name": "additional",
                                    "mountPath": "/additional",
                                    "readOnly": True,
                                },
                                {"name": "outputs", "mountPath": "/outputs"},
                                {"name": "tmp", "mountPath": "/tmp"},
                            ],
                        }
                    ],
                    "volumes": [
                        *[
                            {
                                "name": role,
                                "persistentVolumeClaim": {"claimName": f"{CA_NAME}-{role}"},
                            }
                            for role in CA_ROLES
                        ],
                        {
                            "name": "signer",
                            "secret": {
                                "secretName": ca.signing_secret,
                                "defaultMode": 0o400,
                                "items": [
                                    {"key": "tls.crt", "path": "tls.crt"},
                                    {"key": "tls.key", "path": "tls.key"},
                                ],
                            },
                        },
                        {
                            "name": "additional",
                            "configMap": {
                                "name": ca.additional_configmap,
                                "items": [{"key": "ca.crt", "path": "ca.crt"}],
                            },
                        },
                        {"name": "outputs", "emptyDir": {"medium": "Memory", "sizeLimit": "16Mi"}},
                        {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "16Mi"}},
                    ],
                },
            },
        },
    }
