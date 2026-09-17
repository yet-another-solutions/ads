from __future__ import annotations

from copy import deepcopy
from typing import Any

from ads_sandbox_manager.config import Settings

Object = dict[str, Any]
VERSION = "ads.io/golden-version"
JOB_UID = "ads.io/golden-job-uid"
COMPONENT = "app.kubernetes.io/component"


def metadata(settings: Settings) -> Object:
    return {
        "name": settings.golden_name,
        "namespace": settings.namespace,
        "labels": {VERSION: settings.golden_version, COMPONENT: "ads-sandbox-golden"},
    }


def golden_job(settings: Settings) -> Object:
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": metadata(settings),
        "spec": {
            "completions": 1,
            "parallelism": 1,
            "backoffLimit": 0,
            "activeDeadlineSeconds": settings.bake_seconds,
            # Retain success evidence. No TTL: readiness and restart recovery need this Job.
            "template": {
                "metadata": {"labels": metadata(settings)["labels"]},
                "spec": {
                    "runtimeClassName": "kata-qemu",
                    "restartPolicy": "Never",
                    "nodeSelector": deepcopy(settings.node_selector),
                    "tolerations": deepcopy(settings.tolerations),
                    "automountServiceAccountToken": False,
                    "enableServiceLinks": False,
                    "dnsPolicy": "None",
                    # Required by API validation for dnsPolicy=None; not guest networking.
                    "dnsConfig": {"nameservers": ["127.0.0.1"]},
                    "imagePullSecrets": [{"name": name} for name in settings.image_pull_secrets],
                    "containers": [
                        {
                            "name": "golden",
                            "image": settings.golden_image,
                            "env": [
                                {"name": "ADS_SESSION_DEVICE", "value": "/dev/ads-session"},
                                {"name": "ADS_SESSION_SIZE", "value": settings.session_size},
                            ],
                            "resources": deepcopy(settings.resources),
                            "securityContext": {
                                "runAsUser": 0,
                                "privileged": False,
                                "allowPrivilegeEscalation": False,
                                "capabilities": {"add": ["SYS_ADMIN"]},
                            },
                            "volumeDevices": [
                                {"name": "session", "devicePath": "/dev/ads-session"}
                            ],
                        }
                    ],
                    "volumes": [
                        {
                            "name": "session",
                            "persistentVolumeClaim": {"claimName": settings.golden_name},
                        }
                    ],
                },
            },
        },
    }


def golden_pvc(settings: Settings, job_uid: str) -> Object:
    meta = metadata(settings)
    meta["labels"][JOB_UID] = job_uid
    # No owner reference: deleting a Job must never garbage-collect a good clone source.
    return {
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": meta,
        "spec": {
            "storageClassName": "sandbox-block",
            "volumeMode": "Block",
            "accessModes": ["ReadWriteOnce"],
            "resources": {"requests": {"storage": str(settings.golden_bytes)}},
        },
    }
