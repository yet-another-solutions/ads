from __future__ import annotations

from copy import deepcopy
from uuid import UUID

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.objects import COMPONENT, VERSION, Object

SESSION = "ads.io/session-id"
SANDBOX = "ads.io/sandbox-id"


def session_name(session_id: UUID) -> str:
    return f"ads-sandbox-{session_id}"


def ipc_name(sandbox_id: UUID) -> str:
    return f"ads-sandbox-ipc-{sandbox_id}"


def labels(session_id: UUID, sandbox_id: UUID, version: str, component: str) -> Object:
    return {
        SESSION: str(session_id),
        SANDBOX: str(sandbox_id),
        VERSION: version,
        COMPONENT: component,
    }


def session_pvc(
    settings: Settings,
    session_id: UUID,
    sandbox_id: UUID,
    version: str,
    storage: str,
    pvc_id: UUID,
) -> Object:
    return {
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {
            "name": session_name(pvc_id),
            "namespace": settings.namespace,
            "labels": labels(session_id, sandbox_id, version, "ads-sandbox"),
        },
        # Never owner-reference the persistent disk to disposable compute.
        "spec": {
            "storageClassName": "sandbox-block",
            "volumeMode": "Block",
            "accessModes": ["ReadWriteOnce"],
            "resources": {"requests": {"storage": storage}},
            "dataSource": {
                "apiGroup": "",
                "kind": "PersistentVolumeClaim",
                "name": settings.golden_name,
            },
        },
    }


def ipc_pvc(settings: Settings, session_id: UUID, sandbox_id: UUID, version: str) -> Object:
    config = settings.session_objects
    assert config is not None
    return {
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {
            "name": ipc_name(sandbox_id),
            "namespace": settings.namespace,
            "labels": labels(session_id, sandbox_id, version, "ads-sandbox-ipc"),
        },
        "spec": {
            "storageClassName": config.ipc_storage_class,
            "volumeMode": "Filesystem",
            "accessModes": ["ReadWriteOnce"],
            "resources": {"requests": {"storage": config.ipc_size}},
        },
    }


def guest_deployment(
    settings: Settings,
    session_id: UUID,
    sandbox_id: UUID,
    version: str,
    pvc_id: UUID,
) -> Object:
    config = settings.session_objects
    assert config is not None
    pod_labels = labels(session_id, sandbox_id, version, "ads-sandbox")
    return _deployment(
        settings,
        session_name(sandbox_id),
        pod_labels,
        {
            "runtimeClassName": config.guest_runtime_class,
            "automountServiceAccountToken": False,
            "enableServiceLinks": False,
            "dnsPolicy": "None",
            # Kubernetes requires a nameserver for None. Loopback does not add a guest NIC.
            "dnsConfig": {"nameservers": ["127.0.0.1"]},
            "nodeSelector": deepcopy(settings.node_selector),
            "tolerations": deepcopy(settings.tolerations),
            "imagePullSecrets": [{"name": n} for n in settings.image_pull_secrets],
            "containers": [
                {
                    "name": "sandbox",
                    "image": config.guest_image,
                    "env": [
                        {"name": "ADS_SESSION_DEVICE", "value": "/dev/ads-session"},
                        *[
                            {"name": f"ADS_SANDBOX_{key}", "value": str(value)}
                            for key, value in sorted(config.guest_budget.items())
                        ],
                    ],
                    "resources": deepcopy(config.guest_resources),
                    "securityContext": {
                        "runAsUser": 0,
                        "privileged": False,
                        # Rootless Podman needs setuid newuidmap/newgidmap at bootstrap.
                        "allowPrivilegeEscalation": True,
                        "capabilities": {"add": ["SYS_ADMIN"]},
                    },
                    "volumeDevices": [{"name": "session", "devicePath": "/dev/ads-session"}],
                    "readinessProbe": {
                        "exec": {"command": ["test", "-f", "/run/ads-sandbox-ready"]},
                        "periodSeconds": 2,
                    },
                }
            ],
            "volumes": [
                {
                    "name": "session",
                    "persistentVolumeClaim": {"claimName": session_name(pvc_id)},
                }
            ],
        },
    )


def ipc_deployment(
    settings: Settings,
    session_id: UUID,
    sandbox_id: UUID,
    version: str,
) -> Object:
    config = settings.session_objects
    assert config is not None
    env = {
        "SANDBOX_ID": str(sandbox_id),
        "NAMESPACE": settings.namespace,
        "PID_DIRECTORY": "/var/lib/ads-sandbox-ipc",
        "TLS_CERT_PATH": "/tls/tls.crt",
        "TLS_KEY_PATH": "/tls/tls.key",
        "PORT": "8080",
    }
    volumes: list[Object] = [
        {"name": "pids", "persistentVolumeClaim": {"claimName": ipc_name(sandbox_id)}},
        {"name": "tls", "secret": {"secretName": config.ipc_tls_secret}},
    ]
    mounts: list[Object] = [
        {"name": "pids", "mountPath": env["PID_DIRECTORY"]},
        {"name": "tls", "mountPath": "/tls", "readOnly": True},
    ]
    if config.ipc_ca_secret:
        env["TLS_CA_BUNDLE"] = "/ca/ca.crt"
        volumes.append({"name": "ca", "secret": {"secretName": config.ipc_ca_secret}})
        mounts.append({"name": "ca", "mountPath": "/ca", "readOnly": True})
    return _deployment(
        settings,
        ipc_name(sandbox_id),
        labels(session_id, sandbox_id, version, "ads-sandbox-ipc"),
        {
            "automountServiceAccountToken": True,
            "enableServiceLinks": False,
            "serviceAccountName": config.ipc_service_account,
            "nodeSelector": deepcopy(config.ipc_node_selector),
            "tolerations": deepcopy(config.ipc_tolerations),
            "imagePullSecrets": [{"name": n} for n in settings.image_pull_secrets],
            "securityContext": {"runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 1000},
            "containers": [
                {
                    "name": "ipc",
                    "image": config.ipc_image,
                    "envFrom": [
                        {"configMapRef": {"name": config.ipc_config_map}},
                        {"secretRef": {"name": config.ipc_secret}},
                    ],
                    "env": [{"name": "ADS_SANDBOX_IPC_" + k, "value": v} for k, v in env.items()],
                    "volumeMounts": mounts,
                    "resources": deepcopy(config.ipc_resources),
                    "securityContext": {
                        "privileged": False,
                        "allowPrivilegeEscalation": False,
                        "capabilities": {"drop": ["ALL"]},
                    },
                    "ports": [{"name": "https", "containerPort": 8080}],
                    "livenessProbe": {
                        "httpGet": {"path": "/health/live", "port": "https", "scheme": "HTTPS"},
                    },
                    "readinessProbe": {
                        "httpGet": {"path": "/health/ready", "port": "https", "scheme": "HTTPS"},
                    },
                }
            ],
            "volumes": volumes,
        },
    )


def _deployment(settings: Settings, name: str, pod_labels: Object, spec: Object) -> Object:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": settings.namespace, "labels": pod_labels},
        "spec": {
            "replicas": 1,
            # No rolling surge: never introduce a second IPC consumer or guest writer.
            "strategy": {"type": "Recreate"},
            "selector": {
                "matchLabels": {
                    SANDBOX: pod_labels[SANDBOX],
                    COMPONENT: pod_labels[COMPONENT],
                }
            },
            "template": {"metadata": {"labels": deepcopy(pod_labels)}, "spec": spec},
        },
    }
