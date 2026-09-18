from __future__ import annotations

import json
from dataclasses import asdict, replace
from uuid import uuid4

import pytest

from ads_sandbox_manager.config import SessionSettings, load_settings
from ads_sandbox_manager.session_objects import (
    SANDBOX,
    SESSION,
    guest_deployment,
    ipc_deployment,
    ipc_name,
    ipc_pvc,
    session_name,
    session_pvc,
)
from test_manager_config import configure, manager_tls  # noqa: F401


@pytest.fixture
def object_settings(manager_settings):
    return replace(
        manager_settings,
        session_objects=SessionSettings(
            guest_image="registry.test/ads-sandbox-base:0.0.10",
            ipc_image="registry.test/ads-sandbox-ipc:0.0.10",
            ipc_storage_class="application-disks",
            ipc_service_account="sandbox-ipc",
            ipc_config_map="ipc-config",
            ipc_secret="ipc-credentials",
            ipc_tls_secret="ipc-tls",
            ipc_ca_secret="lab-ca",
            ipc_node_selector={"ads.io/application-node": "true"},
            guest_resources={"limits": {"cpu": "2", "memory": "2Gi"}},
            ipc_resources={"limits": {"cpu": "1", "memory": "256Mi"}},
        ),
        tolerations=[{"key": "sandbox", "operator": "Exists", "effect": "NoSchedule"}],
        image_pull_secrets=("registry-pull",),
    )


def test_four_object_names_storage_and_no_ownership_gc(object_settings):
    s, session, sandbox, pvc_id = object_settings, uuid4(), uuid4(), uuid4()
    disk = session_pvc(s, session, sandbox, s.golden_version, "23622320128", pvc_id)
    ipc_disk = ipc_pvc(s, session, sandbox, s.golden_version)
    guest = guest_deployment(s, session, sandbox, s.golden_version, pvc_id)
    ipc = ipc_deployment(s, session, sandbox, s.golden_version)
    assert disk["metadata"]["name"] == session_name(pvc_id)
    assert pvc_id != session
    assert guest["metadata"]["name"] == session_name(sandbox)
    assert ipc_disk["metadata"]["name"] == ipc["metadata"]["name"] == ipc_name(sandbox)
    for obj in (disk, ipc_disk, guest, ipc):
        assert obj["metadata"]["labels"][SESSION] == str(session)
        assert obj["metadata"]["labels"][SANDBOX] == str(sandbox)
        assert "ownerReferences" not in obj["metadata"]
    assert disk["spec"]["dataSource"] == {
        "apiGroup": "",
        "kind": "PersistentVolumeClaim",
        "name": s.golden_name,
    }
    assert disk["spec"]["resources"]["requests"]["storage"] == "23622320128"
    assert disk["spec"]["volumeMode"] == "Block"
    assert disk["spec"]["storageClassName"] == "sandbox-block"
    assert ipc_disk["spec"]["volumeMode"] == "Filesystem"
    assert ipc_disk["spec"]["storageClassName"] == "application-disks"
    assert "dataSource" not in ipc_disk["spec"]


def test_guest_airgap_and_ipc_identity_are_separate(object_settings):
    s, session, sandbox, pvc_id = object_settings, uuid4(), uuid4(), uuid4()
    guest = guest_deployment(s, session, sandbox, s.golden_version, pvc_id)
    ipc = ipc_deployment(s, session, sandbox, s.golden_version)
    for obj in (guest, ipc):
        assert obj["spec"]["replicas"] == 1
        assert obj["spec"]["strategy"] == {"type": "Recreate"}
        template = obj["spec"]["template"]
        assert template["metadata"]["labels"][SANDBOX] == str(sandbox)
        assert "annotations" not in template["metadata"]
    g = guest["spec"]["template"]["spec"]
    i = ipc["spec"]["template"]["spec"]
    assert g["nodeSelector"] == s.node_selector
    assert g["tolerations"] == s.tolerations
    assert i["nodeSelector"] == s.session_objects.ipc_node_selector
    assert g["runtimeClassName"] == "kata-qemu"
    assert not g["automountServiceAccountToken"] and not g["enableServiceLinks"]
    assert g["dnsPolicy"] == "None" and g["dnsConfig"] == {"nameservers": ["127.0.0.1"]}
    assert g["volumes"] == [
        {
            "name": "session",
            "persistentVolumeClaim": {"claimName": session_name(pvc_id)},
        }
    ]
    container = g["containers"][0]
    assert container["name"] == "sandbox"
    assert container["volumeDevices"] == [{"name": "session", "devicePath": "/dev/ads-session"}]
    assert container["securityContext"] == {
        "runAsUser": 0,
        "privileged": False,
        "allowPrivilegeEscalation": False,
        "capabilities": {"add": ["SYS_ADMIN"]},
    }
    assert container["readinessProbe"]["exec"]["command"] == [
        "test",
        "-f",
        "/run/ads-sandbox-ready",
    ]
    assert not {"command", "args", "ports", "volumeMounts", "envFrom"} & container.keys()
    assert len(container["env"]) == 1
    assert i["automountServiceAccountToken"]
    assert i["serviceAccountName"] == "sandbox-ipc"
    assert "runtimeClassName" not in i
    assert i["securityContext"]["fsGroup"] == 1000
    c = i["containers"][0]
    env = {e["name"]: e["value"] for e in c["env"]}
    assert env["ADS_SANDBOX_IPC_SANDBOX_ID"] == str(sandbox)
    assert env["ADS_SANDBOX_IPC_PID_DIRECTORY"] == "/var/lib/ads-sandbox-ipc"
    assert env["ADS_SANDBOX_IPC_TLS_CA_BUNDLE"] == "/ca/ca.crt"
    assert c["envFrom"] == [
        {"configMapRef": {"name": "ipc-config"}},
        {"secretRef": {"name": "ipc-credentials"}},
    ]
    for probe in ("livenessProbe", "readinessProbe"):
        assert c[probe]["httpGet"]["scheme"] == "HTTPS"
    assert c["resources"] == s.session_objects.ipc_resources
    assert container["resources"] == s.session_objects.guest_resources


def test_builders_do_not_mutate_helm_inputs_and_ca_is_optional(object_settings):
    s = replace(
        object_settings,
        session_objects=replace(
            object_settings.session_objects,
            ipc_ca_secret=None,
        ),
    )
    before = asdict(s)
    guest = guest_deployment(s, uuid4(), uuid4(), s.golden_version, uuid4())
    guest["spec"]["template"]["spec"]["nodeSelector"]["mutated"] = "true"
    ipc = ipc_deployment(s, uuid4(), uuid4(), s.golden_version)
    assert not any(v["name"] == "ca" for v in ipc["spec"]["template"]["spec"]["volumes"])
    assert before == asdict(s)


@pytest.mark.parametrize(
    "field,value",
    [
        ("guest_image", ""),
        ("ipc_image", " "),
        ("ipc_storage_class", "sandbox-block"),
        ("ipc_service_account", "../foreign"),
        ("ipc_secret", ""),
        ("ipc_size", "0"),
        ("create_seconds", 0),
        ("create_seconds", float("nan")),
        ("ipc_node_selector", {}),
        ("ipc_node_selector", {"x": 1}),
        ("ipc_resources", []),
        ("ipc_tolerations", {}),
    ],
)
def test_object_configuration_rejects_invalid_inputs(object_settings, field, value):
    with pytest.raises(ValueError):
        replace(object_settings.session_objects, **{field: value})


def test_load_session_object_configuration(monkeypatch, manager_tls, object_settings):  # noqa: F811
    configure(monkeypatch, manager_tls)
    monkeypatch.setenv(
        "ADS_SANDBOX_MANAGER_SESSION_OBJECTS",
        json.dumps(
            asdict(object_settings.session_objects),
        ),
    )
    assert load_settings().session_objects == object_settings.session_objects
