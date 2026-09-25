from pathlib import Path

import yaml


def test_manager_cleanup_is_namespace_scoped_and_cluster_observation_stays_read_only():
    template = Path(__file__).parents[3] / "charts/ads/templates/sandbox-rbac.yaml"
    # These RBAC documents contain only the two namespace substitutions. Real Helm
    # rendering remains in charts/ads/tests, run by the separate Helm CI job.
    selected = template.read_text().split("---")
    role = next(d for d in selected if "kind: Role\n" in d and "name: ads-sandbox-manager\n" in d)
    cluster = next(d for d in selected if "kind: ClusterRole\n" in d)
    binding = next(d for d in selected if "kind: ClusterRoleBinding\n" in d)
    docs = [
        yaml.safe_load(
            d.replace("{{ .Values.namespace }}", "ads").replace(
                "{{ .Values.sandbox.namespace }}", "ads-sandbox"
            )
        )
        for d in (role, cluster, binding)
    ]
    permissions = {
        (group, resource): rule["verbs"]
        for rule in docs[0]["rules"] + docs[1]["rules"]
        for group in rule["apiGroups"]
        for resource in rule["resources"]
    }
    assert permissions == {
        ("batch", "jobs"): ["create", "delete", "get", "list", "watch"],
        ("apps", "deployments"): ["create", "delete", "get", "list", "watch"],
        ("", "persistentvolumeclaims"): ["create", "delete", "get", "list", "watch"],
        ("", "pods"): ["create", "get", "list", "delete"],
        ("", "services"): ["create", "get", "delete"],
        ("networking.k8s.io", "networkpolicies"): ["create", "get", "delete"],
        ("scheduling.k8s.io", "podgroups"): ["create", "get", "delete"],
        ("", "secrets"): ["create", "get", "delete"],
        ("", "persistentvolumes"): ["get"],
        ("", "nodes"): ["get"],
        ("storage.k8s.io", "volumeattachments"): ["list"],
        ("storage.k8s.io", "storageclasses"): ["get"],
    }
    assert docs[0]["metadata"]["namespace"] == "ads-sandbox"
    assert all(set(rule["verbs"]) <= {"get", "list", "watch"} for rule in docs[1]["rules"])
    assert all("pods" not in rule["resources"] for rule in docs[1]["rules"])
    assert docs[2]["subjects"] == [
        {"kind": "ServiceAccount", "name": "ads-sandbox-manager", "namespace": "ads"}
    ]
