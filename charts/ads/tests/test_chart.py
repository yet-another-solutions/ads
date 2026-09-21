"""Exercise real Helm rendering and online lookups without a cluster or credentials."""

import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

import yaml

CHART = Path(__file__).resolve().parents[1]
HELM = os.environ.get("HELM_BIN", "helm")
VALUES = ("-f", str(CHART / "values-ci.yaml"))
CRD = "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/clusterpolicies.kyverno.io"
DEPLOYMENT = "/apis/apps/v1/namespaces/kyverno/deployments/kyverno-admission-controller"
SA = "/api/v1/namespaces/kyverno/serviceaccounts/kyverno-admission-controller"
BLOCK = "/apis/storage.k8s.io/v1/storageclasses/sandbox-block"
FILESYSTEM = "/apis/storage.k8s.io/v1/storageclasses/local-path"
SERVICES = "/api/v1/namespaces/default/services/"


def resource(kind, name, **fields):
    return {"apiVersion": "v1", "kind": kind, "metadata": {"name": name}, **fields}


def fixtures():
    """Only the resources the production prerequisite templates need."""
    return {
        "/api/v1/namespaces/kube-system": resource("Namespace", "kube-system"),
        "/api/v1/namespaces/default": resource("Namespace", "default"),
        "/api/v1/nodes": {
            "apiVersion": "v1",
            "kind": "NodeList",
            "items": [
                {
                    "metadata": {
                        "name": "application",
                        "labels": {"ads.io/application-node": "true"},
                    },
                    "status": {},
                },
                {
                    "metadata": {
                        "name": "sandbox",
                        "labels": {
                            "ads.io/sandbox-node": "true",
                            "katacontainers.io/kata-runtime": "true",
                        },
                    },
                    "status": {},
                },
            ],
        },
        "/apis/node.k8s.io/v1/runtimeclasses/kata-qemu": resource(
            "RuntimeClass", "kata-qemu", handler="kata-qemu"
        ),
        "/apis/node.k8s.io/v1/runtimeclasses/kata-qemu-ads": {
            **resource("RuntimeClass", "kata-qemu-ads", handler="kata-qemu-ads"),
            "metadata": {
                "name": "kata-qemu-ads",
                "annotations": {
                    "ads.io/runtime-contract": "nested-v1",
                },
            },
        },
        CRD: resource(
            "CustomResourceDefinition",
            "clusterpolicies.kyverno.io",
            status={"conditions": [{"type": "Established", "status": "True"}]},
        ),
        DEPLOYMENT: resource(
            "Deployment", "kyverno-admission-controller", status={"availableReplicas": 1}
        ),
        SA: resource("ServiceAccount", "kyverno-admission-controller"),
        BLOCK: resource("StorageClass", "sandbox-block", provisioner="fixture.csi"),
        FILESYSTEM: resource("StorageClass", "local-path", provisioner="fixture.csi"),
        SERVICES + "ads-redis": resource("Service", "ads-redis"),
        SERVICES + "ads-rabbitmq": resource("Service", "ads-rabbitmq"),
        SERVICES + "ads-postgres": resource("Service", "ads-postgres"),
    }


DISCOVERY = {
    "v1": [
        ("namespaces", "Namespace", False),
        ("nodes", "Node", False),
        ("serviceaccounts", "ServiceAccount", True),
        ("services", "Service", True),
    ],
    "apps/v1": [("deployments", "Deployment", True)],
    "apiextensions.k8s.io/v1": [("customresourcedefinitions", "CustomResourceDefinition", False)],
    "node.k8s.io/v1": [("runtimeclasses", "RuntimeClass", False)],
    "storage.k8s.io/v1": [("storageclasses", "StorageClass", False)],
}


class ChartTests(unittest.TestCase):
    def test_context_compactor_is_internal_tls_with_scoped_secret_and_engine_urls(self):
        docs = self.documents()
        name = "ads-context-compactor"
        pod = docs["Deployment", name]["spec"]["template"]["spec"]
        container = pod["containers"][0]
        self.assertEqual(container["name"], name)
        self.assertEqual(container["readinessProbe"]["httpGet"]["scheme"], "HTTPS")
        self.assertEqual(docs["Service", name]["spec"]["type"], "ClusterIP")
        self.assertEqual(
            container["env"][0]["valueFrom"]["secretKeyRef"],
            {"name": "ads-context-compactor-keycloak", "key": "client-secret"},
        )
        config = docs["ConfigMap", name]["data"]
        self.assertEqual(
            config["ADS_CONTEXT_COMPACTOR_METER_URL"], "https://ads-context-meter:8080/meter"
        )
        self.assertFalse(any("DATABASE" in k or "KAFKA" in k for k in config))
        engine = docs["ConfigMap", "ads-engine"]["data"]
        self.assertEqual(
            engine["ADS_ENGINE_CONTEXT_COMPACTOR_URL"], "https://ads-context-compactor:8080/compact"
        )
        self.assertEqual(engine["ADS_ENGINE_CONTEXT_TRIGGER"], "80")
        self.assertEqual(engine["ADS_ENGINE_CONTEXT_TARGET"], "50")
        for (kind, _), obj in docs.items():
            if kind in {"HTTPRoute", "Ingress"}:
                self.assertNotIn(name, json.dumps(obj))

    def test_context_meter_is_one_internal_tls_deployment(self):
        docs = self.documents()
        name = "ads-context-meter"
        pod = docs["Deployment", name]["spec"]["template"]["spec"]
        self.assertEqual(len(pod["containers"]), 1)
        container = pod["containers"][0]
        self.assertEqual(container["name"], name)
        self.assertEqual(container["readinessProbe"]["httpGet"]["scheme"], "HTTPS")
        self.assertEqual(container["livenessProbe"]["httpGet"]["scheme"], "HTTPS")
        self.assertEqual(docs["Service", name]["spec"]["type"], "ClusterIP")
        self.assertNotIn(("Secret", name), docs)
        config = docs["ConfigMap", name]["data"]
        self.assertEqual(config["ADS_CONTEXT_METER_KEYCLOAK_AUDIENCE"], name)
        self.assertFalse(any("DATABASE" in key or "KAFKA" in key for key in config))
        cert = docs["Certificate", name]
        self.assertIn(name, cert["spec"]["dnsNames"])
        for (kind, _), obj in docs.items():
            if kind in {"HTTPRoute", "Ingress"}:
                self.assertNotIn(name, json.dumps(obj))

    def test_main_database_url_is_rendered_only_into_secret(self):
        url = "postgresql+psycopg://fixture:fixture@database/ads"
        rendered = self.render("--set", f"database.url={url}")
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        objects = [x for x in yaml.safe_load_all(rendered.stdout) if x]
        secret = next(
            x for x in objects if x["kind"] == "Secret" and x["metadata"]["name"] == "ads"
        )
        self.assertEqual(secret["stringData"]["ADS_DATABASE_URL"], url)
        for obj in objects:
            if obj["kind"] == "ConfigMap":
                self.assertNotIn(url, json.dumps(obj))

    def test_scoped_sasl_for_every_sandbox_component(self):
        for component in ("mcp", "ipc", "manager"):
            with self.subTest(component=component):
                args = ["--set", f"sandbox.{component}.kafka.securityProtocol=SASL_PLAINTEXT"]
                self.assertNotEqual(self.render(*args).returncode, 0)
                args += ["--set", f"sandbox.{component}.kafka.saslUsername=scoped-{component}"]
                self.assertNotEqual(self.render(*args).returncode, 0)
                existing = self.render(
                    *args, "--set", f"sandbox.{component}.existingSecret=external-credentials"
                )
                self.assertEqual(existing.returncode, 0, existing.stderr)
                args += ["--set", f"sandbox.{component}.kafka.saslPassword=fixture-password"]
                rendered = self.render(*args)
                self.assertEqual(rendered.returncode, 0, rendered.stderr)
                objects = list(yaml.safe_load_all(rendered.stdout))
                name = f"ads-sandbox-{component}"
                secret = next(
                    x
                    for x in objects
                    if x and x["kind"] == "Secret" and x["metadata"]["name"] == name
                )["stringData"]
                prefix = f"ADS_SANDBOX_{component.upper()}_"
                self.assertEqual(secret[prefix + "KAFKA_SASL_PASSWORD"], "fixture-password")
                self.assertEqual(secret[prefix + "KAFKA_SASL_USERNAME"], f"scoped-{component}")
                for obj in objects:
                    if obj and obj["kind"] == "ConfigMap":
                        self.assertNotIn("fixture-password", json.dumps(obj))
                        self.assertNotIn("KAFKA_SASL_PASSWORD", json.dumps(obj))
                config = next(
                    x
                    for x in objects
                    if x and x["kind"] == "ConfigMap" and x["metadata"]["name"] == name
                )["data"]
                self.assertEqual(config[prefix + "KAFKA_SECURITY_PROTOCOL"], "SASL_PLAINTEXT")

    def render(self, *args):
        return subprocess.run(
            [HELM, "template", "ads", str(CHART), "--namespace", "default", *VALUES, *args],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def online(self, objects, *args, forbidden=None):
        seen = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                path = urlsplit(self.path).path
                seen.append(path)
                code = 200
                if path == "/version":
                    body = {"major": "1", "minor": "36", "gitVersion": "v1.36.0"}
                elif path == "/api":
                    body = {"kind": "APIVersions", "versions": ["v1"]}
                elif path == "/apis":
                    body = {
                        "kind": "APIGroupList",
                        "groups": [
                            {
                                "name": gv.split("/")[0],
                                "versions": [{"groupVersion": gv, "version": "v1"}],
                                "preferredVersion": {"groupVersion": gv, "version": "v1"},
                            }
                            for gv in DISCOVERY
                            if gv != "v1"
                        ],
                    }
                elif path.removeprefix("/apis/").removeprefix("/api/") in DISCOVERY:
                    gv = path.removeprefix("/apis/").removeprefix("/api/")
                    body = {
                        "kind": "APIResourceList",
                        "groupVersion": gv,
                        "resources": [
                            {
                                "name": name,
                                "kind": kind,
                                "namespaced": namespaced,
                                "verbs": ["get", "list"],
                            }
                            for name, kind, namespaced in DISCOVERY[gv]
                        ],
                    }
                elif path == forbidden:
                    code = 403
                    body = {
                        "kind": "Status",
                        "apiVersion": "v1",
                        "status": "Failure",
                        "reason": "Forbidden",
                        "message": "fixture access forbidden",
                        "code": 403,
                    }
                elif path in objects:
                    body = objects[path]
                else:
                    code = 404
                    body = {
                        "kind": "Status",
                        "apiVersion": "v1",
                        "status": "Failure",
                        "reason": "NotFound",
                        "code": 404,
                    }
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with tempfile.TemporaryDirectory() as directory:
                    config = Path(directory) / "kubeconfig"
                    config.write_text(
                        json.dumps(
                            {
                                "apiVersion": "v1",
                                "kind": "Config",
                                "clusters": [
                                    {
                                        "name": "fixture",
                                        "cluster": {
                                            "server": f"http://127.0.0.1:{server.server_port}"
                                        },
                                    }
                                ],
                                "contexts": [
                                    {"name": "fixture", "context": {"cluster": "fixture"}}
                                ],
                                "current-context": "fixture",
                            }
                        )
                    )
                    config.chmod(0o600)
                    result = self.render("--dry-run=server", "--kubeconfig", str(config), *args)
            finally:
                server.shutdown()
                thread.join()
        self.assertIn("/api/v1/namespaces/kube-system", seen)
        return result

    def test_namespaces_and_all_application_objects(self):
        for app, sandbox in [("ads", "ads-sandbox"), ("custom-app", "custom-sandbox")]:
            with self.subTest(app=app):
                result = self.render("--set", f"namespace={app},sandbox.namespace={sandbox}")
                self.assertEqual(result.returncode, 0, result.stderr)
                namespace_names = []
                for doc in result.stdout.split("\n---"):
                    kind = re.search(r"^kind: (\w+)$", doc, re.M)
                    if not kind:
                        continue
                    metadata = re.search(r"^metadata:\n((?:[ \t].*\n)+)", doc, re.M)[1]
                    if kind[1] == "Namespace":
                        namespace_names.append(re.search(r'  name: "?([^"\n]+)', metadata)[1])
                        self.assertNotIn("resource-policy", metadata)
                    elif kind[1] in ("ClusterPolicy", "ClusterRole", "ClusterRoleBinding"):
                        self.assertNotIn("namespace:", metadata)
                    else:
                        namespace = re.search(r'  namespace: "?([^"\n]+)', metadata)[1]
                        self.assertIn(namespace, [app, sandbox])
                        if kind[1] in [
                            "Deployment",
                            "Service",
                            "Secret",
                            "ConfigMap",
                            "Certificate",
                            "HTTPRoute",
                            "BackendTLSPolicy",
                        ]:
                            expected = sandbox if "sandbox-ipc" in metadata else app
                            self.assertEqual(namespace, expected)
                self.assertCountEqual(namespace_names, [app, sandbox])
                self.assertIn(f"ads.{app}.svc.cluster.local", result.stdout)
                self.assertIn(f"ads-preferences.{app}.svc.cluster.local", result.stdout)
                self.assertNotIn("resource-policy: keep", result.stdout)
                self.assertIn(f"/namespaces/{sandbox}/pods/", result.stdout)
                self.assertIn("failurePolicy: Fail", result.stdout)
                self.assertIn("validationFailureAction: Enforce", result.stdout)
                self.assertIn("{{ request.", result.stdout)
                self.assertIn("authentication.kubernetes.io/pod-uid", result.stdout)

    def test_custom_admission_settings_and_manager_subject(self):
        result = self.render(
            "--set",
            "namespace=custom-app,sandbox.namespace=custom-sandbox",
            "--set",
            "sandbox.admission.kyvernoNamespace=policy-system",
            "--set",
            "sandbox.admission.serviceAccountName=admission-sa",
            "--set",
            "sandbox.admission.policyName=custom-exec",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("name: custom-exec", result.stdout)
        self.assertIn("name: admission-sa\n    namespace: policy-system", result.stdout)
        self.assertIn("name: ads-sandbox-manager\n    namespace: custom-app", result.stdout)
        self.assertIn("name: ads-sandbox-ipc\n    namespace: custom-sandbox", result.stdout)

    def test_reject_unsafe_namespace_layouts(self):
        for value in [
            "namespace=default",
            "sandbox.namespace=default",
            "namespace=kyverno",
            "sandbox.namespace=kube-system",
            "sandbox.namespace=ads",
            "namespace=",
        ]:
            with self.subTest(value=value):
                self.assertNotEqual(self.render("--set", value).returncode, 0)
        result = self.render("--namespace", "ads")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("use --namespace default", result.stderr)

    def test_online_ready(self):
        result = self.online(fixtures())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_guest_runtime_contract_required(self):
        path = "/apis/node.k8s.io/v1/runtimeclasses/kata-qemu-ads"
        for missing in (True, False):
            objects = fixtures()
            if missing:
                del objects[path]
            else:
                del objects[path]["metadata"]["annotations"]
            result = self.online(objects)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("guest RuntimeClass", result.stderr)

    def test_string_budget_is_normalized_to_integer_json(self):
        result = self.render("--set-string", "sandbox.guest.budget.CPU_MILLIS=600")
        self.assertEqual(result.returncode, 0, result.stderr)
        docs = list(yaml.safe_load_all(result.stdout))
        manager = next(
            doc
            for doc in docs
            if doc
            and doc.get("kind") == "ConfigMap"
            and "ADS_SANDBOX_MANAGER_SESSION_OBJECTS" in doc.get("data", {})
        )
        settings = json.loads(manager["data"]["ADS_SANDBOX_MANAGER_SESSION_OBJECTS"])
        self.assertEqual(settings["guest_budget"]["CPU_MILLIS"], 600)
        self.assertIsInstance(settings["guest_budget"]["CPU_MILLIS"], int)

    def test_online_custom_admission_installation(self):
        objects = fixtures()
        objects["/apis/apps/v1/namespaces/policy-system/deployments/admission"] = objects.pop(
            DEPLOYMENT
        )
        objects["/api/v1/namespaces/policy-system/serviceaccounts/admission"] = objects.pop(SA)
        result = self.online(
            objects,
            "--set",
            "sandbox.admission.kyvernoNamespace=policy-system",
            "--set",
            "sandbox.admission.deploymentName=admission",
            "--set",
            "sandbox.admission.serviceAccountName=admission",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_kyverno_check_is_not_gated_by_nodes(self):
        objects = fixtures()
        del objects["/api/v1/nodes"]
        del objects[CRD]
        result = self.online(objects)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing clusterpolicies.kyverno.io CRD", result.stderr)

    def test_missing_prerequisites(self):
        for path, message in [
            (CRD, "missing clusterpolicies.kyverno.io CRD"),
            (DEPLOYMENT, "requires Kyverno admission Deployment"),
            (SA, "requires the configured Kyverno admission ServiceAccount"),
            ("/api/v1/namespaces/default", "release namespace must already exist"),
            (BLOCK, "requires existing StorageClass sandbox-block"),
            (FILESYSTEM, "requires existing StorageClass local-path"),
        ]:
            with self.subTest(path=path):
                objects = fixtures()
                del objects[path]
                result = self.online(objects)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)

    def test_unready_and_status_absent(self):
        for path, status, message in [
            (CRD, {}, "established Kyverno"),
            (
                CRD,
                {"conditions": [{"type": "Established", "status": "False"}]},
                "established Kyverno",
            ),
            (DEPLOYMENT, {}, "available Kyverno admission"),
            (DEPLOYMENT, {"availableReplicas": 0}, "available Kyverno admission"),
        ]:
            with self.subTest(path=path, status=status):
                objects = fixtures()
                objects[path]["status"] = status
                result = self.online(objects)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)

    def test_forbidden_lookup_fails_closed(self):
        for path in ["/api/v1/namespaces/kube-system", CRD, DEPLOYMENT, SA, BLOCK, FILESYSTEM]:
            with self.subTest(path=path):
                result = self.online(fixtures(), forbidden=path)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("fixture access forbidden", result.stderr)

    def documents(self, *args):
        result = self.render(*args)
        self.assertEqual(result.returncode, 0, result.stderr)
        return {
            (doc["kind"], doc["metadata"]["name"]): doc
            for doc in yaml.safe_load_all(result.stdout)
            if doc
        }

    def test_the_auditor_logs_in_to_the_journal_on_its_own_host(self):
        docs = self.documents()
        config = docs["ConfigMap", "ads-audit"]["data"]
        self.assertEqual(config["ADS_KEYCLOAK_CLIENT_ID"], "ads-audit")
        self.assertEqual(config["ADS_KEYCLOAK_AUDIENCE"], "ads-audit")
        self.assertEqual(config["ADS_KEYCLOAK_AUDITOR_ROLE"], "auditor")
        self.assertEqual(config["ADS_PUBLIC_BASE_URL"], "https://ads-audit.interlab")
        self.assertNotIn("SECRET", json.dumps(config))
        secret = docs["Secret", "ads-audit"]["stringData"]
        self.assertEqual(secret["ADS_KEYCLOAK_CLIENT_SECRET"], "ci-audit-client-secret")
        self.assertIn("ADS_SESSION_SECRET", secret)
        route = docs["HTTPRoute", "ads-audit"]["spec"]
        self.assertEqual(route["hostnames"], ["ads-audit.interlab"])
        self.assertEqual(route["rules"][0]["backendRefs"][0]["name"], "ads-audit")
        tls = docs["BackendTLSPolicy", "ads-audit"]["spec"]["validation"]
        self.assertEqual(tls["hostname"], "ads-audit.interlab")
        certificate = docs["Certificate", "ads-audit"]["spec"]
        self.assertIn("ads-audit.interlab", certificate["dnsNames"])

    def test_the_auditor_needs_its_own_client_secret_and_session_secret(self):
        for missing in ["secrets.auditKeycloakClientSecret", "secrets.auditSessionSecret"]:
            with self.subTest(missing=missing):
                result = self.render("--set", f"{missing}=")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"{missing} is required", result.stderr)

    def test_the_sandbox_is_reached_through_the_guardrail_and_only_through_it(self):
        governed = [
            "--set",
            "guardrail.enabled=true,tls.caBundle.secretName=lab-ca",
            "--set",
            "engine.workspace.project=ads,engine.workspace.repo=r,engine.workspace.env=test",
        ]
        docs = self.documents(*governed)
        engine = docs["ConfigMap", "ads-engine"]["data"]
        self.assertEqual(engine["ADS_ENGINE_MCP_URL"], "https://ads-guardrail:8083/mcp/sandbox")
        self.assertEqual(engine["ADS_ENGINE_GUARDRAIL_URL"], "https://ads-guardrail:8083")
        self.assertEqual(engine["ADS_ENGINE_WORKSPACE_PROJECT"], "ads")
        mcp = docs["ConfigMap", "ads-sandbox-mcp"]["data"]
        self.assertEqual(mcp["ADS_SANDBOX_MCP_ALLOWED_CALLERS"], "ads-guardrail")
        guardrail = docs["ConfigMap", "ads-guardrail"]["data"]
        servers = {server["name"]: server for server in json.loads(guardrail["ADS_MCP_SERVERS"])}
        self.assertEqual(servers["sandbox"]["audience"], "ads-sandbox-mcp")
        self.assertEqual(servers["sandbox"]["url"], "https://ads-sandbox-mcp:8080/mcp")
        self.assertEqual(servers["sandbox"]["site"]["runtime_class_name"], "kata-qemu-ads")
        self.assertIn("ADS_KEYCLOAK_CLIENT_SECRET", docs["Secret", "ads-guardrail"]["stringData"])

    def test_the_engine_mints_its_credential_for_the_audience_the_guardrail_accepts(self):
        docs = self.documents(
            "--set",
            "guardrail.enabled=true,tls.caBundle.secretName=lab-ca",
            "--set",
            "engine.workspace.project=ads,engine.workspace.repo=r,engine.workspace.env=test",
            "--set",
            "guardrail.personTokenAudience=ads-guardrail",
        )
        engine = docs["ConfigMap", "ads-engine"]["data"]
        guardrail = docs["ConfigMap", "ads-guardrail"]["data"]
        self.assertEqual(engine["ADS_ENGINE_GUARDRAIL_AUDIENCE"], "ads-guardrail")
        self.assertEqual(engine["ADS_ENGINE_GUARDRAIL_AUDIENCE"], guardrail["ADS_MCP_AUDIENCE"])

    def test_without_a_guardrail_the_engine_reaches_the_sandbox_itself(self):
        docs = self.documents()
        engine = docs["ConfigMap", "ads-engine"]["data"]
        self.assertEqual(engine["ADS_ENGINE_MCP_URL"], "https://ads-sandbox-mcp:8080/mcp")
        self.assertNotIn("ADS_ENGINE_GUARDRAIL_URL", engine)
        self.assertNotIn(
            "ADS_SANDBOX_MCP_ALLOWED_CALLERS", docs["ConfigMap", "ads-sandbox-mcp"]["data"]
        )

    def test_storage_lookup_independent_of_node_list(self):
        objects = fixtures()
        del objects["/api/v1/nodes"]
        del objects[BLOCK]
        result = self.online(objects)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires existing StorageClass sandbox-block", result.stderr)

    def test_custom_filesystem_class(self):
        objects = fixtures()
        objects["/apis/storage.k8s.io/v1/storageclasses/app-disk"] = objects.pop(FILESYSTEM)
        result = self.online(objects, "--set", "sandbox.ipc.storageClass=app-disk")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_invalid_values_fail_offline(self):
        for value in [
            "sandbox.golden.slack=0",
            "sandbox.golden.slack=1Gi",
            "sandbox.golden.slack=2047Mi",
            "sandbox.golden.slack=2G",
            "sandbox.golden.slack=-2Gi",
            "sandbox.golden.slack=2.5Gi",
            "sandbox.golden.slack=999999999999999999999Gi",
            "sandbox.golden.slack=9223372036854775807",
            "sandbox.sessionSize=30Gi",
            "sandbox.ipc.storageClass=sandbox-block",
            "sandbox.ipc.storageClass=",
            "sandbox.ipc.size=0",
            "sandbox.manager.idleSeconds=0",
            "sandbox.manager.detachedSeconds=-1",
            "sandbox.manager.lifecycleBatch=0",
            "sandbox.manager.pvcTimeoutSeconds=0",
            "sandbox.manager.pingTimeoutSeconds=10",
            "sandbox.manager.recoverySeconds=120",
            "sandbox.manager.replicaCount=1.5",
            "sandbox.manager.bakeSeconds=1.5",
            "sandbox.mcp.port=65536",
            "engine.mcpTimeoutSeconds=0",
            "engine.maxToolCalls=0",
            "engine.maxToolCalls=1.5",
            "sandbox.mcp.stdoutBytes=0",
            "sandbox.ipc.ackSeconds=0",
            "sandbox.ipc.timeoutSeconds=NaN",
            "sandbox.manager.kafka.securityProtocol=SASL_SSL",
            "sandbox.manager.kafka.securityProtocol=unknown",
            "nodes.sandbox.runtimeClassName=other-kata",
            "sandbox.guest.runtimeClassName=../bad",
            "sandbox.guest.budget.PIDS=0",
            "sandbox.guest.budget.MAX_DEPTH=-1",
            "sandbox.guest.budget.CPU_MILLIS=1000",
            "sandbox.guest.budget.MEMORY_BYTES=1610612736",
            "sandbox.guest.budget.MEMORY_BYTES=4097",
            "sandbox.guest.resources.limits.cpu=0",
            "sandbox.guest.resources.limits.memory=0",
        ]:
            with self.subTest(value=value):
                self.assertNotEqual(self.render("--set", value).returncode, 0)

    def test_valid_slack_quantities(self):
        for value in ["2Gi", "2048Mi", "2147483648", "3G"]:
            with self.subTest(value=value):
                result = self.render("--set", f"sandbox.golden.slack={value}")
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_service_wiring_and_no_infrastructure(self):
        docs = self.documents()
        forbidden = {
            "StorageClass",
            "RuntimeClass",
            "PersistentVolumeClaim",
            "Job",
            "StatefulSet",
            "Keycloak",
            "KeycloakRealmImport",
        }
        self.assertFalse({kind for kind, _ in docs} & forbidden)
        self.assertEqual(sum(kind == "Deployment" for kind, _ in docs), 10)
        self.assertNotIn(("Deployment", "ads-sandbox-ipc"), docs)
        for component in ["mcp", "manager"]:
            deployment = docs["Deployment", f"ads-sandbox-{component}"]
            pod = deployment["spec"]["template"]["spec"]
            self.assertEqual(pod["nodeSelector"]["ads.io/application-node"], "true")
            self.assertEqual(pod["automountServiceAccountToken"], component == "manager")
            container = pod["containers"][0]
            for probe in ["livenessProbe", "readinessProbe"]:
                self.assertEqual(container[probe]["httpGet"]["scheme"], "HTTPS")
        manager = docs["Deployment", "ads-sandbox-manager"]["spec"]["template"]["spec"]
        self.assertEqual(manager["serviceAccountName"], "ads-sandbox-manager")
        engine = docs["ConfigMap", "ads-engine"]["data"]
        self.assertEqual(engine["ADS_ENGINE_MCP_URL"], "https://ads-sandbox-mcp:8080/mcp")
        self.assertEqual(engine["ADS_ENGINE_MAX_TOOL_CALLS"], "32")
        service = docs["Service", "ads-sandbox-mcp"]
        self.assertEqual(service["spec"]["type"], "ClusterIP")
        self.assertEqual(service["spec"]["ports"][0]["port"], 8080)
        routes = [doc for (kind, _), doc in docs.items() if kind == "HTTPRoute"]
        self.assertNotIn("sandbox", json.dumps(routes))
        config = docs["ConfigMap", "ads-sandbox-manager"]["data"]
        self.assertEqual(config["ADS_SANDBOX_MANAGER_IDLE_SECONDS"], "1800")
        self.assertEqual(config["ADS_SANDBOX_MANAGER_DETACHED_SECONDS"], "7200")
        self.assertEqual(config["ADS_SESSION_SIZE"], "20Gi")
        self.assertEqual(config["ADS_SANDBOX_MANAGER_GOLDEN_VERSION"], "v0.0.1")
        self.assertNotIn("KEYCLOAK_CLIENT_SECRET", json.dumps(config))

    def test_overrides_reach_real_settings_and_object_builders(self):
        from uuid import uuid4

        from ads_sandbox_ipc.config import load_settings as ipc_settings
        from ads_sandbox_manager.config import load_settings as manager_settings
        from ads_sandbox_manager.objects import golden_job, golden_pvc
        from ads_sandbox_manager.session_objects import guest_deployment, ipc_deployment
        from ads_sandbox_mcp.config import load_settings as mcp_settings

        docs = self.documents(
            "--set",
            "fullnameOverride=custom,namespace=app,sandbox.namespace=guests",
            "--set",
            "sandbox.manager.idleSeconds=99,sandbox.manager.detachedSeconds=999",
            "--set",
            "sandbox.manager.lifecycleBatch=7,sandbox.manager.pvcTimeoutSeconds=87",
            "--set",
            "sandbox.manager.pingIntervalSeconds=12,sandbox.manager.pingTimeoutSeconds=40",
            "--set",
            "sandbox.golden.slack=3Gi,sandbox.ipc.size=2Gi",
            "--set",
            "sandbox.mcp.port=8443,sandbox.ipc.caSecretName=guest-ca",
            "--set",
            "sandbox.imagePullSecrets[0]=guest-registry",
            "--set",
            "sandbox.tolerations[0].key=isolated,sandbox.tolerations[0].operator=Exists",
            "--set",
            "sandbox.guest.resources.limits.cpu=2,sandbox.ipc.resources.limits.memory=256Mi",
            "--set",
            "sandbox.manager.createSeconds=144",
            "--set",
            "sandbox.ipc.timeoutSeconds=55,sandbox.mcp.timeoutSeconds=66",
        )

        def environment(component):
            name = f"custom-sandbox-{component}"
            return docs["ConfigMap", name]["data"] | docs["Secret", name]["stringData"]

        with (
            patch.dict(os.environ, environment("manager"), clear=True),
            patch("ads_sandbox_manager.config.load_tls_context"),
        ):
            settings = manager_settings()
        self.assertEqual(settings.idle_seconds, 99)
        self.assertEqual(settings.detached_seconds, 999)
        self.assertEqual(settings.lifecycle_batch, 7)
        self.assertEqual(settings.pvc_timeout_seconds, 87)
        self.assertEqual(settings.ping_interval_seconds, 12)
        self.assertEqual(settings.ping_timeout_seconds, 40)
        self.assertEqual(settings.golden_bytes, 23 * 1024**3)
        self.assertEqual(settings.session_objects.create_seconds, 144)
        job = golden_job(settings)["spec"]["template"]["spec"]
        self.assertEqual(job["runtimeClassName"], "kata-qemu")
        self.assertEqual(job["imagePullSecrets"], [{"name": "guest-registry"}])
        self.assertEqual(job["tolerations"][0]["key"], "isolated")
        self.assertEqual(
            golden_pvc(settings, "uid")["spec"]["resources"]["requests"]["storage"],
            str(23 * 1024**3),
        )
        sid, bid, pid = uuid4(), uuid4(), uuid4()
        guest = guest_deployment(settings, sid, bid, settings.golden_version, pid)
        self.assertEqual(guest["metadata"]["namespace"], "guests")
        self.assertEqual(
            guest["spec"]["template"]["spec"]["containers"][0]["resources"],
            {
                "limits": {"cpu": 2, "memory": "1536Mi"},
                "requests": {"cpu": "1", "memory": "1536Mi"},
            },
        )
        self.assertEqual(guest["spec"]["template"]["spec"]["runtimeClassName"], "kata-qemu-ads")
        ipc = ipc_deployment(settings, sid, bid, settings.golden_version)
        pod = ipc["spec"]["template"]["spec"]
        self.assertEqual(pod["serviceAccountName"], "ads-sandbox-ipc")
        self.assertEqual(pod["nodeSelector"]["ads.io/application-node"], "true")
        env = environment("ipc") | {
            entry["name"]: entry["value"] for entry in pod["containers"][0]["env"]
        }
        with (
            patch.dict(os.environ, env, clear=True),
            patch("ads_sandbox_ipc.config.load_tls_context"),
        ):
            ipc_config = ipc_settings()
        self.assertEqual(ipc_config.namespace, "guests")
        self.assertEqual(ipc_config.timeout_seconds, 55)
        self.assertEqual(str(ipc_config.tls_ca_bundle), "/ca/ca.crt")
        with (
            patch.dict(os.environ, environment("mcp"), clear=True),
            patch("ads_sandbox_mcp.config.load_tls_context"),
        ):
            mcp = mcp_settings()
        self.assertEqual(mcp.port, 8443)
        self.assertEqual(mcp.timeout_seconds, 66)
        self.assertIn("custom-sandbox-mcp.app.svc.cluster.local:*", mcp.allowed_hosts)
        self.assertEqual(
            docs["ConfigMap", "custom-engine"]["data"]["ADS_ENGINE_MCP_URL"],
            "https://custom-sandbox-mcp:8443/mcp",
        )

    def test_byo_tls_and_external_secrets(self):
        flags = [
            "--set",
            "tls.certManager.enabled=false,tls.serviceSecretName=app-tls",
            "--set",
            "tls.policySecretName=policy-tls,tls.auditSecretName=audit-tls",
            "--set",
            "preferences.tls.serviceSecretName=preferences-tls",
            "--set",
            "contextMeter.tls.serviceSecretName=context-meter-tls",
            "--set",
            "contextCompactor.tls.serviceSecretName=context-compactor-tls",
        ]
        for component in ["mcp", "manager", "ipc"]:
            flags += ["--set", f"sandbox.{component}.tlsSecretName={component}-tls"]
            flags += ["--set", f"sandbox.{component}.existingSecret={component}-credentials"]
        docs = self.documents(*flags, "--set", "tls.caBundle.secretName=app-ca")
        self.assertFalse(any(kind == "Certificate" for kind, _ in docs))
        for component in ["mcp", "manager", "ipc"]:
            self.assertNotIn(("Secret", f"ads-sandbox-{component}"), docs)
        manager = docs["ConfigMap", "ads-sandbox-manager"]["data"]
        objects = json.loads(manager["ADS_SANDBOX_MANAGER_SESSION_OBJECTS"])
        self.assertEqual(objects["ipc_secret"], "ipc-credentials")
        self.assertEqual(objects["ipc_tls_secret"], "ipc-tls")
        self.assertNotIn("ipc_ca_secret", objects)  # Never cross-namespace Secret reuse.
        for component in ["mcp", "manager"]:
            pod = docs["Deployment", f"ads-sandbox-{component}"]["spec"]["template"]["spec"]
            self.assertIn(
                {"secretRef": {"name": f"{component}-credentials"}}, pod["containers"][0]["envFrom"]
            )
            self.assertIn(
                {
                    "name": "ca",
                    "secret": {
                        "secretName": "app-ca",
                        "items": [{"key": "ca.crt", "path": "ca.crt"}],
                    },
                },
                pod["volumes"],
            )
        for component in ["mcp", "manager", "ipc"]:
            result = self.render(*flags, "--set", f"sandbox.{component}.tlsSecretName=")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(f"sandbox.{component}.tlsSecretName", result.stderr)

    def test_context_budget_values_reach_service_settings(self):
        from ads_context_compactor.config import load_settings as compactor_settings
        from ads_engine.config import load_settings as engine_settings

        for custom in (False, True):
            flags = (
                [
                    "--set",
                    "context.triggerPercentage=75,context.targetPercentage=40,"
                    "engine.recall.inner.reservedOutputTokens=512,engine.recall.inner.starvationPercentage=15,"
                    "engine.recall.inner.answerCapTokens=768,engine.recall.inner.completionCapTokens=8192,"
                    "engine.recall.topLevel.reservedOutputTokens=128,"
                    "engine.recall.topLevel.answerCapTokens=2048,"
                    "engine.recall.topLevel.completionCapTokens=4096,"
                    "engine.recall.topLevel.starvationPercentage=25,"
                    "contextCompactor.reservedOutputTokens=256,contextCompactor.summaryCapTokens=1536,"
                    "contextCompactor.completionCapTokens=16384,"
                    "contextCompactor.minimumReductionPercentage=20,contextCompactor.starvationPercentage=12,"
                    "contextCompactor.recall.reservedOutputTokens=384,"
                    "contextCompactor.recall.answerCapTokens=640,"
                    "contextCompactor.recall.completionCapTokens=3072,"
                    "contextCompactor.recall.starvationPercentage=18",
                ]
                if custom
                else []
            )
            docs = self.documents(*flags)
            for component, loader in [
                ("engine", engine_settings),
                ("context-compactor", compactor_settings),
            ]:
                prefix = "ADS_" + component.upper().replace("-", "_") + "_"
                env = dict(docs["ConfigMap", f"ads-{component}"]["data"])
                env[prefix + "KEYCLOAK_CLIENT_SECRET"] = "fixture"
                env[prefix + "DATABASE_URL"] = "postgresql+psycopg://fixture@db/fixture"
                with (
                    patch.dict(os.environ, env, clear=True),
                    patch("ads_context_compactor.config.load_tls_context"),
                ):
                    settings = loader()
                if component == "engine":
                    self.assertEqual(settings.recall_starvation_percentage, 15 if custom else 10)
                    self.assertEqual(settings.recall_answer_cap, 768 if custom else 1024)
                    self.assertEqual(settings.recall_completion_cap, 8192 if custom else 1024)
                    self.assertEqual(settings.context_trigger, 75 if custom else 80)
                    self.assertEqual(settings.context_target, 40 if custom else 50)
                    self.assertEqual(settings.recall_reserve, 512 if custom else 1024)
                    self.assertEqual(settings.top_level_recall_reserve, 128 if custom else 1024)
                    self.assertEqual(settings.top_level_recall_answer_cap, 2048 if custom else 1024)
                    self.assertEqual(
                        settings.top_level_recall_completion_cap, 4096 if custom else 1024
                    )
                    self.assertEqual(
                        settings.top_level_recall_starvation_percentage, 25 if custom else 10
                    )
                else:
                    self.assertEqual(settings.recall_reserve, 384 if custom else 1024)
                    self.assertEqual(settings.recall_starvation_percentage, 18 if custom else 10)
                    self.assertEqual(settings.recall_answer_cap, 640 if custom else 1024)
                    self.assertEqual(settings.recall_completion_cap, 3072 if custom else 1024)
                    self.assertEqual(settings.reserve, 256 if custom else 1024)
                    self.assertEqual(settings.starvation_percentage, 12 if custom else 10)
                    self.assertEqual(settings.summary_cap, 1536 if custom else 2048)
                    self.assertEqual(settings.completion_cap, 16384 if custom else 2048)
                    self.assertEqual(settings.minimum_reduction_percentage, 20 if custom else 10)

    def test_context_budgets_reject_invalid_helm_values(self):
        for setting in [
            "context.triggerPercentage=100",
            "context.targetPercentage=80",
            "context.targetPercentage=0",
            "engine.recall.inner.starvationPercentage=0",
            "engine.recall.inner.starvationPercentage=100",
            "engine.recall.inner.reservedOutputTokens=0",
            "engine.recall.inner.answerCapTokens=-1",
            "engine.recall.inner.completionCapTokens=0",
            "contextCompactor.reservedOutputTokens=0",
            "contextCompactor.summaryCapTokens=0",
            "contextCompactor.completionCapTokens=0",
            "contextCompactor.minimumReductionPercentage=100",
            "engine.recall.inner.starvationPercentage=10.5",
            "engine.recall.topLevel.reservedOutputTokens=0",
            "engine.recall.topLevel.answerCapTokens=0",
            "engine.recall.topLevel.completionCapTokens=0",
            "engine.recall.topLevel.starvationPercentage=100",
            "contextCompactor.recall.reservedOutputTokens=0",
            "contextCompactor.recall.answerCapTokens=0",
            "contextCompactor.recall.completionCapTokens=0",
            "contextCompactor.recall.starvationPercentage=100",
            "contextCompactor.starvationPercentage=0",
            "contextCompactor.starvationPercentage=100",
            "context.reservedOutputTokens=512",
        ]:
            with self.subTest(setting=setting):
                result = self.render("--set", setting)
                self.assertNotEqual(result.returncode, 0, setting)
                self.assertIn(setting.split("=")[0].split(".")[-1], result.stderr)

    def test_recall_configuration_groups_do_not_leak_into_each_other(self):
        groups = {
            "engine.recall.topLevel": ("ads-engine", "ADS_ENGINE_TOP_LEVEL_RECALL_"),
            "engine.recall.inner": ("ads-engine", "ADS_ENGINE_INNER_RECALL_"),
            "contextCompactor.recall": ("ads-context-compactor", "ADS_CONTEXT_COMPACTOR_RECALL_"),
        }
        fields = {
            "reservedOutputTokens": ("RESERVED_OUTPUT_TOKENS", 128, 1024),
            "answerCapTokens": ("ANSWER_CAP_TOKENS", 640, 1024),
            "completionCapTokens": ("COMPLETION_CAP_TOKENS", 8192, 1024),
            "starvationPercentage": ("STARVATION_PERCENTAGE", 25, 10),
        }
        for changed in groups:
            with self.subTest(group=changed):
                docs = self.documents(
                    "--set", ",".join(f"{changed}.{k}={v[1]}" for k, v in fields.items())
                )
                for group, (name, prefix) in groups.items():
                    config = docs["ConfigMap", name]["data"]
                    for suffix, custom, default in fields.values():
                        self.assertEqual(
                            config[prefix + suffix], str(custom if group == changed else default)
                        )
                compactor = docs["ConfigMap", "ads-context-compactor"]["data"]
                self.assertEqual(compactor["ADS_CONTEXT_COMPACTOR_RESERVED_OUTPUT_TOKENS"], "1024")
                self.assertEqual(compactor["ADS_CONTEXT_COMPACTOR_STARVATION_PERCENTAGE"], "10")

    def test_manager_sasl_secret_and_ca(self):
        docs = self.documents(
            "--set",
            "sandbox.manager.kafka.securityProtocol=SASL_SSL",
            "--set",
            "sandbox.manager.kafka.saslUsername=test-user",
            "--set",
            "sandbox.manager.kafka.saslPassword=fixture-only",
            "--set",
            "sandbox.manager.kafka.caBundle.secretName=kafka-ca",
        )
        config = docs["ConfigMap", "ads-sandbox-manager"]["data"]
        secret = docs["Secret", "ads-sandbox-manager"]["stringData"]
        self.assertNotIn("fixture-only", json.dumps(config))
        self.assertEqual(secret["ADS_SANDBOX_MANAGER_KAFKA_SASL_PASSWORD"], "fixture-only")
        self.assertEqual(config["ADS_SANDBOX_MANAGER_KAFKA_CA_BUNDLE"], "/kafka-ca/ca.crt")
        pod = docs["Deployment", "ads-sandbox-manager"]["spec"]["template"]["spec"]
        self.assertIn(
            {
                "name": "kafka-ca",
                "secret": {
                    "secretName": "kafka-ca",
                    "items": [{"key": "ca.crt", "path": "ca.crt"}],
                },
            },
            pod["volumes"],
        )

    def test_release_packaging_carries_ci_size_and_version(self):
        with tempfile.TemporaryDirectory() as directory:
            chart = Path(directory) / "ads"
            shutil.copytree(CHART, chart)
            result = subprocess.run(
                [
                    "python3",
                    str(chart / "package_release.py"),
                    "--chart",
                    str(chart),
                    "--version",
                    "0.0.123-rc.1",
                    "--session-size",
                    "30Gi",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run(
                [HELM, "package", str(chart), "--destination", directory],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            archive = next(Path(directory).glob("*.tgz"))
            result = subprocess.run(
                [HELM, "template", "ads", str(archive), "-f", str(chart / "values-ci.yaml")],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('ADS_SESSION_SIZE: "30Gi"', result.stdout)
            self.assertIn('ADS_SANDBOX_MANAGER_GOLDEN_VERSION: "v0.0.123-rc.1"', result.stdout)
            self.assertNotIn(':0.0.1"', result.stdout)
            self.assertIn("ads-sandbox-golden:0.0.123-rc.1", result.stdout)


if __name__ == "__main__":
    unittest.main()
