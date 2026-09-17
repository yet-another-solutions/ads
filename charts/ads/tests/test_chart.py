"""Exercise real Helm rendering and online lookups without a cluster or credentials."""

import json
import os
import re
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

CHART = Path(__file__).resolve().parents[1]
HELM = os.environ.get("HELM_BIN", "helm")
CRD = "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/clusterpolicies.kyverno.io"
DEPLOYMENT = "/apis/apps/v1/namespaces/kyverno/deployments/kyverno-admission-controller"
SA = "/api/v1/namespaces/kyverno/serviceaccounts/kyverno-admission-controller"


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
        CRD: resource(
            "CustomResourceDefinition",
            "clusterpolicies.kyverno.io",
            status={"conditions": [{"type": "Established", "status": "True"}]},
        ),
        DEPLOYMENT: resource(
            "Deployment", "kyverno-admission-controller", status={"availableReplicas": 1}
        ),
        SA: resource("ServiceAccount", "kyverno-admission-controller"),
    }


DISCOVERY = {
    "v1": [("namespaces", "Namespace", False), ("nodes", "Node", False),
           ("serviceaccounts", "ServiceAccount", True)],
    "apps/v1": [("deployments", "Deployment", True)],
    "apiextensions.k8s.io/v1": [
        ("customresourcedefinitions", "CustomResourceDefinition", False)
    ],
    "node.k8s.io/v1": [("runtimeclasses", "RuntimeClass", False)],
}


class ChartTests(unittest.TestCase):
    def render(self, *args):
        return subprocess.run(
            [HELM, "template", "ads", str(CHART), "--namespace", "default", *args],
            capture_output=True, text=True, timeout=30, check=False,
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
                            for gv in DISCOVERY if gv != "v1"
                        ],
                    }
                elif path.removeprefix("/apis/").removeprefix("/api/") in DISCOVERY:
                    gv = path.removeprefix("/apis/").removeprefix("/api/")
                    body = {
                        "kind": "APIResourceList", "groupVersion": gv,
                        "resources": [
                            {"name": name, "kind": kind, "namespaced": namespaced,
                             "verbs": ["get", "list"]}
                            for name, kind, namespaced in DISCOVERY[gv]
                        ],
                    }
                elif path == forbidden:
                    code = 403
                    body = {"kind": "Status", "apiVersion": "v1", "status": "Failure",
                            "reason": "Forbidden", "message": "fixture access forbidden",
                            "code": 403}
                elif path in objects:
                    body = objects[path]
                else:
                    code = 404
                    body = {"kind": "Status", "apiVersion": "v1", "status": "Failure",
                            "reason": "NotFound", "code": 404}
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
                    config.write_text(json.dumps({
                        "apiVersion": "v1", "kind": "Config",
                        "clusters": [{"name": "fixture", "cluster": {
                            "server": f"http://127.0.0.1:{server.server_port}"}}],
                        "contexts": [{"name": "fixture", "context": {"cluster": "fixture"}}],
                        "current-context": "fixture",
                    }))
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
                    elif kind[1] == "ClusterPolicy":
                        self.assertNotIn("namespace:", metadata)
                    else:
                        namespace = re.search(r'  namespace: "?([^"\n]+)', metadata)[1]
                        self.assertIn(namespace, [app, sandbox])
                        if kind[1] in ["Deployment", "Service", "Secret", "ConfigMap",
                                       "Certificate", "HTTPRoute", "BackendTLSPolicy"]:
                            self.assertEqual(namespace, app)
                self.assertCountEqual(namespace_names, [app, sandbox])
                self.assertIn(f"ads.{app}.svc.cluster.local", result.stdout)
                self.assertIn(f"ads-preferences.{app}.svc.cluster.local", result.stdout)
                self.assertNotIn("resource-policy: keep", result.stdout)
                self.assertIn(f"/namespaces/{sandbox}/pods/", result.stdout)
                self.assertIn("failurePolicy: Fail", result.stdout)
                self.assertIn("validationFailureAction: Enforce", result.stdout)
                self.assertIn("{{ request.", result.stdout)
                self.assertIn('authentication.kubernetes.io/pod-uid', result.stdout)

    def test_custom_admission_settings_and_manager_subject(self):
        result = self.render(
            "--set", "namespace=custom-app,sandbox.namespace=custom-sandbox",
            "--set", "sandbox.admission.kyvernoNamespace=policy-system",
            "--set", "sandbox.admission.serviceAccountName=admission-sa",
            "--set", "sandbox.admission.policyName=custom-exec",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("name: custom-exec", result.stdout)
        self.assertIn("name: admission-sa\n    namespace: policy-system", result.stdout)
        self.assertIn("name: ads-sandbox-manager\n    namespace: custom-app", result.stdout)
        self.assertIn("name: ads-sandbox-ipc\n    namespace: custom-sandbox", result.stdout)

    def test_reject_unsafe_namespace_layouts(self):
        for value in [
            "namespace=default", "sandbox.namespace=default",
            "namespace=kyverno", "sandbox.namespace=kube-system",
            "sandbox.namespace=ads", "namespace=",
        ]:
            with self.subTest(value=value):
                self.assertNotEqual(self.render("--set", value).returncode, 0)
        result = self.render("--namespace", "ads")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("use --namespace default", result.stderr)

    def test_online_ready(self):
        result = self.online(fixtures())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_online_custom_admission_installation(self):
        objects = fixtures()
        objects["/apis/apps/v1/namespaces/policy-system/deployments/admission"] = objects.pop(
            DEPLOYMENT
        )
        objects["/api/v1/namespaces/policy-system/serviceaccounts/admission"] = objects.pop(SA)
        result = self.online(
            objects, "--set", "sandbox.admission.kyvernoNamespace=policy-system",
            "--set", "sandbox.admission.deploymentName=admission",
            "--set", "sandbox.admission.serviceAccountName=admission",
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
            (CRD, {"conditions": [{"type": "Established", "status": "False"}]},
             "established Kyverno"),
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
        for path in ["/api/v1/namespaces/kube-system", CRD, DEPLOYMENT, SA]:
            with self.subTest(path=path):
                result = self.online(fixtures(), forbidden=path)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("fixture access forbidden", result.stderr)


if __name__ == "__main__":
    unittest.main()
