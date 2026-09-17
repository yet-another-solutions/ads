"""Real API-server admission proof using real pod-bound ServiceAccount tokens.

All test Pods are plain published BusyBox on application nodes, not Kata.
Token kubeconfigs live in anonymous memory file descriptors, not on disk.
Only objects with this invocation's unique label are deleted.
"""
import json
import os
import subprocess
from uuid import uuid4

NS = "ads-sandbox"
RUN = "slice6-" + uuid4().hex[:10]
PODS = {}


def kubectl(*args, data=None, token=None):
    command = ["kubectl"]
    fd = None
    try:
        if token is not None:
            cluster = json.loads(subprocess.check_output(
                ["kubectl", "config", "view", "--minify", "--flatten", "--raw", "-o", "json"]
            ))["clusters"][0]["cluster"]
            cfg = {
                "apiVersion": "v1", "kind": "Config",
                "clusters": [{"name": "proof", "cluster": cluster}],
                "users": [{"name": "proof", "user": {"token": token}}],
                "contexts": [{"name": "proof", "context": {
                    "cluster": "proof", "user": "proof", "namespace": NS}}],
                "current-context": "proof",
            }
            fd = os.memfd_create("ads-slice6-proof")
            os.write(fd, json.dumps(cfg).encode())
            os.lseek(fd, 0, os.SEEK_SET)
            command += ["--kubeconfig", f"/proc/self/fd/{fd}"]
        return subprocess.run(command + list(args), input=data, text=True,
                              capture_output=True, timeout=150,
                              pass_fds=() if fd is None else (fd,))
    finally:
        if fd is not None:
            os.close(fd)


def checked(*args, **kwargs):
    result = kubectl(*args, **kwargs)
    assert result.returncode == 0, result.stderr[:1000]
    return result.stdout


def create(role, sandbox=None, *, ipc=False):
    name = f"{RUN}-{role}"
    labels = {"ads.io/identity-proof": RUN}
    if sandbox is not None:
        labels["ads.io/sandbox-id"] = sandbox
    containers = [{"name": "ipc" if ipc else "sandbox",
                   "image": "docker.io/library/busybox:1.37.0",
                   "command": ["sleep", "600"],
                   "resources": {"requests": {"cpu": "5m", "memory": "8Mi"},
                                 "limits": {"cpu": "50m", "memory": "32Mi"}}}]
    if role == "guest-a":
        containers.append({**containers[0], "name": "other"})
    pod = {"apiVersion": "v1", "kind": "Pod",
           "metadata": {"name": name, "namespace": NS, "labels": labels},
           "spec": {"nodeSelector": {"ads.io/application-node": "true"},
                    "serviceAccountName": "ads-sandbox-ipc" if ipc else "default",
                    "automountServiceAccountToken": ipc,
                    "restartPolicy": "Never", "containers": containers}}
    out = checked("create", "-f", "-", "-o", "json", data=json.dumps(pod))
    PODS[role] = json.loads(out)
    return name


def token_for(role):
    pod = PODS[role]
    return checked("-n", NS, "create", "token", "ads-sandbox-ipc",
                   "--duration=10m", "--bound-object-kind=Pod",
                   "--bound-object-name=" + pod["metadata"]["name"],
                   "--bound-object-uid=" + pod["metadata"]["uid"]).strip()


def exec_check(token, target, *, allowed, container="sandbox"):
    result = kubectl("-n", NS, "exec", PODS[target]["metadata"]["name"],
                     "-c", container, "--", "true", token=token)
    if allowed:
        assert result.returncode == 0, result.stderr[:1000]
    else:
        assert result.returncode != 0
        assert "ads-sandbox-ipc-exec" in result.stderr, result.stderr[:1000]
    print(f"PASS: exec {target}/{container} {'allowed' if allowed else 'admission denied'}", flush=True)


def main():
    a, b = str(uuid4()), str(uuid4())
    try:
        for role, label, ipc in (
            ("ipc-a", a, True), ("ipc-b", b, True),
            ("guest-a", a, False), ("guest-b", b, False),
            ("unlabeled-guest", None, False), ("unlabeled-ipc", None, True),
        ):
            create(role, label, ipc=ipc)
        checked("-n", NS, "wait", "pod", "-l", "ads.io/identity-proof=" + RUN,
                "--for=condition=Ready", "--timeout=120s")
        ta, tb = token_for("ipc-a"), token_for("ipc-b")
        info = json.loads(checked("auth", "whoami", "-o", "json", token=ta))
        extra = info["status"]["userInfo"]["extra"]
        assert extra["authentication.kubernetes.io/pod-uid"] == [PODS["ipc-a"]["metadata"]["uid"]]
        print("PASS: API-server verified real pod-bound UID", flush=True)
        exec_check(ta, "guest-a", allowed=True)
        exec_check(tb, "guest-b", allowed=True)
        exec_check(ta, "guest-b", allowed=False)
        exec_check(tb, "guest-a", allowed=False)
        exec_check(ta, "unlabeled-guest", allowed=False)
        exec_check(token_for("unlabeled-ipc"), "guest-a", allowed=False)
        exec_check(ta, "guest-a", allowed=False, container="other")
        exec_check(ta, "ipc-a", allowed=False, container="ipc")
        unbound = checked("-n", NS, "create", "token", "ads-sandbox-ipc", "--duration=10m").strip()
        exec_check(unbound, "guest-a", allowed=False)
        for verb, resource, namespace in (
            ("create", "deployments.apps", NS), ("patch", "pods", NS),
            ("create", "roles", NS), ("create", "serviceaccounts/token", NS),
            ("create", "pods/exec", "ads"),
        ):
            result = kubectl("auth", "can-i", verb, resource, "-n", namespace, token=ta)
            assert result.stdout.strip() == "no"
            print(f"PASS: IPC cannot {verb} {resource} in {namespace}", flush=True)
        manager = "system:serviceaccount:ads:ads-sandbox-manager"
        for resource in ("jobs.batch", "deployments.apps", "persistentvolumeclaims"):
            assert checked("auth", "can-i", "create", resource, "-n", NS,
                           "--as", manager).strip() == "yes"
        for verb, resource in (
            ("create", "pods/exec"), ("create", "roles"),
            ("create", "rolebindings"), ("create", "namespaces"),
        ):
            result = kubectl("auth", "can-i", verb, resource, "-n", NS, "--as", manager)
            assert result.stdout.strip() == "no"
        print("PASS: manager object rights; no exec, RBAC, or namespace rights", flush=True)
    finally:
        checked("-n", NS, "delete", "pods", "-l", "ads.io/identity-proof=" + RUN,
                "--wait=true", "--timeout=120s")
        print("PASS: disposable proof Pods removed", flush=True)


if __name__ == "__main__":
    main()
