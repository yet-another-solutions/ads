"""Add sandbox principals and least-privilege ACLs to the existing lab broker.

Run on the admin node; canonical passwords arrive via JSON stdin.
Existing broker admin remains `ads`; ANONYMOUS is never a superuser.
The controller and loopback admin listener become SASL/PLAIN. The existing
anonymous ADS compatibility listener is kept, with engine-only topic/group ACLs.
"""
import json
import subprocess
import sys
from pathlib import Path

K = ["kubectl", "-n", "kafka"]
BIN = "/opt/kafka/bin/"
SECRET_DIR = "/etc/kafka/secrets/"
STATIC = (
    "ads.sandbox.exec.request", "ads.sandbox.exec.reply", "ads.sandbox.ready",
    "ads.sandbox.ping.req", "ads.sandbox.ping.res", "ads.sandbox.idle", "ads.sandbox.recover",
    "ads.sandbox.manager.barrier",
)


def run(command, data=None):
    result = subprocess.run(command, input=data, capture_output=True, text=True, timeout=300)
    if result.returncode:
        # Kubernetes object payloads may contain credentials. Never echo them.
        raise RuntimeError(f"Command failed: {command[0]}; output suppressed")
    return result.stdout


def patch(kind, name, body, namespace="kafka"):
    run(["kubectl", "-n", namespace, "patch", kind, name, "--type=merge", "--patch-file=/dev/stdin"],
        json.dumps(body))


def properties(user, password):
    assert all(c not in password for c in ('"', "\\", "\n", "\r"))
    return ("security.protocol=SASL_PLAINTEXT\nsasl.mechanism=PLAIN\n"
            "sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule "
            f'required username="{user}" password="{password}";\n'
            "request.timeout.ms=10000\ndefault.api.timeout.ms=15000\n")


def cli(tool, *args):
    return run(K + ["exec", "kafka-0", "--", BIN + tool,
                   "--bootstrap-server", "127.0.0.1:19092",
                   "--command-config", SECRET_DIR + "admin.properties", *args])


def acl(principal, operations, *, topics=(), groups=(), prefix=False):
    args = ["--add", "--allow-principal", "User:" + principal]
    for operation in operations:
        args += ["--operation", operation]
    for topic in topics:
        args += ["--topic", topic]
    for group in groups:
        args += ["--group", group]
    if prefix:
        args += ["--resource-pattern-type", "prefixed"]
    cli("kafka-acls.sh", *args)


def save_statefulset():
    """Persist the effective nonsecret manifest without server-owned metadata."""
    observed = json.loads(run(K + ["get", "sts", "kafka", "-o", "json"]))
    clean = {
        "apiVersion": observed["apiVersion"],
        "kind": observed["kind"],
        "metadata": {"name": "kafka", "namespace": "kafka"},
        "spec": observed["spec"],
    }
    for key in ("labels", "annotations"):
        values = dict(observed["metadata"].get(key, {}))
        values.pop("kubectl.kubernetes.io/last-applied-configuration", None)
        if values:
            clean["metadata"][key] = values
    # JSON is valid YAML. This is the existing lab's canonical broker manifest.
    Path("/opt/src/kafka/statefulset.yaml").write_text(json.dumps(clean, indent=2) + "\n")


def main():
    credentials = json.load(sys.stdin)
    users = {"ads": credentials["kafka-credentials"]}
    users.update({f"ads-sandbox-{c}": credentials[f"ads-sandbox-{c}-kafka-credentials"]
                  for c in ("mcp", "manager", "ipc")})
    for password in users.values():
        assert all(c not in password for c in ('"', "\\", "\n", "\r"))
    jaas = ("KafkaServer {\n org.apache.kafka.common.security.plain.PlainLoginModule required\n"
            f' username="ads"\n password="{users["ads"]}"\n')
    jaas += "\n".join(f' user_{user}="{password}"' for user, password in users.items())
    jaas += ";\n};\n"
    secret_data = {"kafka_jaas.conf": jaas}
    for name, password in users.items():
        filename = "admin.properties" if name == "ads" else name + ".properties"
        secret_data[filename] = properties(name, password)
    patch("secret", "kafka-credentials", {"stringData": secret_data})
    for user, password in users.items():
        if user == "ads":
            continue
        namespace = "ads-sandbox" if user.endswith("-ipc") else "ads"
        run(["kubectl", "apply", "-f", "-"], json.dumps({
            "apiVersion": "v1", "kind": "Secret", "type": "Opaque",
            "metadata": {"name": user + "-kafka", "namespace": namespace},
            "stringData": {"username": user, "password": password},
        }))
    sts = json.loads(run(K + ["get", "sts", "kafka", "-o", "json"]))
    pod_spec = sts["spec"]["template"]["spec"]
    container = next(c for c in pod_spec["containers"] if c["name"] == "kafka")
    values = {e["name"]: e for e in container["env"]}
    protocols = dict(item.split(":", 1) for item in
                     values["KAFKA_LISTENER_SECURITY_PROTOCOL_MAP"]["value"].split(","))
    assert protocols["PLAINTEXT_ADS"] == "PLAINTEXT"
    protocols.update({"CONTROLLER": "SASL_PLAINTEXT", "PLAINTEXT": "SASL_PLAINTEXT"})
    for name, value in {
        "KAFKA_LISTENER_SECURITY_PROTOCOL_MAP": ",".join(f"{k}:{v}" for k, v in protocols.items()),
        "KAFKA_SASL_MECHANISM_CONTROLLER_PROTOCOL": "PLAIN",
        "KAFKA_AUTHORIZER_CLASS_NAME": "org.apache.kafka.metadata.authorizer.StandardAuthorizer",
        "KAFKA_SUPER_USERS": "User:ads",
        "KAFKA_ALLOW_EVERYONE_IF_NO_ACL_FOUND": "false",
    }.items():
        values[name] = {"name": name, "value": value}
    container["env"] = list(values.values())
    volume = next(v for v in pod_spec["volumes"] if v["name"] == "creds")
    paths = {i["key"]: i for i in volume["secret"]["items"]}
    for key in secret_data:
        paths[key] = {"key": key, "path": key}
    volume["secret"]["items"] = list(paths.values())
    # Update the full observed Pod spec, without touching PVCs or other namespaces.
    patch("statefulset", "kafka", {"spec": {"template": {"spec": pod_spec}}})
    print("Kafka authorization restart requested", flush=True)
    run(K + ["rollout", "status", "statefulset/kafka", "--timeout=240s"])
    # First restore the only old anonymous application's topic/group permissions.
    acl("ANONYMOUS", ("Read", "Write", "Describe"),
        topics=("ads.engine.request", "ads.engine.output"))
    acl("ANONYMOUS", ("Read", "Describe"), groups=("ads", "ads-engine"))
    print("PASS: existing ADS compatibility topic/group access restored", flush=True)
    for topic in STATIC:
        cli("kafka-topics.sh", "--create", "--if-not-exists", "--topic", topic,
            "--partitions", "1", "--replication-factor", "1")
    mcp, manager, ipc = ("ads-sandbox-" + c for c in ("mcp", "manager", "ipc"))
    acl(mcp, ("Write", "Describe"), topics=("ads.sandbox.exec.request",))
    acl(mcp, ("Read", "Describe"), topics=("ads.sandbox.exec.reply",))
    acl(mcp, ("Read", "Describe"), groups=("ads-sandbox-mcp-",), prefix=True)
    acl(manager, ("Read", "Describe"), topics=("ads.sandbox.exec.request", "ads.sandbox.ping.res"))
    acl(manager, ("Write", "Describe"), topics=("ads.sandbox.exec.reply", "ads.sandbox.ping.req"))
    acl(manager, ("Read", "Write", "Describe"),
        topics=("ads.sandbox.ready", "ads.sandbox.idle", "ads.sandbox.recover"))
    acl(manager, ("Read", "Write", "Describe"), topics=("ads.sandbox.manager.barrier",))
    acl(manager, ("Create", "Delete", "Describe"), topics=("sandbox.req.", "sandbox.res."), prefix=True)
    acl(manager, ("Write",), topics=("sandbox.req.",), prefix=True)
    acl(manager, ("Read",), topics=("sandbox.res.",), prefix=True)
    acl(manager, ("Read", "Describe"), groups=("ads-sandbox-manager",), prefix=True)
    acl(ipc, ("Read", "Describe"), topics=("sandbox.req.",), prefix=True)
    acl(ipc, ("Write", "Describe"), topics=("sandbox.res.",), prefix=True)
    acl(ipc, ("Read", "Write", "Describe"), topics=("ads.sandbox.ready",))
    acl(ipc, ("Read", "Describe"), topics=("ads.sandbox.ping.req",))
    acl(ipc, ("Write", "Describe"), topics=("ads.sandbox.ping.res",))
    acl(ipc, ("Read", "Describe"), groups=("ads-sandbox-ipc-",), prefix=True)
    print("PASS: sandbox static topics and principal-specific ACLs installed", flush=True)
    save_statefulset()
    print("PASS: effective nonsecret broker manifest persisted", flush=True)
    print(cli("kafka-acls.sh", "--list"), flush=True)


if __name__ == "__main__":
    main()
