"""Run on the admin node: real scoped Kafka traffic and negative ACL proofs.

Only UUID-named proof topics/groups are removed. No engine records are produced.
Passwords stay in the broker's mounted client properties, never argv or output.
"""

import subprocess
import uuid

BIN = "/opt/kafka/bin/"
CONFIG = "/etc/kafka/secrets/"


def call(tool, principal, *args, data=None, anonymous=False):
    option = {
        "kafka-console-producer.sh": "--producer.config",
        "kafka-console-consumer.sh": "--consumer.config",
    }.get(tool, "--command-config")
    command = ["kubectl", "-n", "kafka", "exec"]
    if data is not None:
        command.append("-i")
    command += [
        "kafka-0", "--", BIN + tool, "--bootstrap-server",
        "127.0.0.1:9094" if anonymous else "127.0.0.1:19092",
    ]
    if not anonymous:
        filename = "admin" if principal == "admin" else "ads-sandbox-" + principal
        command += [option, CONFIG + filename + ".properties"]
    return subprocess.run(
        command + list(args), input=data, capture_output=True, text=True, timeout=60,
    )


def allowed(result, label):
    if result.returncode or "AuthorizationException" in result.stderr + result.stdout:
        raise RuntimeError(f"Expected allowed: {label}; details suppressed")
    print("PASS: " + label, flush=True)
    return result.stdout


def denied(result, label):
    if "AuthorizationException" not in result.stderr + result.stdout:
        raise RuntimeError(f"Expected authorization denial: {label}; details suppressed")
    print("PASS: denied " + label, flush=True)


def invisible(result, label):
    output = result.stderr + result.stdout
    if not result.returncode or not (
        "AuthorizationException" in output or "does not exist as expected" in output
    ):
        raise RuntimeError(f"Expected unauthorized or hidden topic: {label}; {output}")
    print("PASS: denied " + label, flush=True)


def main():
    proof = "slice6-" + uuid.uuid4().hex
    request, response = ("sandbox." + part + "." + proof for part in ("req", "res"))
    outside = "ads.slice6-proof." + proof
    groups = []
    try:
        for topic in (request, response):
            allowed(call("kafka-topics.sh", "manager", "--create", "--topic", topic,
                         "--partitions", "1", "--replication-factor", "1"),
                    "manager creates " + topic.split(".")[1] + " prefix topic")
        allowed(call("kafka-topics.sh", "admin", "--create", "--topic", outside,
                     "--partitions", "1", "--replication-factor", "1"),
                "disposable out-of-prefix topic created by admin")
        for principal in ("mcp", "ipc"):
            denied(call("kafka-topics.sh", principal, "--create", "--topic",
                        "sandbox.req." + proof + "-" + principal,
                        "--partitions", "1", "--replication-factor", "1"),
                   principal + " cannot create sandbox topics")
        denied(call("kafka-topics.sh", "manager", "--create", "--topic", outside + "-new",
                    "--partitions", "1", "--replication-factor", "1"),
               "manager cannot create outside prefixes")
        invisible(call("kafka-topics.sh", "manager", "--delete", "--topic", outside),
                  "manager cannot delete outside prefixes")
        allowed(call("kafka-topics.sh", "admin", "--describe", "--topic", outside),
                "out-of-prefix topic still exists after denied deletion")
        for producer, consumer, topic in (
            ("manager", "ipc", request), ("ipc", "manager", response),
            ("mcp", "manager", "ads.sandbox.exec.request"),
            ("manager", "mcp", "ads.sandbox.exec.reply"),
        ):
            marker = proof + ":" + producer
            allowed(call("kafka-console-producer.sh", producer, "--topic", topic,
                         "--sync", data=marker + "\n"), producer + " writes authorized topic")
            group = "ads-sandbox-" + consumer + "-" + proof
            groups.append(group)
            result = call("kafka-console-consumer.sh", consumer, "--topic", topic,
                          "--group", group, "--from-beginning",
                          "--timeout-ms", "10000",
                          "--consumer-property", "enable.auto.commit=false")
            if "AuthorizationException" in result.stderr or marker not in result.stdout:
                raise RuntimeError("Proof marker missing from authorized consumption")
            print("PASS: " + consumer + " reads authorized topic", flush=True)
        denied(call("kafka-console-consumer.sh", "ipc", "--topic", "ads.sandbox.recover",
                    "--group", "ads-sandbox-ipc-" + proof, "--timeout-ms", "5000"),
               "IPC cannot read manager recovery traffic")
        denied(call("kafka-console-consumer.sh", "ipc", "--topic", request,
                    "--group", "ads-sandbox-mcp-" + proof, "--timeout-ms", "5000"),
               "IPC cannot use another service's consumer group")
        invisible(call("kafka-topics.sh", "mcp", "--describe", "--topic", request),
                  "MCP cannot access dynamic IPC topics")
        invisible(call("kafka-topics.sh", "admin", "--describe", "--topic", request,
                       anonymous=True), "anonymous compatibility listener cannot access sandbox")
        allowed(call("kafka-get-offsets.sh", "admin", "--topic",
                     "ads.engine.request", anonymous=True),
                "legacy engine metadata remains accessible without producing records")
        for topic in (request, response):
            allowed(call("kafka-topics.sh", "manager", "--delete", "--topic", topic),
                    "manager deletes its dynamic proof topic")
    finally:
        for topic in (request, response, outside):
            allowed(call("kafka-topics.sh", "admin", "--delete", "--if-exists",
                         "--topic", topic), "proof topic cleanup")
        for group in sorted(set(groups)):
            # Empty groups may already have expired; deletion is best-effort.
            call("kafka-consumer-groups.sh", "admin", "--delete", "--group", group)
        print("PASS: disposable Kafka proof objects cleaned up", flush=True)


if __name__ == "__main__":
    main()
