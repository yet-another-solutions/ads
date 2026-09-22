"""CI-only two-relay proof. Native endpoints; no Kubernetes Service or Kata claim."""

from __future__ import annotations

import hashlib
import http.client
import importlib.machinery
import importlib.util
import json
import os
import signal
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from uuid import uuid4


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def run(*args, data=None, success=True):
    reply = subprocess.run(args, input=data, capture_output=True, text=True, timeout=15)
    if success and reply.returncode:
        raise RuntimeError(f"CI operation failed: {args[0]}: {reply.stderr[:1000]}")
    return reply.stdout.strip() if success else reply


def write(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(value)


if len(sys.argv) > 1 and sys.argv[1] == "--child":
    # ip-netns-exec/unshare isolate this mount from the parent and other relay.
    run("mount", "-t", "tmpfs", "-o", "mode=755,nosuid,nodev", "tmpfs", "/run")
    directory = Path(sys.argv[2])
    config = json.loads((directory / "config.json").read_text())
    environment = {
        **os.environ,
        "POD_UID": config["pod_uid"],
        "ATTACHMENT_GENERATION": config["generation"],
    }
    os.execve(
        "/usr/local/bin/python",
        [
            "python",
            "/usr/local/bin/ads-ptp-relay",
            "--config",
            str(directory / "config.json"),
            "--key",
            str(directory / "key"),
            "--cert",
            str(directory.parent / "cert.pem"),
            "--tls-key",
            str(directory.parent / "tls.key"),
            "--state",
            "/run/relay-state",
        ],
        environment,
    )

relay = load("relay", "/usr/local/bin/ads-ptp-relay")
plugin = load("attachment", "/usr/local/bin/ads-ptp")
attestor = load("attestor", "/usr/local/bin/ads-ptp-attest")
canary = load("canary", "/usr/local/bin/ads-ptp-canary")
generation, sandbox = str(uuid4()), str(uuid4())
prefix = generation[:8]
bridge = "br" + prefix
namespaces = []
children = []
logs = []
attachments = []
created_bridge = False
temporary = tempfile.TemporaryDirectory(prefix="ads-relay-ci-")
root = Path(temporary.name)
context = None


def ns(name, *args, **kwargs):
    return run("ip", "netns", "exec", name, *args, **kwargs)


def health(host):
    connection = http.client.HTTPSConnection(host, 8443, context=context, timeout=5)
    try:
        connection.request("GET", "/health")
        reply = connection.getresponse()
        reply.read()
        return reply.status
    except (OSError, http.client.HTTPException):
        return None
    finally:
        connection.close()


def await_health(hosts, status, seconds=30):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if all(health(host) == status for host in hosts):
            return
        assert all(child.poll() is None for child in children), "relay exited unexpectedly"
        time.sleep(0.2)
    raise AssertionError(f"expected health {status}")


try:
    run(
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-subj",
        "/CN=relay-ci",
        "-addext",
        "subjectAltName=IP:198.18.1.1,IP:198.18.1.2",
        "-days",
        "1",
        "-keyout",
        str(root / "tls.key"),
        "-out",
        str(root / "cert.pem"),
    )
    context = ssl.create_default_context(cafile=str(root / "cert.pem"))
    public = {}
    for side in ("guest", "egress"):
        directory = root / side
        directory.mkdir(mode=0o700)
        private = run("wg", "genkey") + "\n"
        write(directory / "key", private)
        public[side] = run("wg", "pubkey", data=private)
        del private
    run("ip", "link", "add", bridge, "type", "bridge", "stp_state", "0")
    created_bridge = True
    run("ip", "address", "add", "198.18.1.254/24", "dev", bridge)
    run("ip", "link", "set", bridge, "up")
    configs, transports, vms = {}, {}, {}
    for index, side in enumerate(("guest", "egress"), 1):
        transport = f"cni-{side}-{generation}"
        run("ip", "netns", "add", transport)
        namespaces.append(transport)
        transports[side] = transport
        ns(transport, "ip", "link", "set", "lo", "up")
        host_end = f"v{index}{prefix}"
        run(
            "ip",
            "link",
            "add",
            host_end,
            "mtu",
            "1400",
            "type",
            "veth",
            "peer",
            "name",
            "eth0",
            "mtu",
            "1400",
            "netns",
            transport,
        )
        run("ip", "link", "set", host_end, "master", bridge)
        run("ip", "link", "set", host_end, "up")
        ns(transport, "ip", "address", "add", f"198.18.1.{index}/24", "dev", "eth0")
        ns(transport, "ip", "link", "set", "eth0", "up")
        other = "egress" if side == "guest" else "guest"
        local, remote = ("2", "1") if side == "guest" else ("1", "2")
        config = {
            "pod_uid": str(uuid4()),
            "generation": generation,
            "sandbox_id": sandbox,
            "side": side,
            "local_private": f"10.10.30.{local}/24",
            "peer_private": f"10.10.30.{remote}/24",
            "local_tunnel": f"10.10.40.{local}/32",
            "peer_tunnel": f"10.10.40.{remote}/32",
            "transport_mtu": 1400,
            "peer_key": public[other],
            "endpoint": "198.18.1.2:51820" if side == "guest" else None,
            "wireguard_port": 51820,
            "vxlan_port": 4789,
            "vni": 42,
            "packet_rate": 10000,
        }
        configs[side] = config
        run("nft", "--check", "-f", "-", data=relay.firewall(config))
        write(root / side / "config.json", json.dumps(config))
        output = (root / side / "process.log").open("w")
        logs.append(output)
        child = subprocess.Popen(
            [
                "ip",
                "netns",
                "exec",
                transport,
                "unshare",
                "--mount",
                "--propagation",
                "private",
                "python",
                "/relay-kernel-smoke.py",
                "--child",
                str(root / side),
            ],
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=output,
        )
        children.append(child)
        if side == "guest":
            await_health(["198.18.1.1"], 503)
    await_health(["198.18.1.1", "198.18.1.2"], 200)
    # Actual pidfd_open and /proc start-time fencing against both live relays.
    with attestor.processes(tuple(child.pid for child in children)) as check_processes:
        check_processes()
    for index, side in enumerate(("guest", "egress")):
        config, child = configs[side], children[index]
        private_path = f"/proc/{child.pid}/root/run/netns/private-{generation}"
        private_info = os.stat(private_path)
        transport_path = "/run/netns/" + transports[side]
        transport_info = os.stat(transport_path)
        vm = f"vm-{side}-{generation}"
        run("ip", "netns", "add", vm)
        namespaces.append(vm)
        vms[side] = vm
        canary.configure_namespace(vm)
        ns(vm, "ip", "link", "set", "lo", "up")
        interface = "eth0" if side == "guest" else "eth1"
        if side == "egress":
            ns(vm, "ip", "link", "add", "eth0", "type", "dummy")
            ns(vm, "ip", "address", "add", "198.19.1.2/24", "dev", "eth0")
            ns(vm, "ip", "link", "set", "eth0", "up")
            ns(vm, "ip", "route", "add", "default", "via", "198.19.1.1", "dev", "eth0")
        directory = root / ("attach-" + side)
        directory.mkdir(mode=0o700)
        for name in ("state", "bindings"):
            (directory / name).mkdir(mode=0o700)
        uid = str(uuid4())
        binding = {
            "pod_uid": uid,
            "generation": generation,
            "sandbox_id": sandbox,
            "role": side,
            "ifname": interface,
            "network": "ads-private",
            "relay_pod_uid": config["pod_uid"],
            "relay_runtime_id": hashlib.sha256(side.encode()).hexdigest(),
            "private": {
                "path": private_path,
                "identity": [private_info.st_dev, private_info.st_ino],
            },
            "transport": {
                "path": transport_path,
                "identity": [transport_info.st_dev, transport_info.st_ino],
            },
            "mtu": 1290,
            "address": config["local_private"],
            "gateway": "10.10.30.1" if side == "guest" else None,
        }
        plugin.save_record(directory / "bindings" / (uid + ".json"), binding)
        cni = {
            "cniVersion": "1.0.0",
            "type": "ads-ptp",
            "name": "ads-private",
            "bindingDir": str(directory / "bindings"),
            "stateDir": str(directory / "state"),
        }
        env = {
            "CNI_COMMAND": "ADD",
            "CNI_CONTAINERID": hashlib.sha256(uid.encode()).hexdigest(),
            "CNI_IFNAME": interface,
            "CNI_NETNS": "/run/netns/" + vm,
            "CNI_ARGS": "K8S_POD_UID=" + uid,
        }
        attachments.append((cni, env))
        result = plugin.perform(cni, env)
        cni["prevResult"] = result
        env["CNI_COMMAND"] = "CHECK"
        plugin.perform(cni, env)
        assert ns(vm, "sysctl", "-n", "net.ipv4.ip_forward") == "0"
        if side == "egress":
            default = json.loads(ns(vm, "ip", "-j", "route", "show", "default"))
            assert len(default) == 1 and default[0]["gateway"] == "198.19.1.1"
    await_health(["198.18.1.1", "198.18.1.2"], 200)
    ns(vms["guest"], "ping", "-n", "-c", "3", "-w", "8", "10.10.30.1")
    ns(vms["egress"], "ping", "-n", "-c", "3", "-w", "8", "10.10.30.2")
    # The untrusted guest cannot spoof the authenticated endpoint's MAC.
    ns(vms["guest"], "ip", "link", "set", "eth0", "address", "02:ff:ee:dd:cc:bb")
    assert (
        ns(vms["guest"], "ping", "-n", "-c", "1", "-w", "2", "10.10.30.1", success=False).returncode
        != 0
    )
    ns(vms["guest"], "ip", "link", "set", "eth0", "address", relay.mac(configs["guest"], "guest"))
    ns(vms["guest"], "ping", "-n", "-c", "1", "-w", "3", "10.10.30.1")
    # Positive ordinary-transport listener path exists, but guest has no route bypass.
    ns(transports["guest"], "ping", "-n", "-c", "1", "-w", "3", "198.18.1.254")
    assert (
        ns(
            vms["guest"], "ping", "-n", "-c", "1", "-w", "2", "198.18.1.254", success=False
        ).returncode
        != 0
    )
    # Replace only the disposable sender key, prove denial, then restore its exact key.
    wrong = root / "wrong-key"
    write(wrong, run("wg", "genkey") + "\n")
    guest_private = f"/proc/{children[0].pid}/root/run/netns/private-{generation}"
    run(
        "nsenter",
        "--net=" + guest_private,
        "--",
        "wg",
        "set",
        "wg-private",
        "private-key",
        str(wrong),
    )
    await_health(["198.18.1.1", "198.18.1.2"], 503)
    run(
        "nsenter",
        "--net=" + guest_private,
        "--",
        "wg",
        "set",
        "wg-private",
        "private-key",
        str(root / "guest/key"),
    )
    await_health(["198.18.1.1", "198.18.1.2"], 200)
    children[1].send_signal(signal.SIGTERM)
    assert children[1].wait(timeout=10) == 0
    assert health("198.18.1.1") == 503
finally:
    for child in children:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
    for output in logs:
        output.close()
    for cni, env in reversed(attachments):
        env["CNI_COMMAND"] = "DEL"
        plugin.perform(cni, env)
        plugin.perform(cni, env)
    for name in reversed(namespaces):
        run("ip", "netns", "delete", name)
    if created_bridge:
        run("ip", "link", "delete", bridge)
    # Diagnostic logs exclude credentials; preserve a failure reason before removing keys.
    for side in ("guest", "egress"):
        log = root / side / "process.log"
        if log.exists() and log.stat().st_size:
            print(side + " relay log: " + log.read_text()[-2000:])
    temporary.cleanup()
assert not json.loads(run("ip", "-j", "netns", "list"))
print(
    json.dumps(
        {
            "two_real_wireguard_relays": True,
            "https_session_health": True,
            "health_denies_before_peer_and_on_wrong_identity": True,
            "private_ethernet_bidirectional": True,
            "spoofed_mac_denied": True,
            "guest_transport_bypass_denied": True,
            "peer_shutdown_unhealthy": True,
            "owned_namespaces_and_processes_cleaned": True,
            "real_relay_process_identity_pinning": True,
            "kubernetes_service_node_attestation_kata_proven": False,
        }
    )
)
