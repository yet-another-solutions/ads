"""GitHub CI: real rootless user/net namespace NIC move, not full Kata/Podman boot."""

import array
import fcntl
import importlib.machinery
import importlib.util
import json
import os
import pwd
import select
import signal
import subprocess
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

loader = importlib.machinery.SourceFileLoader("network", "/usr/local/sbin/ads-sandbox-network")
spec = importlib.util.spec_from_loader(loader.name, loader)
network = importlib.util.module_from_spec(spec)
loader.exec_module(network)
generation = str(uuid4())
config = network.configuration(
    {
        "ADS_SANDBOX_NETWORK_MODE": "private",
        "ADS_ATTACHMENT_GENERATION": generation,
        "ADS_PRIVATE_MTU": "1340",
    }
)
peer = "peer-" + generation
process = None
netfd = pidfd = None
server = None


def run(*command):
    return subprocess.run(command, check=True, capture_output=True, text=True, timeout=10).stdout


try:
    # This Python process was launched under a new netns, never the runner host netns.
    assert {link["ifname"] for link in json.loads(run("ip", "-j", "link"))} == {"lo"}
    run("ip", "link", "set", "lo", "up")
    run(
        "sysctl",
        "-q",
        "-w",
        "net.ipv6.conf.all.disable_ipv6=1",
        "net.ipv6.conf.default.disable_ipv6=1",
        "net.ipv4.ip_forward=0",
    )
    run("ip", "netns", "add", peer)
    run(
        "ip",
        "link",
        "add",
        "eth0",
        "address",
        config["mac"],
        "mtu",
        "1340",
        "type",
        "veth",
        "peer",
        "name",
        "gateway",
    )
    run("ip", "link", "set", "gateway", "netns", peer)
    run("ip", "address", "add", "10.10.30.2/24", "dev", "eth0")
    run("ip", "link", "set", "eth0", "up")
    run("ip", "route", "add", "default", "via", "10.10.30.1")
    run("ip", "-n", peer, "address", "add", "10.10.30.1/24", "dev", "gateway")
    run("ip", "-n", peer, "link", "set", "gateway", "up")
    run("ip", "-n", peer, "link", "set", "lo", "up")
    # Reproduce Kata's independently initialized kernel, not only the host CNI
    # namespace. Strict validation must reject IPv6 until guest hardening runs.
    run(
        "sysctl",
        "-q",
        "-w",
        "net.ipv6.conf.all.disable_ipv6=0",
        "net.ipv6.conf.default.disable_ipv6=0",
    )
    run("ip", "-6", "address", "replace", "fe80::1234/64", "dev", "eth0")
    try:
        network.validate_network(network.inventory(), config, True)
    except ValueError:
        pass
    else:
        raise AssertionError("IPv6 topology was accepted before hardening")
    network.disable_guest_ipv6()
    network.validate_network(network.inventory(), config, True)
    # uidmap helpers map the normal rootless account and its assigned sub-ID ranges.
    process = subprocess.Popen(
        [
            "runuser",
            "-u",
            "podman",
            "--",
            "unshare",
            "--user",
            "--map-auto",
            "--map-root-user",
            "--net",
            "--",
            "python3",
            "-c",
            "import os,time; print(os.getpid(),flush=True); time.sleep(180)",
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    assert select.select([process.stdout], [], [], 10)[0], "rootless namespace startup timeout"
    pid = int(process.stdout.readline())
    pidfd = os.pidfd_open(pid)
    netfd = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY)
    owner = fcntl.ioctl(netfd, network.NS_GET_USERNS)
    try:
        owner_uid = array.array("I", [0])
        fcntl.ioctl(owner, network.NS_GET_OWNER_UID, owner_uid, True)
        assert owner_uid[0] == pwd.getpwnam("podman").pw_uid
    finally:
        os.close(owner)
    poll = select.poll()
    poll.register(pidfd, select.POLLIN)
    ticks = network.process_ticks(pid)

    def check():
        assert not poll.poll(0) and network.process_ticks(pid) == ticks
        actual = os.stat(f"/proc/{pid}/ns/net")
        assert (actual.st_dev, actual.st_ino) == network.identity(netfd)

    target = SimpleNamespace(net=netfd, check=check, recheck=check)
    network.ip("link", "set", "lo", "up", namespace=netfd)
    network.transfer(config, target)
    server = subprocess.Popen(
        [
            "ip",
            "netns",
            "exec",
            peer,
            "python3",
            "-c",
            "import socket; s=socket.socket(); s.bind(('10.10.30.1',18080)); s.listen(1); "
            "print('ready',flush=True); c,_=s.accept(); "
            "c.sendall(c.recv(128)); c.close(); s.close()",
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    assert (
        select.select([server.stdout], [], [], 5)[0] and server.stdout.readline().strip() == "ready"
    )
    network.execute(
        [
            "/usr/bin/python3",
            "-c",
            "import socket; s=socket.create_connection(('10.10.30.1',18080),timeout=3); "
            "s.sendall(b'private-handoff'); assert s.recv(128)==b'private-handoff'; s.close()",
        ],
        netfd,
    )
    assert server.wait(timeout=5) == 0
    network.validate_network(network.inventory(), config, False)
    network.validate_network(network.inventory(netfd), config, True)
    # A repeated move cannot consume a second interface or pretend the source exists.
    try:
        network.transfer(config, target)
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate NIC handoff accepted")
    print(
        "rootless namespace FD move, private TCP, outer loopback-only and duplicate denial passed"
    )
finally:
    if server is not None and server.poll() is None:
        server.kill()
        server.wait(timeout=5)
    if pidfd is not None:
        try:
            signal.pidfd_send_signal(pidfd, signal.SIGTERM)
        except ProcessLookupError:
            pass
        os.close(pidfd)
    if process is not None:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    if netfd is not None:
        os.close(netfd)
    run("ip", "netns", "delete", peer)
    assert not (Path("/run/netns") / peer).exists()
