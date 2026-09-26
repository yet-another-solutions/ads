"""Actual nft REDIRECT, original destination and no-forwarding proof in private netns.

The downstream HTTP/TLS owner is an explicit recorder fixture here. Its full
protocol/policy behavior is separately exercised by the ordinary socket suite.
No relay, manager, Kubernetes or lab topology is involved.
"""

import asyncio
import ipaddress
import json
import os
import socket
import subprocess
from types import SimpleNamespace
from uuid import uuid4

from ads_sandbox_egress.interception import Interception, KernelBoundary, Network, rules


def run(*args):
    result = subprocess.run(args, capture_output=True, check=False, timeout=5)
    if result.returncode:
        raise RuntimeError(f"fixture command {args!r} failed: {result.stderr[:4096]!r}")
    return result.stdout


async def main():
    if os.getuid() != 0 or os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
        raise RuntimeError("explicit private network namespace required")
    if {item["ifname"] for item in json.loads(run("ip", "-j", "link"))} != {"lo"}:
        raise RuntimeError("empty isolated fixture network required")
    guest, origin = ("egress-test-" + uuid4().hex for _ in range(2))
    created, children, servers = [], [], []
    intercepted = None
    try:
        run("mount", "--make-rprivate", "/")
        run("ip", "link", "set", "lo", "up")
        run(
            "sysctl",
            "-q",
            "-w",
            "net.ipv4.ip_forward=0",
            "net.ipv6.conf.all.disable_ipv6=1",
            "net.ipv6.conf.default.disable_ipv6=1",
        )
        for namespace, interface in ((guest, "eth1"), (origin, "eth0")):
            run("ip", "netns", "add", namespace)
            created.append(namespace)
            run("ip", "link", "add", interface, "type", "veth", "peer", "name", "peer")
            run("ip", "link", "set", "peer", "netns", namespace)
            run("ip", "-n", namespace, "link", "set", "peer", "up")
            run("ip", "-n", namespace, "link", "set", "lo", "up")
            run("ip", "link", "set", interface, "up")
        run("ip", "link", "set", "eth1", "address", "02:12:34:56:78:90", "mtu", "1340")
        run("ip", "address", "add", "10.10.30.1/24", "dev", "eth1")
        run("ip", "-n", guest, "address", "add", "10.10.30.2/24", "dev", "peer")
        run("ip", "-n", guest, "route", "add", "default", "via", "10.10.30.1")
        run("ip", "address", "add", "192.0.2.1/30", "dev", "eth0")
        run("ip", "-n", origin, "address", "add", "192.0.2.2/30", "dev", "peer")
        run("ip", "-n", origin, "address", "add", "1.1.1.1/32", "dev", "lo")
        run("ip", "route", "add", "1.1.1.1/32", "via", "192.0.2.2")
        run("ip", "-n", origin, "route", "add", "10.10.30.0/24", "via", "192.0.2.1")
        boundary = KernelBoundary(
            Network(
                "eth1",
                "eth0",
                ipaddress.IPv4Interface("10.10.30.1/24"),
                ipaddress.IPv4Address("10.10.30.2"),
                ipaddress.IPv4Address("192.0.2.1"),
                8080,
                15001,
                15002,
                1340,
                "02:12:34:56:78:90",
            )
        )
        # Check the exact production batch first so CI reports nft diagnostics
        # without exposing command output in the production runtime.
        checked = subprocess.run(
            ("nft", "--check", "-f", "-"),
            input=rules(boundary.network).encode(),
            capture_output=True,
            check=False,
            timeout=2,
        )
        assert checked.returncode == 0, checked.stderr[:4096]
        boundary.establish()
        origin_process = await asyncio.create_subprocess_exec(
            "ip",
            "netns",
            "exec",
            origin,
            "python",
            "-u",
            "-c",
            "import socket,select\n"
            "tcp=socket.socket();tcp.bind(('1.1.1.1',4443));tcp.listen()\n"
            "udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('1.1.1.1',443))\n"
            "print('ready',flush=True)\n"
            "while True:\n"
            " for s in select.select([tcp,udp],[],[],10)[0]:\n"
            "  if s is tcp:\n"
            "   c,_=tcp.accept();c.settimeout(2);c.recv(4);c.sendall(b'origin');c.close()\n"
            "  else:\n"
            "   _,peer=udp.recvfrom(64);udp.sendto(b'origin',peer)\n",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        children.append(origin_process)
        async with asyncio.timeout(5):
            assert await origin_process.stdout.readline() == b"ready\n"
        reader, writer = await asyncio.open_connection("1.1.1.1", 4443)
        try:
            writer.write(b"test")
            await writer.drain()
            assert await asyncio.wait_for(reader.read(64), 2) == b"origin"
        finally:
            writer.close()
            await writer.wait_closed()
        # Positive control: the UDP destination is genuinely responding, not
        # a test which "passes" because no origin service exists.
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            await asyncio.get_running_loop().sock_sendto(sock, b"test", ("1.1.1.1", 443))
            answer, _ = await asyncio.wait_for(
                asyncio.get_running_loop().sock_recvfrom(sock, 64), 2
            )
            assert answer == b"origin"
        finally:
            sock.close()
        seen = []
        tasks = set()

        def accept(reader, writer, address, port):
            seen.append((str(address), port))

            async def reply():
                try:
                    assert await reader.readexactly(4) == b"test"
                    writer.write(b"intercepted")
                    await writer.drain()
                finally:
                    writer.close()
                    await writer.wait_closed()

            task = asyncio.create_task(reply())
            tasks.add(task)
            task.add_done_callback(tasks.discard)

        async def close():
            await asyncio.gather(*tasks)

        intercepted = Interception(boundary, SimpleNamespace(accept=accept, close=close))
        await intercepted.start()

        async def client(code):
            process = await asyncio.create_subprocess_exec(
                "ip",
                "netns",
                "exec",
                guest,
                "python",
                "-c",
                code,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            children.append(process)
            async with asyncio.timeout(5):
                out, err = await process.communicate()
            assert process.returncode == 0, (out, err)
            return out

        request = (
            "import socket;s=socket.create_connection(('1.1.1.1',4443),2);"
            "s.sendall(b'test');assert s.recv(64)==b'intercepted';s.close()"
        )
        await client(request)
        assert seen == [("1.1.1.1", 4443)]
        # Direct upstream listener is not reachable over a forwarding path.
        # With interception removed the guest must fail, never reach origin.
        await intercepted.close()
        await client(
            "import socket;s=socket.socket();s.settimeout(.5);"
            "assert s.connect_ex(('1.1.1.1',4443))!=0;s.close()"
        )
        # Even accidental forwarding enablement cannot open the kernel fence.
        run("sysctl", "-q", "-w", "net.ipv4.ip_forward=1")
        await client(
            "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(.3);"
            "s.sendto(b'forbidden',('1.1.1.1',443));"
            "\ntry:s.recv(64);raise AssertionError('UDP forwarded')\nexcept TimeoutError:pass\n"
        )
        run("sysctl", "-q", "-w", "net.ipv4.ip_forward=0")
        assert boundary.check()
        print("real REDIRECT/original destination and closed-listener fail-closed: passed")
    finally:
        if intercepted is not None:
            await intercepted.close()
        for process in children:
            if process.returncode is None:
                process.kill()
                await process.wait()
        for server in servers:
            server.close()
            await server.wait_closed()
        for namespace in reversed(created):
            run("ip", "netns", "delete", namespace)
        for interface in ("eth1", "eth0"):
            subprocess.run(("ip", "link", "delete", interface), capture_output=True, check=False)
        assert not any(ns.encode() in run("ip", "netns", "list") for ns in created)
        print("temporary namespaces, links, clients and listeners removed")


if __name__ == "__main__":
    asyncio.run(main())
