from __future__ import annotations

import base64
import http.client
import importlib.machinery
import importlib.util
import json
import os
import ssl
import subprocess
import threading
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

SCRIPT = Path(__file__).parents[2] / "services/ads-ptp-tools/ads-ptp-relay"


@pytest.fixture
def relay():
    loader = importlib.machinery.SourceFileLoader("ptp_relay", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@pytest.fixture
def config():
    return {
        "pod_uid": str(uuid4()),
        "generation": str(uuid4()),
        "sandbox_id": str(uuid4()),
        "side": "guest",
        "local_private": "10.10.30.2/24",
        "peer_private": "10.10.30.1/24",
        "local_tunnel": "10.10.40.2/32",
        "peer_tunnel": "10.10.40.1/32",
        "transport_mtu": 1450,
        "peer_key": base64.b64encode(bytes(range(32))).decode(),
        "endpoint": "10.32.0.99:51820",
        "wireguard_port": 51820,
        "vxlan_port": 4789,
        "vni": 42,
        "packet_rate": 10000,
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("side", "host"),
        ("pod_uid", "no"),
        ("generation", "no"),
        ("sandbox_id", "no"),
        ("local_private", "127.0.0.2/24"),
        ("local_private", "10.10.30.0/24"),
        ("local_private", "10.10.30.2/32"),
        ("peer_private", "10.10.30.255/24"),
        ("peer_private", "10.10.30.2/24"),
        ("peer_private", "10.10.31.1/24"),
        ("local_tunnel", "10.10.40.2/24"),
        ("peer_tunnel", "10.10.30.1/32"),
        ("peer_tunnel", "10.10.40.2/32"),
        ("transport_mtu", True),
        ("transport_mtu", 685),
        ("vni", 0),
        ("packet_rate", 0),
        ("packet_rate", 100001),
        ("wireguard_port", 53),
        ("peer_key", "bad"),
        ("endpoint", "service.invalid:51820"),
        ("endpoint", "10.32.0.1:9999"),
        ("endpoint", "224.0.0.1:51820"),
        ("endpoint", "0.0.0.0:51820"),
    ],
)
def test_invalid_relay_inputs_fail_before_effect(relay, config, field, value):
    pod, generation = config["pod_uid"], config["generation"]
    config[field] = value
    with pytest.raises((ValueError, TypeError)):
        relay.validate(config, pod, generation)


def test_exact_identity_configuration_and_egress_endpoint(relay, config):
    pod, generation = config["pod_uid"], config["generation"]
    assert relay.validate(config, pod, generation) == config
    with pytest.raises(ValueError):
        relay.validate({**config, "extra": 1}, pod, generation)
    with pytest.raises(ValueError):
        relay.validate(config, str(uuid4()), generation)
    config["side"] = "egress"
    with pytest.raises(ValueError):
        relay.validate(config, pod, generation)
    config["endpoint"] = None
    assert relay.validate(config, pod, generation) == config


@pytest.mark.parametrize("side", ["guest", "egress"])
def test_firewall_bounds_frames_without_relay_forwarding_or_proxy_policy(relay, config, side):
    config["side"] = side
    if side == "egress":
        config["local_private"], config["peer_private"] = (
            config["peer_private"],
            config["local_private"],
        )
    rules = relay.firewall(config)
    assert rules.count("policy drop") == 6
    assert "table bridge ads_relay" in rules
    assert "arp operation { request, reply }" in rules
    assert "limit rate 20/second burst 40 packets" in rules
    assert "limit rate 10000/second burst 20000 packets" in rules
    assert "ip saddr 10.10.30.2" in rules
    assert "ip daddr 10.10.30.2" in rules
    assert "ether type ip" in rules and "ether type arp" in rules
    assert "ether type ip6" not in rules and "vlan" not in rules
    assert "masquerade" not in rules and "snat" not in rules and "eth0" not in rules
    assert "ip daddr 10.10.30.1" not in rules.split("ether type ip")[-1]
    assert relay.mac(config, "guest") != relay.mac(config, "egress")


@pytest.fixture
def runtime(relay, config, tmp_path):
    value = relay.Relay(config, tmp_path / "state", tmp_path / "key")
    value.state = {"complete": True}
    value.public_key = base64.b64encode(b"x" * 32).decode()
    return value


def healthy_outputs(runtime):
    return {
        "links": [
            {"ifname": "lo", "flags": ["UP"]},
            {"ifname": "wg-private", "flags": ["UP"]},
            {
                "ifname": "br-private",
                "ifindex": 2,
                "flags": ["UP"],
                "ifalias": runtime.bridge_alias,
                "linkinfo": {"info_kind": "bridge"},
            },
            {"ifname": "vxlan-private", "flags": ["UP"], "master": "br-private"},
        ],
        "peers": runtime.config["peer_key"],
        "public-key": runtime.public_key,
        "allowed-ips": runtime.config["peer_key"] + "\t" + runtime.config["peer_tunnel"],
    }


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "down",
        "extra-nic",
        "bridge",
        "membership",
        "peer",
        "key",
        "allowed",
        "session",
        "timeout",
        "incomplete",
    ],
)
def test_health_requires_configured_authenticated_active_session_without_mutations(
    runtime, monkeypatch, fault
):
    outputs = healthy_outputs(runtime)
    if fault == "down":
        outputs["links"][1]["flags"] = []
    elif fault == "extra-nic":
        outputs["links"].append({"ifname": "bypass", "flags": ["UP"]})
    elif fault == "bridge":
        outputs["links"][2]["ifalias"] = "foreign"
    elif fault == "membership":
        outputs["links"][3].pop("master")
    elif fault in ("peer", "key", "allowed"):
        outputs[{"peer": "peers", "key": "public-key", "allowed": "allowed-ips"}[fault]] = "wrong"
    elif fault == "incomplete":
        runtime.state["complete"] = False
    calls = []

    def observed(*args, **kwargs):
        calls.append((args, kwargs))
        assert kwargs["deadline"] > 0
        if args[:4] == ("ip", "-d", "-j", "link"):
            return json.dumps(outputs["links"])
        if args[0] == "wg":
            assert args[1] == "show" and args[-1] not in ("dump", "showconf", "private-key")
            return outputs[args[-1]]
        assert args[0] == "ping"
        if fault == "session":
            raise RuntimeError("no peer")
        if fault == "timeout":
            raise subprocess.TimeoutExpired("ping", 1)
        return ""

    monkeypatch.setattr(runtime, "ns", observed)
    assert runtime.healthy() is (fault is None)
    assert not any("set" in args or "add" in args or "delete" in args for args, _ in calls)
    if fault is None:
        assert calls[-1][0] == (
            "ping",
            "-n",
            "-I",
            "wg-private",
            "-c",
            "1",
            "-W",
            "1",
            "10.10.40.1",
        )


def test_health_tls_server_and_statuses(relay, tmp_path):
    certificate, private = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-subj",
            "/CN=relay-test",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
            "-days",
            "1",
            "-keyout",
            str(private),
            "-out",
            str(certificate),
        ],
        check=True,
        capture_output=True,
    )
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certificate, private)
    state = SimpleNamespace(value=True)
    runtime = SimpleNamespace(healthy=lambda: state.value)
    server = relay.HealthServer(("127.0.0.1", 0), server_context, runtime)
    worker = threading.Thread(target=server.serve_forever)
    worker.start()
    context = ssl.create_default_context(cafile=str(certificate))
    try:
        for healthy, path, status in (
            (True, "/health", 200),
            (False, "/health", 503),
            (True, "/configuration", 404),
        ):
            state.value = healthy
            connection = http.client.HTTPSConnection(
                *server.server_address, context=context, timeout=5
            )
            try:
                connection.request("GET", path)
                response = connection.getresponse()
                assert response.status == status
                if path == "/health":
                    assert response.read() == b""
            finally:
                connection.close()
    finally:
        server.shutdown()
        worker.join(5)
        server.server_close()
    assert not worker.is_alive()


def test_protected_input_rejects_symlink_and_untrusted_metadata(relay, tmp_path, monkeypatch):
    file = tmp_path / "input"
    file.write_bytes(b"safe")
    file.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(file)
    with pytest.raises(OSError):
        relay.protected(link)
    real = relay.os.fstat

    def metadata(fd):
        info = real(fd)
        return SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_size=info.st_size)

    monkeypatch.setattr(relay.os, "fstat", metadata)
    assert relay.protected(file) == b"safe"
    file.chmod(0o644)
    with pytest.raises(ValueError):
        relay.protected(file)
    with pytest.raises(ValueError):
        relay.pairs([("field", 1), ("field", 2)])


def test_tls_failure_precedes_any_network_effect(relay, config, tmp_path, monkeypatch):
    monkeypatch.setenv("POD_UID", config["pod_uid"])
    monkeypatch.setenv("ATTACHMENT_GENERATION", config["generation"])
    monkeypatch.setattr(relay, "protected", lambda _: json.dumps(config).encode())
    monkeypatch.setattr(relay.Relay, "start", lambda _: pytest.fail("network changed before TLS"))
    monkeypatch.setattr(
        "sys.argv",
        [
            "ads-ptp-relay",
            "--config",
            "config",
            "--key",
            "key",
            "--cert",
            str(tmp_path / "absent"),
            "--tls-key",
            "key",
            "--state",
            str(tmp_path / "state"),
        ],
    )
    with pytest.raises(FileNotFoundError):
        relay.main()


def test_zero_key_and_self_peer_reject_before_state_creation(relay, config, tmp_path, monkeypatch):
    with pytest.raises(ValueError):
        relay.key(base64.b64encode(bytes(32)).decode())
    monkeypatch.setattr(relay.os, "geteuid", lambda: 0)
    monkeypatch.setattr(relay, "protected", lambda _: config["peer_key"].encode())
    monkeypatch.setattr(relay, "run", lambda *args, **kwargs: config["peer_key"])
    runtime = relay.Relay(config, tmp_path / "state", tmp_path / "key")
    with pytest.raises(ValueError, match="self peer"):
        runtime.start()
    assert not runtime.root.exists()


def test_replaced_namespace_is_never_destroyed(relay, config, tmp_path, monkeypatch):
    runtime = relay.Relay(config, tmp_path / "state", tmp_path / "key")
    runtime.root.mkdir()
    runtime.path = tmp_path / "namespace"
    runtime.path.touch()
    runtime.state = {
        "pod_uid": config["pod_uid"],
        "generation": config["generation"],
        "private": [1, 2],
        "complete": True,
    }
    monkeypatch.setattr(relay.fcntl, "ioctl", lambda *args: 0x40000000)
    monkeypatch.setattr(relay, "run", lambda *a, **kw: pytest.fail("must not mutate network"))
    with pytest.raises(ValueError, match="namespace replaced"):
        runtime.stop()
    assert runtime.path.exists()
    assert json.loads((runtime.root / "state.json").read_text())["complete"] is False


@pytest.mark.parametrize("foreign", [False, True])
def test_cleanup_of_incomplete_birthplace_link_requires_creation_group(
    relay, config, tmp_path, monkeypatch, foreign
):
    runtime = relay.Relay(config, tmp_path / "state", tmp_path / "key")
    runtime.root.mkdir()
    info = os.stat("/proc/self/ns/net")
    runtime.state = {
        "pod_uid": config["pod_uid"],
        "generation": config["generation"],
        "private": None,
        "complete": False,
        "transport": [info.st_dev, info.st_ino],
    }
    calls = []

    def observed(*args, **kwargs):
        calls.append(args)
        if args == ("ip", "-N", "-d", "-j", "link"):
            return json.dumps(
                [
                    {
                        "ifname": "wg-private",
                        "linkinfo": {"info_kind": "wireguard"},
                        "group": str(runtime.group + 1 if foreign else runtime.group),
                    }
                ]
            )
        if args == ("ip", "-j", "link"):
            return "[]"
        assert args == ("ip", "link", "delete", "wg-private")
        return ""

    monkeypatch.setattr(relay, "run", observed)
    if foreign:
        with pytest.raises(ValueError, match="foreign transport"):
            runtime.stop()
        assert len(calls) == 1
    else:
        runtime.stop()
        assert runtime.state["stopped"] is True
        assert len(calls) == 3


def test_health_worker_has_absolute_deadline_and_releases_slot(relay, monkeypatch):
    observed = []

    class Timer:
        def __init__(self, seconds, callback, args):
            assert seconds == 6
            self.callback, self.args = callback, args

        def start(self):
            observed.append("start")
            self.callback(*self.args)

        def cancel(self):
            observed.append("cancel")

    request = SimpleNamespace(
        shutdown=lambda how: observed.append(("shutdown", how)),
        close=lambda: observed.append("close"),
    )
    server = object.__new__(relay.HealthServer)
    server.slots = threading.BoundedSemaphore(1)
    assert server.slots.acquire(blocking=False)
    monkeypatch.setattr(relay.threading, "Timer", Timer)
    monkeypatch.setattr(
        relay.ThreadingHTTPServer,
        "process_request_thread",
        lambda *args: observed.append("handled"),
    )
    server.process_request_thread(request, ("127.0.0.1", 12345))
    assert observed == ["start", ("shutdown", relay.socket.SHUT_RDWR), "close", "handled", "cancel"]
    assert server.slots.acquire(blocking=False)
