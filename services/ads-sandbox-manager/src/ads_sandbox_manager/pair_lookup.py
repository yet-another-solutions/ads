"""CNI pair lookup: read-only /v1/pair served to ads-ptp-cni over mTLS.

G9: pod annotations are the join key. The plugin dials
``GET /v1/pair?generation=<uuid>&role=<role>&pod_uid=<uid>`` with a client
certificate (CN ``ads-ptp-cni``); the manager answers from PairIntent state.
One read-only route, stdlib http.server behind TLS, dedicated asyncio loop
thread so the engine loop keeps its affinity.
"""

from __future__ import annotations

import asyncio
import json
import re
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.kube import KubeClient
from ads_sandbox_manager.pair_store import PairIntent

LIMIT = 8192
CLIENT_CN = "ads-ptp-cni"
GATEWAY = "10.10.30.1"
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
VM_ROLES = ("guest", "egress")


def container_identity(pod: dict[str, Any], name: str) -> str | None:
    """CRI runtime identity of the named container, without any runtime prefix."""
    for status in pod.get("status", {}).get("containerStatuses", []):
        if status.get("name") == name:
            raw = status.get("containerID")
            if not isinstance(raw, str) or not raw.strip():
                return None
            return raw.split("//", 1)[-1] or None
    return None


def binding_record(
    pair: dict[str, Any],
    role: str,
    payload: dict[str, Any],
    relay_pod_uid: str,
    relay_runtime_id: str,
) -> dict[str, Any]:
    """The PARTIAL record: plugin adds ifname + private/transport identities."""
    guest = role == "guest"
    config = payload["configuration"]
    # The plugin needs the bare IP; the configuration carries a /24.
    address = config["local_private"].split("/", 1)[0]
    return {
        "pod_uid": str(pair["pod_uid"]),
        "generation": str(pair["generation"]),
        "sandbox_id": str(pair["sandbox_id"]),
        "role": role,
        "network": pair["network"],
        "relay_pod_uid": relay_pod_uid,
        "relay_runtime_id": relay_runtime_id,
        "mtu": payload["runtime"]["transport_mtu"] - 110,
        "address": address,
        "gateway": GATEWAY if guest else None,
    }


class PairLookup:
    """Pure lookup logic over (generation, role); DB + kube injected per request."""

    def __init__(
        self, settings: Settings, sessions_factory: Any = None, kube_factory: Any = None
    ) -> None:
        self.settings = settings
        self.sessions_factory = sessions_factory
        self.kube_factory = kube_factory
        self.network = "ads-sandbox"

    async def lookup(
        self, db: AsyncSession, kube: Any, generation: UUID, role: str, pod_uid: str | None
    ) -> tuple[int, dict[str, Any]]:
        if role not in VM_ROLES:
            return 404, {}
        intent = await db.get(PairIntent, generation)
        if intent is None or intent.retired_at is not None:
            # Unknown AND retired generations are indistinguishable: 404.
            return 404, {}
        if intent.namespace != self.settings.namespace:
            return 404, {}
        captured = intent.compute_uids.get(f"Pod/{role}")
        # G9: the join works before uid capture; a captured mismatch is fatal.
        if captured is not None and pod_uid is not None and captured != pod_uid:
            return 404, {}
        relay_role = {"guest": "guest-relay", "egress": "egress-relay"}[role]
        inputs = intent.relay_inputs.get(relay_role)
        payload = (inputs or {}).get("payload")
        if payload is None:
            return 503, {"Retry-After": "1"}
        relay_uid = intent.compute_uids.get(f"Pod/{relay_role}")
        if relay_uid is None:
            return 503, {"Retry-After": "1"}
        relay_pod = await kube._get(
            kube.core.read_namespaced_pod, f"ads-{relay_role}-{intent.sandbox_id}"
        )
        if relay_pod is None:
            return 503, {"Retry-After": "1"}
        relay_runtime_id = container_identity(relay_pod, "relay")
        if relay_runtime_id is None:
            return 503, {"Retry-After": "1"}
        return (
            200,
            binding_record(
                {
                    "pod_uid": captured or pod_uid,
                    "generation": str(generation),
                    "sandbox_id": str(intent.sandbox_id),
                    "network": self.network,
                },
                role,
                payload,
                relay_uid,
                relay_runtime_id,
            ),
        )

    async def handle(
        self, generation: str, role: str, pod_uid: str | None
    ) -> tuple[int, dict[str, Any], dict[str, str]]:
        """Canonical parse + one request-scoped engine/kube pair."""
        if (
            not UUID_RE.fullmatch(generation or "")
            or role not in VM_ROLES
            or (pod_uid is not None and not UUID_RE.fullmatch(pod_uid))
        ):
            return 400, {"error": "invalid query"}, {}
        engine = create_async_engine(self.settings.database_url, pool_pre_ping=True, echo=False)
        try:
            sessions = async_sessionmaker(engine, expire_on_commit=False)
            kube = KubeClient(self.settings)
            try:
                async with sessions() as db:
                    status, body = await self.lookup(db, kube, UUID(generation), role, pod_uid)
            finally:
                await kube.close()
        finally:
            await engine.dispose()
        headers = {"Retry-After": "1"} if status == 503 else {}
        return status, body, headers


class _Handler(BaseHTTPRequestHandler):
    server: PairLookupServer

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        parts = urlsplit(self.path)
        if parts.path != "/v1/pair":
            self._respond(404, {"error": "unknown route"})
            return
        query = parse_qs(parts.query, keep_blank_values=True)
        generation = (query.get("generation") or [""])[0].strip()
        role = (query.get("role") or [""])[0].strip()
        raw_uid = (query.get("pod_uid") or [""])[0]
        pod_uid = raw_uid.strip() if raw_uid.strip() else None
        peer = self.connection.getpeercert() or {}
        cn = ""
        for rdn in peer.get("subject", ()):
            for key, value in rdn:
                if key == "commonName":
                    cn = value
        if cn != CLIENT_CN:
            self._respond(403, {"error": "unauthorized client"})
            return
        try:
            status, body, headers = asyncio.run(
                self.server.lookup.handle(generation, role, pod_uid)
            )
        except Exception:  # noqa: BLE001 - handler must never crash the thread
            status, body, headers = 500, {"error": "lookup failed"}, {}
        self._respond(status, body, headers)

    def _respond(
        self, status: int, body: dict[str, Any], headers: dict[str, str] | None = None
    ) -> None:
        data = json.dumps(body, separators=(",", ":")).encode()
        if len(data) > LIMIT:
            self.send_response(500)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args: Any) -> None:  # silence per-request stderr
        return


class PairLookupServer(ThreadingHTTPServer):
    daemon_threads = True
    lookup: PairLookup


class PairLookupListener:
    """serve_forever thread + dedicated asyncio loop thread (engine affinity)."""

    def __init__(self, settings: Settings, context: ssl.SSLContext) -> None:
        self.settings = settings
        self.context = context
        self.httpd: PairLookupServer | None = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self._loop_thread: threading.Thread | None = None
        self._serve_thread: threading.Thread | None = None

    def start(self) -> None:
        pair_lookup = self.settings.pair_lookup
        assert pair_lookup is not None  # __main__ constructs only when configured
        lookup = PairLookup(self.settings)
        httpd = PairLookupServer((pair_lookup.host, pair_lookup.port), _Handler)
        httpd.lookup = lookup
        httpd.socket = self.context.wrap_socket(httpd.socket, server_side=True)
        self.httpd = httpd
        self.loop = asyncio.new_event_loop()
        self._loop_thread = threading.Thread(
            target=self.loop.run_forever, name="pair-lookup-loop", daemon=True
        )
        self._serve_thread = threading.Thread(
            target=httpd.serve_forever,
            kwargs={"poll_interval": 0.5},
            name="pair-lookup-serve",
            daemon=True,
        )
        self._loop_thread.start()
        self._serve_thread.start()

    def stop(self) -> None:
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None
        if self.loop is not None:
            self.loop.call_soon_threadsafe(self.loop.stop)
            if self._loop_thread is not None:
                self._loop_thread.join(timeout=5)
            self.loop.close()
            self.loop = None
