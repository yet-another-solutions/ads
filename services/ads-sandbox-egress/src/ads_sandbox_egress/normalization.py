"""Disposable, bounded NGINX header-only normalization, never an HTTP proxy."""

from __future__ import annotations

import asyncio
import base64
import binascii
import math
import re
from pathlib import Path

from ads_sandbox_egress.framing import Headers, raw_http1_headers, validate_headers
from ads_sandbox_egress.policy import RequestDenied


def nginx_configuration(directory: Path) -> str:
    """Private runtime directory must be inaccessible to the execution guest.

    No TCP listener, filesystem serving, proxying, rewrites, body reader, or
    access log. NGINX's normalizer is authoritative; no Python URI normalization.
    """
    if not directory.is_absolute() or not re.fullmatch(r"/[A-Za-z0-9_./-]+", str(directory)):
        raise ValueError("unsafe helper directory")
    return f"""
load_module /usr/lib/nginx/modules/ndk_http_module.so;
load_module /usr/lib/nginx/modules/ngx_http_lua_module.so;
# Single-process helper already runs as container root without CAP_CHOWN.
# Keep its private temporary paths owned by that same identity.
user root;
daemon off;
master_process off;
pid {directory}/nginx.pid;
error_log stderr crit;
events {{ worker_connections 128; }}
http {{
    access_log off;
    client_body_temp_path {directory}/body;
    proxy_temp_path {directory}/proxy;
    fastcgi_temp_path {directory}/fastcgi;
    uwsgi_temp_path {directory}/uwsgi;
    scgi_temp_path {directory}/scgi;
    client_max_body_size 0;
    client_header_timeout 2s;
    client_body_timeout 2s;
    send_timeout 2s;
    lingering_close off;
    keepalive_timeout 0;
    large_client_header_buffers 4 16k;
    lua_need_request_body off;
    server {{
        listen unix:{directory}/normalize.sock;
        server_name _;
        merge_slashes on;
        location / {{
            content_by_lua_block {{
                ngx.header["X-ADS-Normalized-Path"] = ngx.encode_base64(ngx.var.uri)
                return ngx.exit(204)
            }}
        }}
    }}
}}
"""


class Normalizer:
    def __init__(self, socket_path: Path, *, timeout: float = 2, concurrency: int = 32) -> None:
        if not math.isfinite(timeout) or timeout <= 0 or not 1 <= concurrency <= 128:
            raise ValueError("invalid normalization bounds")
        self.path, self.timeout = socket_path, timeout
        self._slots = asyncio.Semaphore(concurrency)

    async def normalize(self, method: bytes, target: bytes, headers: Headers) -> bytes:
        if (
            not re.fullmatch(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", method)
            or not target
            or len(target) > 8192
            or any(char <= 32 or char == 127 for char in target)
        ):
            raise RequestDenied("invalid_normalization_request")
        headers = validate_headers(headers)
        if any(name.startswith(b":") for name, _ in headers):
            raise RequestDenied("normalizer_requires_protocol_adapter")
        hosts = [value for name, value in headers if name == b"host"]
        if len(hosts) > 1:
            raise RequestDenied("normalization_multiple_hosts")
        # Approved no-authority adapter, only for this private no-body exchange.
        # Protocol validity/identity were checked by RequestHead/authorizer.
        # Retain method, exact target, Expect and all other header semantics;
        # never change the separately retained request or its upstream framing.
        version = b"1.1"
        if not hosts or hosts == [b""]:
            version = b"1.0"
            headers = tuple(
                (name, value)
                for name, value in headers
                if name not in (b"host", b"transfer-encoding")
            )
        request = method + b" " + target + b" HTTP/" + version + b"\r\n"
        request += b"".join(name + b": " + value + b"\r\n" for name, value in headers) + b"\r\n"
        if len(request) > 65536:
            raise RequestDenied("normalization_header_limit")
        writer: asyncio.StreamWriter | None = None
        try:
            async with asyncio.timeout(self.timeout), self._slots:
                reader, writer = await asyncio.open_unix_connection(self.path, limit=65536)
                writer.write(request)
                await writer.drain()
                informational = 0
                while True:
                    block = await reader.readuntil(b"\r\n\r\n")
                    start, result = raw_http1_headers(block)
                    if not re.fullmatch(rb"HTTP/1[.][01] [0-9]{3}(?: [^\r\n]*)?", start):
                        raise RequestDenied("invalid_normalization_response")
                    status = int(start.split(b" ", 2)[1])
                    if 100 <= status < 200 and status != 101:
                        informational += 1
                        if informational > 4:
                            raise RequestDenied("normalization_interim_limit")
                        continue
                    if status != 204:
                        raise RequestDenied("normalization_rejected")
                    fields = [v for n, v in result if n == b"x-ads-normalized-path"]
                    if len(fields) != 1 or len(fields[0]) > 10924:
                        raise RequestDenied("invalid_normalization_result")
                    if any(
                        n == b"transfer-encoding" or n == b"content-length" and v != b"0"
                        for n, v in result
                    ):
                        raise RequestDenied("normalization_response_body")
                    path = base64.b64decode(fields[0], validate=True)
                    if (
                        base64.b64encode(path) != fields[0]
                        or not path.startswith(b"/")
                        or len(path) > 8192
                        or b"\0" in path
                    ):
                        raise RequestDenied("invalid_normalization_result")
                    return path
        except (
            OSError,
            TimeoutError,
            ValueError,
            binascii.Error,
            asyncio.IncompleteReadError,
            asyncio.LimitOverrunError,
        ) as exc:
            raise RequestDenied("normalization_unavailable") from exc
        finally:
            if writer is not None:
                writer.close()
                try:
                    async with asyncio.timeout(self.timeout):
                        await writer.wait_closed()
                except (OSError, TimeoutError):
                    writer.transport.abort()
