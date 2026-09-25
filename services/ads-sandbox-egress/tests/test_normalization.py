import asyncio
import shutil
import subprocess
import time

import pytest

from ads_sandbox_egress.normalization import Normalizer, nginx_configuration
from ads_sandbox_egress.policy import RequestDenied


@pytest.fixture
def nginx_helper(tmp_path):
    if shutil.which("nginx") is None:
        pytest.skip("real NGINX/Lua executable unavailable")
    config = tmp_path / "nginx.conf"
    config.write_text(nginx_configuration(tmp_path))
    process = subprocess.Popen(
        ["nginx", "-p", str(tmp_path), "-c", str(config)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 5
        while not (tmp_path / "normalize.sock").exists():
            if process.poll() is not None:
                pytest.fail("NGINX failed: " + process.stderr.read().decode()[:2048])
            if time.monotonic() >= deadline:
                pytest.fail("NGINX socket startup deadline")
            time.sleep(0.01)
        yield Normalizer(tmp_path / "normalize.sock")
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        process.stderr.close()


@pytest.mark.parametrize("method", [b"GET", b"HEAD", b"POST", b"PATCH", b"OPTIONS"])
def test_real_helper_no_body_wait_or_target_rewrite(nginx_helper, method):
    async def run():
        target = b"/a/%62/../c//D?query=%2f"
        headers = (
            (b"host", b"example.com"),
            (b"content-length", b"1000000000000"),
            (b"expect", b"100-continue"),
        )
        result = await nginx_helper.normalize(method, target, headers)
        assert result == b"/a/c/D"
        assert target == b"/a/%62/../c//D?query=%2f"
        assert await nginx_helper.normalize(b"GET", b"/x", ((b"host", b"example.com"),)) == b"/x"

    asyncio.run(run())


def test_real_helper_rejects_bad_target_without_fallback(nginx_helper):
    async def run():
        with pytest.raises(RequestDenied):
            await nginx_helper.normalize(b"GET", b"/%GG", ((b"host", b"example.com"),))

    asyncio.run(run())


@pytest.mark.parametrize("method,target", [(b"CONNECT", b"/chat"), (b"OPTIONS", b"*")])
def test_real_helper_parser_compatibility_blockers_are_explicit(nginx_helper, method, target):
    # Raw NGINX remains incompatible. Approved adapters are outside this
    # primitive: GET for extended CONNECT, no URI normalization for OPTIONS *.
    async def run():
        with pytest.raises(RequestDenied, match="normalization_rejected"):
            await nginx_helper.normalize(method, target, ((b"host", b"origin.example"),))

    asyncio.run(run())


@pytest.mark.parametrize("host", [(), ((b"host", b""),)])
@pytest.mark.parametrize(
    "framing",
    [
        (),
        ((b"content-length", b"1000000000000"), (b"expect", b"100-continue")),
        ((b"transfer-encoding", b"chunked"), (b"expect", b"100-continue")),
    ],
)
def test_real_no_authority_envelope_is_bodyless_and_normalizes(nginx_helper, host, framing):
    async def run():
        original = host + framing
        assert await nginx_helper.normalize(b"POST", b"/a/%62/../c//D?q=%2f", original) == b"/a/c/D"
        assert original == host + framing
        with pytest.raises(RequestDenied, match="normalization_rejected"):
            await nginx_helper.normalize(b"POST", b"/%GG", original)

    asyncio.run(run())


def test_no_authority_adapter_changes_only_helper_envelope(tmp_path):
    async def run():
        seen = []
        complete = asyncio.Event()

        async def handle(reader, writer):
            try:
                seen.append(await reader.readuntil(b"\r\n\r\n"))
                writer.write(b"HTTP/1.0 204 No Content\r\nX-ADS-Normalized-Path: L2E=\r\n\r\n")
                await writer.drain()
                assert await reader.read() == b""  # No body, terminating chunk or reuse.
            finally:
                writer.close()
                await writer.wait_closed()
                complete.set()

        path = tmp_path / "capture.sock"
        server = await asyncio.start_unix_server(handle, path)
        original = (
            (b"host", b""),
            (b"transfer-encoding", b"chunked"),
            (b"expect", b"100-continue"),
            (b"x-end", b"retained"),
        )
        async with server:
            assert await Normalizer(path).normalize(b"PATCH", b"/%61?raw=%2f", original) == b"/a"
            await asyncio.wait_for(complete.wait(), 2)
        assert seen == [
            b"PATCH /%61?raw=%2f HTTP/1.0\r\nexpect: 100-continue\r\nx-end: retained\r\n\r\n"
        ]
        assert original[:2] == ((b"host", b""), (b"transfer-encoding", b"chunked"))

    asyncio.run(run())


@pytest.mark.parametrize(
    "headers",
    [
        ((b"host", b""), (b"host", b"")),
        ((b"host", b""), (b"host", b"origin.example")),
        ((b"host", b""), (b"content-length", b"3"), (b"transfer-encoding", b"chunked")),
        ((b"host", b""), (b"transfer-encoding", b"gzip")),
    ],
)
def test_no_authority_adapter_never_sanitizes_malformed_input(nginx_helper, headers):
    async def run():
        with pytest.raises(RequestDenied):
            await nginx_helper.normalize(b"POST", b"/", headers)

    asyncio.run(run())


@pytest.mark.parametrize(
    "response",
    [
        b"HTTP/1.1 204 No Content\r\n\r\n",
        b"HTTP/1.1 403 Denied\r\nX-ADS-Normalized-Path: Lw==\r\n\r\n",
        b"HTTP/1.1 204 No Content\r\nX-ADS-Normalized-Path: Lw==\r\n"
        b"X-ADS-Normalized-Path: Lw==\r\n\r\n",
        b"HTTP/1.1 204 No Content\r\nX-ADS-Normalized-Path: ****\r\n\r\n",
        b"HTTP/1.1 204 No Content\r\nX-ADS-Normalized-Path: Lw==\r\nContent-Length: 100\r\n\r\n",
    ],
)
def test_invalid_helper_output_is_never_path_or_success(tmp_path, response):
    async def run():
        async def handle(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            writer.write(response)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        socket = tmp_path / "fixture.sock"
        server = await asyncio.start_unix_server(handle, socket)
        async with server:
            with pytest.raises(RequestDenied):
                await Normalizer(socket).normalize(b"GET", b"/", ((b"host", b"example.com"),))

    asyncio.run(run())
