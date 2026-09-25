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
    # Feasibility evidence, NOT accepted support for these valid protocol
    # shapes. An adapter must be reviewed before these become success cases.
    async def run():
        with pytest.raises(RequestDenied, match="normalization_rejected"):
            await nginx_helper.normalize(method, target, ((b"host", b"origin.example"),))

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
