"""Supervised real NGINX normalizer. One private socket, no external listener."""

from __future__ import annotations

import asyncio
import os
import subprocess
from pathlib import Path

from ads_sandbox_egress.normalization import Normalizer, nginx_configuration


class Helper:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.normalizer = Normalizer(directory / "normalize.sock")
        self.process: subprocess.Popen[bytes] | None = None

    async def start(self) -> None:
        if self.process is not None:
            raise RuntimeError("helper already started")
        self.directory.mkdir(mode=0o700)
        config = self.directory / "nginx.conf"
        with config.open("x") as stream:
            stream.write(nginx_configuration(self.directory))
        self.process = subprocess.Popen(
            ["nginx", "-p", str(self.directory), "-c", str(config)],
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            async with asyncio.timeout(5):
                while not self.normalizer.path.exists():
                    if self.process.poll() is not None:
                        raise RuntimeError("normalizer exited during startup")
                    await asyncio.sleep(0.01)
                os.chmod(self.normalizer.path, 0o600)
                if not await self.healthy():
                    raise RuntimeError("normalizer startup check failed")
        except BaseException:
            await self.close()
            raise

    async def healthy(self) -> bool:
        if self.process is None or self.process.poll() is not None:
            return False
        return (
            await self.normalizer.normalize(
                b"GET", b"/ads/./health//%70robe?ignored=1", ((b"host", b"health.invalid"),)
            )
            == b"/ads/health/probe"
        )

    async def close(self) -> None:
        process, self.process = self.process, None
        if process is None:
            return
        if process.poll() is None:
            process.terminate()
        try:
            await asyncio.to_thread(process.wait, 2)
        except subprocess.TimeoutExpired:
            process.kill()
            await asyncio.to_thread(process.wait, 2)
