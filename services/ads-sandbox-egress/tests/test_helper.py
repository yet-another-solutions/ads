import asyncio
import os
import shutil

import pytest

from ads_sandbox_egress.helper import Helper


@pytest.mark.skipif(shutil.which("nginx") is None, reason="real NGINX/Lua unavailable")
def test_real_supervised_helper_health_and_cleanup(tmp_path):
    async def run():
        helper = Helper(tmp_path / "helper")
        await helper.start()
        process = helper.process
        try:
            assert await helper.healthy()
            assert helper.normalizer.path.stat().st_mode & 0o777 == 0o600
            process.terminate()
            await asyncio.to_thread(process.wait, 2)
            assert not await helper.healthy()
        finally:
            await helper.close()
        assert process.poll() is not None and helper.process is None
        with pytest.raises(ProcessLookupError):
            os.kill(process.pid, 0)

    asyncio.run(run())
