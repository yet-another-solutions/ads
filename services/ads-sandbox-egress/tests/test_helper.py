import asyncio
import os
import shutil

import pytest

from ads_sandbox_egress.helper import Helper
from ads_sandbox_egress.normalization import nginx_configuration


def test_single_process_helper_keeps_existing_identity_without_chown(tmp_path):
    configuration = nginx_configuration(tmp_path)
    assert "\nuser root;\n" in configuration
    assert "\nmaster_process off;\n" in configuration
    assert f"listen unix:{tmp_path}/normalize.sock;" in configuration
    for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"):
        assert f"{name}_temp_path {tmp_path}/" in configuration


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
