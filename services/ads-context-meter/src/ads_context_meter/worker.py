"""One isolated counting worker; JWT verification remains in the REST process."""

import asyncio
import multiprocessing
from concurrent.futures import ProcessPoolExecutor

from ads_commons.context_meter import MeterRequest
from ads_context_meter.config import Settings
from ads_context_meter.counter import count, initialize


class TokenCounter:
    def __init__(self, settings: Settings) -> None:
        self._pool = ProcessPoolExecutor(
            max_workers=1,
            mp_context=multiprocessing.get_context("spawn"),
            initializer=initialize,
            initargs=(str(settings.tokenizer_directory),),
        )
        # Startup fails before listen if any baked tokenizer is absent/corrupt,
        # or any import attempts a download. Warmup carries no caller credentials.
        try:
            self._pool.submit(count, MeterRequest("glm-5.2", [])).result(timeout=60)
        except BaseException:
            self._pool.shutdown(wait=False, cancel_futures=True)
            raise
        self._slot = asyncio.Semaphore(1)

    async def count(self, body: MeterRequest) -> int:
        async with self._slot:
            return await asyncio.wrap_future(self._pool.submit(count, body))

    def close(self) -> None:
        self._pool.shutdown(wait=True, cancel_futures=True)
