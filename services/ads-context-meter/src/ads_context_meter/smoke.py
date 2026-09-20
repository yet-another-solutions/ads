"""Run the real baked-tokenizer path in a fresh, network-less image."""

import asyncio
import os
from pathlib import Path
from tempfile import TemporaryDirectory

from ads_commons.context_meter import MeterRequest, ReasoningMessage, SystemMessage
from ads_commons.engine import AssistantHistoryTurn, ToolCall, ToolResult, UserHistoryTurn
from ads_context_meter.config import Settings
from ads_context_meter.worker import TokenCounter


async def smoke() -> None:
    directory = Path(os.environ.get("ADS_CONTEXT_METER_TOKENIZER_DIRECTORY", "/opt/tokenizers"))
    with TemporaryDirectory() as empty:
        os.environ["HOME"] = empty
        os.environ["HF_HOME"] = empty
        settings = Settings("", "", "", "", directory, Path("unused"), Path("unused"), None, "", 0)
        counter = TokenCounter(settings)
        try:
            for model in ("glm-5.2", "glm-5.3"):
                body = MeterRequest(
                    model,
                    [
                        SystemMessage("Be helpful."),
                        UserHistoryTurn("Hello, мир, 你好"),
                        ReasoningMessage("Plan a tool call."),
                        ToolCall("call-1", "exec_python", {"code": "print(42)"}),
                        ToolResult("call-1", "exec_python", "success", {"stdout": "42"}),
                        AssistantHistoryTurn("42"),
                    ],
                )
                first = await counter.count(body)
                assert first > 0
                assert await counter.count(body) == first
                print(f"{model}: {first} estimated tokens (offline)")
        finally:
            counter.close()


if __name__ == "__main__":
    asyncio.run(smoke())
