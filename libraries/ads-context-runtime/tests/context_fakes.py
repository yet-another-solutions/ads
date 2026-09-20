import json
from uuid import uuid4

from langchain_core.messages import AIMessage

from ads_commons.context_meter import MeterResponse
from ads_commons.engine import (
    OpenAiBearerToken,
    OpenAiStreamAuthentication,
    OpenAiStreamModel,
    OpenAiStreamOptions,
    Tombstone,
)


def model_settings(total=10000):
    return OpenAiStreamModel(
        url="https://model.test/v1",
        options=OpenAiStreamOptions(model_name="glm-5.3", max_context_tokens=total),
        authentication=OpenAiStreamAuthentication(openai_bearer=OpenAiBearerToken("model-secret")),
    )


def memory(messages=(), remaining=(), inner=None, summary="summary"):
    return Tombstone(uuid4(), summary, list(messages), list(remaining), inner)


class Meter:
    def __init__(self):
        self.calls = []

    async def meter(self, body):
        self.calls.append(list(body.messages))
        size = 0
        for item in body.messages:
            if isinstance(item, Tombstone):
                size += 100 + len(item.summarization)
            elif hasattr(item, "text"):
                size += len(item.text)
            else:
                import msgspec

                size += len(json.dumps(msgspec.to_builtins(item)))
        return MeterResponse(size)


class Model:
    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = []

    async def invoke(self, messages, tools, cap):
        self.calls.append((messages, tools, cap))
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer if isinstance(answer, AIMessage) else AIMessage(answer)


def native(name, args=None, text=""):
    return AIMessage(text, tool_calls=[{"id": str(uuid4()), "name": name, "args": args or {}}])
