import json
import os
import subprocess
import sys
from pathlib import Path

import msgspec
import pytest

from ads_commons.context_meter import MeterRequest, ReasoningMessage, SystemMessage
from ads_commons.engine import AssistantHistoryTurn, ToolCall, ToolResult, UserHistoryTurn
from ads_context_meter.assets import TOKENIZERS, read_tokenizer
from ads_context_meter.bake import bake
from ads_context_meter.counter import counting_messages

ROOT = Path(__file__).resolve().parents[3]


def test_primitives_preserve_text_and_tool_fields_without_metadata():
    request = MeterRequest(
        "glm-5.3",
        [
            SystemMessage("instructions"),
            UserHistoryTurn("hello"),
            ReasoningMessage("internal reasoning"),
            AssistantHistoryTurn("answer"),
            ToolCall("call", "exec_python", {"code": "print('你好')"}, {"trace": "not-context"}),
            ToolResult(
                "call", "exec_python", "error", {"stderr": "failed"}, {"artifact": "not-context"}
            ),
        ],
    )
    messages = counting_messages(request)
    assert messages[:4] == [
        {"role": "system", "content": "instructions"},
        {"role": "user", "content": "hello"},
        {"role": "assistant", "content": "<think>internal reasoning</think>"},
        {"role": "assistant", "content": "answer"},
    ]
    assert json.loads(messages[4]["content"]) == {
        "tool_call": {"id": "call", "name": "exec_python", "arguments": {"code": "print('你好')"}},
    }
    assert json.loads(messages[5]["content"]) == {
        "tool_call_id": "call",
        "name": "exec_python",
        "status": "error",
        "content": {"stderr": "failed"},
    }
    assert "not-context" not in json.dumps(messages)
    assert msgspec.json.decode(msgspec.json.encode(request), type=MeterRequest) == request


def test_missing_and_corrupt_assets_fail_closed(tmp_path):
    with pytest.raises(FileNotFoundError):
        read_tokenizer(tmp_path, "glm-5.3")
    (tmp_path / "glm-5.3.json").write_text("{}")
    with pytest.raises(RuntimeError, match="checksum"):
        read_tokenizer(tmp_path, "glm-5.3")
    with pytest.raises(KeyError):
        read_tokenizer(tmp_path, "../../remote")


def test_bake_verifies_pins_before_writing(tmp_path, monkeypatch):
    from io import BytesIO

    seen = []

    def download(url, timeout):
        seen.append(url)
        return BytesIO(b"corrupt")

    monkeypatch.setattr("ads_context_meter.bake.urlopen", download)
    with pytest.raises(RuntimeError, match="checksum"):
        bake(tmp_path)
    assert not list(tmp_path.iterdir())
    first = TOKENIZERS["glm-5.2"]
    assert seen == [
        f"https://huggingface.co/{first.repository}/resolve/{first.revision}/tokenizer.json",
    ]


def test_kernel_denies_native_and_python_network_but_parent_is_unaffected():
    script = """
import ctypes, socket, subprocess
from ads_context_meter.isolation import deny_network
deny_network()
libc = ctypes.CDLL(None, use_errno=True)
assert libc.socket(socket.AF_INET, socket.SOCK_STREAM, 0) == -1
assert ctypes.get_errno() == 1
for family in (socket.AF_INET, socket.AF_INET6):
    try:
        socket.socket(family, socket.SOCK_STREAM)
    except PermissionError:
        pass
    else:
        raise AssertionError("network socket allowed")
try:
    subprocess.run(["/bin/true"], check=True)
except PermissionError:
    pass
else:
    raise AssertionError("exec allowed")
print("denied")
"""
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=20
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "denied"
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM):
        pass


def test_real_litellm_cold_import_with_tiny_fixture_and_no_network(tmp_path):
    # No network, weights or large downloaded fixtures in the Python test suite.
    # Production pinned GLM tokenizers are exercised separately by the CI image smoke.
    tokenizer = {
        "version": "1.0",
        "truncation": None,
        "padding": None,
        "added_tokens": [],
        "normalizer": None,
        "pre_tokenizer": {"type": "Whitespace"},
        "post_processor": None,
        "decoder": None,
        "model": {"type": "WordLevel", "vocab": {"[UNK]": 0, "hello": 1}, "unk_token": "[UNK]"},
    }
    for name in TOKENIZERS:
        (tmp_path / f"{name}.json").write_text(json.dumps(tokenizer))
    script = """
import sys
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from ads_context_meter.assets import TOKENIZERS
from ads_context_meter.counter import initialize, count
from ads_commons.context_meter import MeterRequest, ReasoningMessage
from ads_commons.engine import UserHistoryTurn, ToolCall, ToolResult
directory = Path(sys.argv[1])
for name, asset in list(TOKENIZERS.items()):
    digest = sha256((directory / (name + ".json")).read_bytes()).hexdigest()
    TOKENIZERS[name] = replace(asset, sha256=digest)
initialize(str(directory))
for name in TOKENIZERS:
    empty = count(MeterRequest(name, []))
    base = count(MeterRequest(name, [UserHistoryTurn("hello")]))
    more = count(MeterRequest(name, [UserHistoryTurn("hello hello hello")]))
    reasoning = count(MeterRequest(name, [ReasoningMessage("hello hello")]))
    tool = count(MeterRequest(name, [ToolCall("a", "exec", {"code": "hello"}),
                                     ToolResult("a", "exec", "success", {"text": "hello"})]))
    assert empty == 3
    assert base == 8
    assert more == 10
    assert reasoning > base
    assert tool > reasoning
print("offline counts passed")
"""
    env = {
        **os.environ,
        "HOME": str(tmp_path),
        "HF_HOME": str(tmp_path / "empty"),
        "LITELLM_LOCAL_MODEL_COST_MAP": "False",
        "HF_HUB_OFFLINE": "0",
    }
    result = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "offline counts passed" in result.stdout


def test_missing_libseccomp_is_fatal(monkeypatch):
    from ads_context_meter.isolation import deny_network

    monkeypatch.setattr("ctypes.util.find_library", lambda name: None)
    with pytest.raises(RuntimeError, match="libseccomp"):
        deny_network()


def test_catalog_is_fully_baked_and_revisions_are_immutable():
    from ads_commons.model_catalog import SUPPORTED_MODEL_TYPES

    assert set(TOKENIZERS) == {n for t in SUPPORTED_MODEL_TYPES for n in t.names}
    for asset in TOKENIZERS.values():
        assert len(asset.revision) == 40
        assert len(asset.sha256) == 64
        assert int(asset.revision, 16)
        assert int(asset.sha256, 16)


def test_worker_missing_assets_exits_quickly(tmp_path):
    script = """
from pathlib import Path
import sys
from ads_context_meter.config import Settings
from ads_context_meter.worker import TokenCounter
if __name__ == "__main__":
    settings = Settings("", "", "", "", Path(sys.argv[1]), Path(""), Path(""), None, "", 0)
    TokenCounter(settings)
"""
    # A file entry point exercises the production multiprocessing spawn path.
    entry = tmp_path / "startup.py"
    entry.write_text(script)
    result = subprocess.run(
        [sys.executable, str(entry), str(tmp_path)], capture_output=True, text=True, timeout=20
    )
    assert result.returncode != 0
    assert "FileNotFoundError" in result.stderr
