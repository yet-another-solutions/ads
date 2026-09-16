from __future__ import annotations

import pytest

from ads_supervisor.config import _mcp_servers


def test_the_table_maps_names_to_servers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "ADS_MCP_SERVERS", "retriever=http://127.0.0.1:8006/mcp/, jira=https://jira.interlab/mcp"
    )
    assert _mcp_servers() == {
        "retriever": "http://127.0.0.1:8006/mcp",
        "jira": "https://jira.interlab/mcp",
    }


def test_an_empty_table_is_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    """The decision API still works; there is simply nothing to proxy."""
    monkeypatch.delenv("ADS_MCP_SERVERS", raising=False)
    assert _mcp_servers() == {}


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("re/triever=http://x/mcp", "not usable as a path segment"),
        ("retriever=127.0.0.1:8006/mcp", "needs an http"),
    ],
)
def test_a_bad_entry_stops_the_service(
    monkeypatch: pytest.MonkeyPatch, raw: str, message: str
) -> None:
    monkeypatch.setenv("ADS_MCP_SERVERS", raw)
    with pytest.raises(RuntimeError, match=message):
        _mcp_servers()
