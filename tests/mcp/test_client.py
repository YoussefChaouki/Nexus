"""Tests for the NEXUS MCP client wrapper.

Stdio sessions are stubbed out completely: tests inject a fake
``ClientSession`` straight into :class:`MCPClient` so we never spawn a
real subprocess. This keeps the unit tests fast and deterministic.
"""

from __future__ import annotations

from typing import Any

import pytest
from mcp.types import CallToolResult, TextContent

from nexus.exceptions import MCPClientError
from nexus.mcp import TOOL_REGISTRY, MCPClient, get_server_for_tool


class _FakeSession:
    """Stand-in for :class:`mcp.ClientSession` that records calls."""

    def __init__(self, response_text: str = "[]", is_error: bool = False) -> None:
        self.response_text = response_text
        self.is_error = is_error
        self.calls: list[tuple[str, dict[str, Any] | None]] = []

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
    ) -> CallToolResult:
        self.calls.append((name, arguments))
        return CallToolResult(
            content=[TextContent(type="text", text=self.response_text)],
            isError=self.is_error,
        )


def _inject(client: MCPClient, server_name: str, session: _FakeSession) -> None:
    """Insert a fake session into the client's pool, bypassing stdio."""
    client._sessions[server_name] = session  # type: ignore[assignment]


# --- get_server_for_tool / TOOL_REGISTRY ---------------------------------


def test_tool_registry_covers_all_three_servers() -> None:
    servers = set(TOOL_REGISTRY.values())
    assert servers == {"arxiv", "nvd", "atlas"}


def test_get_server_for_tool_returns_server_name() -> None:
    assert get_server_for_tool("search_papers") == "arxiv"
    assert get_server_for_tool("search_cves") == "nvd"
    assert get_server_for_tool("search_techniques") == "atlas"


def test_get_server_for_tool_returns_none_for_unknown_tool() -> None:
    assert get_server_for_tool("does_not_exist") is None


# --- MCPClient.call_tool -------------------------------------------------


async def test_call_tool_returns_raw_text() -> None:
    client = MCPClient()
    fake = _FakeSession(response_text='[{"arxiv_id": "2401.12345v1"}]')
    _inject(client, "arxiv", fake)

    raw = await client.call_tool("arxiv", "search_papers", query="prompt injection")

    assert raw == '[{"arxiv_id": "2401.12345v1"}]'
    assert fake.calls == [("search_papers", {"query": "prompt injection"})]


async def test_call_tool_forwards_kwargs_as_arguments_dict() -> None:
    client = MCPClient()
    fake = _FakeSession(response_text="[]")
    _inject(client, "nvd", fake)

    await client.call_tool("nvd", "search_cves", keyword="rce", severity="HIGH")

    assert fake.calls == [("search_cves", {"keyword": "rce", "severity": "HIGH"})]


async def test_call_tool_unknown_server_raises_value_error() -> None:
    client = MCPClient(server_configs={})

    with pytest.raises(ValueError, match="unknown MCP server"):
        await client.call_tool("nope", "whatever")


async def test_call_tool_envelope_error_raises_mcp_client_error() -> None:
    client = MCPClient()
    envelope = '{"error": "rate limited", "error_type": "arxiv_api_error", "retryable": true}'
    _inject(client, "arxiv", _FakeSession(response_text=envelope))

    with pytest.raises(MCPClientError, match="arxiv_api_error"):
        await client.call_tool("arxiv", "search_papers", query="x")


async def test_call_tool_transport_error_raises_mcp_client_error() -> None:
    client = MCPClient()
    fake = _FakeSession(response_text="boom", is_error=True)
    _inject(client, "arxiv", fake)

    with pytest.raises(MCPClientError, match="transport error"):
        await client.call_tool("arxiv", "search_papers", query="x")


async def test_call_tool_pools_session_per_server() -> None:
    client = MCPClient()
    arxiv_fake = _FakeSession(response_text="[]")
    nvd_fake = _FakeSession(response_text="[]")
    _inject(client, "arxiv", arxiv_fake)
    _inject(client, "nvd", nvd_fake)

    await client.call_tool("arxiv", "search_papers", query="a")
    await client.call_tool("arxiv", "search_papers", query="b")
    await client.call_tool("nvd", "search_cves", keyword="c")

    assert len(arxiv_fake.calls) == 2
    assert len(nvd_fake.calls) == 1


async def test_non_envelope_json_passes_through() -> None:
    """A list response is not an error envelope and must not raise."""
    client = MCPClient()
    _inject(client, "arxiv", _FakeSession(response_text='[{"arxiv_id": "x"}]'))

    raw = await client.call_tool("arxiv", "search_papers", query="x")

    assert raw == '[{"arxiv_id": "x"}]'


async def test_aclose_clears_pool() -> None:
    client = MCPClient()
    _inject(client, "arxiv", _FakeSession())

    await client.aclose()

    assert client._sessions == {}  # type: ignore[attr-defined]
    assert client._exit_stacks == {}  # type: ignore[attr-defined]


async def test_async_context_manager_closes_pool() -> None:
    """Using MCPClient as ``async with`` must drain sessions on exit."""
    client = MCPClient()
    _inject(client, "arxiv", _FakeSession())
    async with client as bound:
        assert bound is client
        assert client._sessions  # type: ignore[attr-defined]
    assert client._sessions == {}  # type: ignore[attr-defined]


async def test_aclose_swallows_stack_close_errors() -> None:
    """A failing AsyncExitStack must not propagate out of aclose()."""
    from contextlib import AsyncExitStack
    from unittest.mock import AsyncMock

    client = MCPClient()
    stack = AsyncExitStack()
    stack.aclose = AsyncMock(side_effect=RuntimeError("boom"))  # type: ignore[method-assign]
    client._exit_stacks["arxiv"] = stack  # type: ignore[assignment]
    client._sessions["arxiv"] = _FakeSession()  # type: ignore[assignment]

    # Must not raise; pool is cleared regardless of the stack failure.
    await client.aclose()
    assert client._sessions == {}  # type: ignore[attr-defined]


async def test_envelope_check_ignores_non_json_payload() -> None:
    """When the tool returns plain text, the envelope check must not raise."""
    client = MCPClient()
    _inject(client, "atlas", _FakeSession(response_text="not-json-at-all"))

    raw = await client.call_tool("atlas", "search_techniques", query="x")

    assert raw == "not-json-at-all"
