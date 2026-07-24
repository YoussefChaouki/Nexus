"""MCP client wrapper used by NEXUS agents to call MCP server tools.

:class:`MCPClient` manages stdio subprocess connections to MCP servers and
pools one :class:`mcp.ClientSession` per ``server_name``. Sessions are
created lazily on first ``call_tool`` and reused for the lifetime of the
client. Calling :meth:`MCPClient.aclose` shuts every session down.

MCP tool responses are returned as raw JSON strings. When a tool returns
the ``MCPToolError`` envelope shape (``{"error", "error_type",
"retryable"}``) this client raises :class:`nexus.exceptions.MCPClientError`
so agent code can treat MCP failures uniformly.
"""

from __future__ import annotations

import asyncio
import json
import sys
from contextlib import AsyncExitStack
from pathlib import Path
from types import TracebackType
from typing import Any

import structlog
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import CallToolResult

from nexus.exceptions import MCPClientError
from nexus.settings import get_settings

logger = structlog.get_logger(__name__)


class MCPClient:
    """Pooled stdio client for the NEXUS MCP servers.

    Args:
        server_configs: Mapping of ``server_name`` to
            :class:`StdioServerParameters`. When ``None`` the default
            configuration pointing at the bundled ``mcp_servers/`` scripts
            is used.
    """

    def __init__(
        self,
        server_configs: dict[str, StdioServerParameters] | None = None,
    ) -> None:
        self._server_configs = (
            dict(server_configs) if server_configs is not None else _default_server_configs()
        )
        self._sessions: dict[str, ClientSession] = {}
        self._exit_stacks: dict[str, AsyncExitStack] = {}
        self._lock = asyncio.Lock()

    async def __aenter__(self) -> MCPClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def call_tool(
        self,
        server_name: str,
        tool_name: str,
        **kwargs: Any,
    ) -> str:
        """Invoke ``tool_name`` on the MCP server registered as ``server_name``.

        Args:
            server_name: Server key (e.g. ``"arxiv"``, ``"nvd"``, ``"atlas"``).
            tool_name: Tool exposed by that server.
            **kwargs: Forwarded to the MCP tool as its ``arguments`` dict.

        Returns:
            The raw JSON string returned by the tool.

        Raises:
            ValueError: If ``server_name`` is not in this client's config.
            MCPClientError: If the tool returned an ``MCPToolError`` envelope
                or the MCP transport flagged the result as an error.
        """
        if server_name not in self._server_configs:
            raise ValueError(f"unknown MCP server: {server_name!r}")

        session = await self._get_session(server_name)
        result = await session.call_tool(tool_name, arguments=kwargs)
        text = _extract_text(result)

        if result.isError:
            raise MCPClientError(f"MCP transport error from {server_name}.{tool_name}: {text}")

        _maybe_raise_envelope(server_name, tool_name, text)
        return text

    async def aclose(self) -> None:
        """Tear down every pooled session."""
        async with self._lock:
            stacks = list(self._exit_stacks.values())
            self._exit_stacks.clear()
            self._sessions.clear()
        for stack in stacks:
            try:
                await stack.aclose()
            except Exception as exc:
                logger.warning("mcp_session_close_failed", error=str(exc))

    async def _get_session(self, server_name: str) -> ClientSession:
        async with self._lock:
            session = self._sessions.get(server_name)
            if session is not None:
                return session

            params = self._server_configs[server_name]
            stack = AsyncExitStack()
            try:
                read, write = await stack.enter_async_context(stdio_client(params))
                session = await stack.enter_async_context(ClientSession(read, write))
                await session.initialize()
            except Exception:
                await stack.aclose()
                raise

            self._exit_stacks[server_name] = stack
            self._sessions[server_name] = session
            return session


def _extract_text(result: CallToolResult) -> str:
    """Concatenate every text content block in a CallToolResult."""
    parts: list[str] = []
    for block in result.content:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            parts.append(text)
    return "".join(parts)


def _maybe_raise_envelope(server_name: str, tool_name: str, text: str) -> None:
    """Raise :class:`MCPClientError` if ``text`` is the MCPToolError envelope."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return

    if (
        isinstance(data, dict)
        and isinstance(data.get("error"), str)
        and isinstance(data.get("error_type"), str)
    ):
        retryable = bool(data.get("retryable", False))
        raise MCPClientError(
            f"{server_name}.{tool_name} → {data['error_type']}: "
            f"{data['error']} (retryable={retryable})",
        )


def _default_server_configs() -> dict[str, StdioServerParameters]:
    """Default stdio launchers pointing at the bundled mcp_servers/ scripts.

    ``Settings.mcp_servers_dir`` takes precedence when set (required for a
    non-editable install, e.g. the Docker image, where this file lives
    under site-packages and no longer sits 3 parents below the repo root).
    """
    configured = get_settings().mcp_servers_dir
    if configured:
        servers_dir = Path(configured)
    else:
        repo_root = Path(__file__).resolve().parents[3]
        servers_dir = repo_root / "mcp_servers"
    return {
        name: StdioServerParameters(
            command=sys.executable,
            args=[str(servers_dir / name / "server.py")],
            cwd=str(servers_dir / name),
        )
        for name in ("arxiv", "nvd", "atlas")
    }
