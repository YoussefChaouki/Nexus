"""MCP client wrapper used by NEXUS agents to invoke MCP server tools."""

from nexus.mcp.client import MCPClient
from nexus.mcp.tool_registry import TOOL_REGISTRY, get_server_for_tool

__all__ = ["MCPClient", "TOOL_REGISTRY", "get_server_for_tool"]
