"""Static mapping of MCP tool names to the server that hosts them.

Agents call ``MCPClient.call_tool`` with a server name and a tool name; this
registry lets them resolve a tool to its owning server when they only know
the tool name (e.g. when assembling research plans).
"""

from typing import Final

TOOL_REGISTRY: Final[dict[str, str]] = {
    # arXiv — see mcp_servers/arxiv/server.py
    "search_papers": "arxiv",
    "get_paper_abstract": "arxiv",
    "get_full_text": "arxiv",
    # NVD — see mcp_servers/nvd/server.py
    "search_cves": "nvd",
    "get_cve_detail": "nvd",
    "search_by_product": "nvd",
    # MITRE ATLAS — added in Sprint 3 T1; registry entries provided up-front
    # so agents can reference them without code churn later.
    "search_techniques": "atlas",
    "get_technique_detail": "atlas",
    "search_by_tactic": "atlas",
    # Code Analysis — see mcp_servers/code_analysis/server.py (S9.T3 stretch)
    "analyze_dependencies": "code_analysis",
    "detect_patterns": "code_analysis",
    "extract_attack_surface": "code_analysis",
}


def get_server_for_tool(tool_name: str) -> str | None:
    """Return the MCP server that hosts ``tool_name``, or None if unknown."""
    return TOOL_REGISTRY.get(tool_name)
