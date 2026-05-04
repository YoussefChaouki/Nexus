"""Pydantic schemas exposed by the arXiv MCP server.

These mirror nexus.schemas.models but are duplicated here so the MCP
server can ship as a standalone package with no dependency on the
NEXUS application code.
"""

from pydantic import BaseModel


class ArxivPaper(BaseModel):
    """Single paper returned by the arXiv API."""

    arxiv_id: str
    title: str
    authors: list[str]
    abstract: str
    published: str
    url: str
    categories: list[str]
    full_text: str | None = None


class MCPToolError(BaseModel):
    """Standard MCP error envelope returned in place of a successful payload."""

    error: str
    error_type: str
    retryable: bool = False
