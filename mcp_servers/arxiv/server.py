"""arXiv MCP server — exposes 3 tools over stdio.

Tools:
    * ``search_papers(query, max_results)``       — returns ``list[ArxivPaper]``
    * ``get_paper_abstract(arxiv_id)``            — returns ``ArxivPaper``
    * ``get_full_text(arxiv_id)``                 — returns ``ArxivPaper`` with
      ``full_text`` populated (falls back to ``abstract`` when unavailable).

Every tool returns a JSON string. On failure the JSON is an
:class:`MCPToolError` payload — tools never raise to the MCP client.
"""

from __future__ import annotations

import asyncio

import structlog
from client import ArxivAPIError, ArxivClient
from mcp.server.fastmcp import FastMCP
from schemas import ArxivPaper, MCPToolError

logger = structlog.get_logger(__name__)

mcp = FastMCP(name="nexus-mcp-arxiv")

_client: ArxivClient | None = None


def get_client() -> ArxivClient:
    """Return the process-wide :class:`ArxivClient`, instantiating on demand."""
    global _client
    if _client is None:
        _client = ArxivClient()
    return _client


def set_client(client: ArxivClient | None) -> None:
    """Override the process-wide client. Used by tests."""
    global _client
    _client = client


def _error_json(exc: Exception, error_type: str) -> str:
    retryable = bool(getattr(exc, "retryable", False))
    return MCPToolError(
        error=str(exc),
        error_type=error_type,
        retryable=retryable,
    ).model_dump_json()


def _papers_json(papers: list[ArxivPaper]) -> str:
    """Serialize a list of papers as a JSON array string."""
    return "[" + ",".join(p.model_dump_json() for p in papers) + "]"


@mcp.tool()
async def search_papers(query: str, max_results: int = 10) -> str:
    """Search arXiv for papers. Returns JSON list of ArxivPaper."""
    try:
        papers = await get_client().search(query, max_results=max_results)
    except ArxivAPIError as exc:
        logger.warning("search_papers_failed", query=query, error=str(exc))
        return _error_json(exc, "arxiv_api_error")
    except Exception as exc:
        logger.exception("search_papers_unexpected", query=query)
        return _error_json(exc, "internal_error")
    return _papers_json(papers)


@mcp.tool()
async def get_paper_abstract(arxiv_id: str) -> str:
    """Get abstract for a specific arXiv paper by ID."""
    try:
        paper = await get_client().get_by_id(arxiv_id)
    except ArxivAPIError as exc:
        logger.warning("get_paper_abstract_failed", arxiv_id=arxiv_id, error=str(exc))
        return _error_json(exc, "arxiv_api_error")
    except Exception as exc:
        logger.exception("get_paper_abstract_unexpected", arxiv_id=arxiv_id)
        return _error_json(exc, "internal_error")
    return paper.model_dump_json()


@mcp.tool()
async def get_full_text(arxiv_id: str) -> str:
    """Get full text summary (uses abstract if full text unavailable)."""
    try:
        paper = await get_client().get_by_id(arxiv_id)
    except ArxivAPIError as exc:
        logger.warning("get_full_text_failed", arxiv_id=arxiv_id, error=str(exc))
        return _error_json(exc, "arxiv_api_error")
    except Exception as exc:
        logger.exception("get_full_text_unexpected", arxiv_id=arxiv_id)
        return _error_json(exc, "internal_error")
    if paper.full_text is None:
        paper = paper.model_copy(update={"full_text": paper.abstract})
    return paper.model_dump_json()


def main() -> None:
    """Entry point: run the MCP server over stdio."""
    asyncio.run(mcp.run_stdio_async())


if __name__ == "__main__":
    main()
