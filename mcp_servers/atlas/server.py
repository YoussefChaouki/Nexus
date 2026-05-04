"""MITRE ATLAS MCP server — exposes 3 stdio tools.

Tools:
    * ``search_techniques(query, max_results=10)``
        Return the techniques most similar to ``query`` (cosine similarity
        over OpenAI ``text-embedding-3-small`` vectors).
    * ``get_technique_detail(technique_id)``
        Fetch a single technique by ATLAS identifier (e.g. ``AML.T0042``).
    * ``search_by_tactic(tactic_name)``
        Filter techniques by ATLAS kill-chain tactic name.

The STIX bundle path is read from the ``ATLAS_STIX_PATH`` environment
variable, defaulting to ``data/atlas/ATLAS.json`` relative to the
repository root. Download the bundle from
https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.json
before launching the server (documented in the project README).
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import structlog
from mcp.server.fastmcp import FastMCP
from schemas import ATLASTechnique, MCPToolError
from stix_loader import STIXLoadError, load_atlas_techniques
from vector_search import ATLASVectorSearch

logger = structlog.get_logger(__name__)

mcp = FastMCP(name="nexus-mcp-atlas")

_search: ATLASVectorSearch | None = None


def get_search() -> ATLASVectorSearch:
    """Return the process-wide :class:`ATLASVectorSearch` (lazy)."""
    global _search
    if _search is None:
        path = _stix_path()
        techniques = load_atlas_techniques(path)
        _search = ATLASVectorSearch(techniques)
    return _search


def set_search(search: ATLASVectorSearch | None) -> None:
    """Override the process-wide search engine. Used by tests."""
    global _search
    _search = search


def _stix_path() -> Path:
    env = os.environ.get("ATLAS_STIX_PATH")
    if env:
        return Path(env)
    repo_root = Path(__file__).resolve().parents[2]
    return repo_root / "data" / "atlas" / "ATLAS.json"


def _error_json(exc: Exception, error_type: str) -> str:
    retryable = bool(getattr(exc, "retryable", False))
    return MCPToolError(
        error=str(exc),
        error_type=error_type,
        retryable=retryable,
    ).model_dump_json()


def _techniques_json(techniques: list[ATLASTechnique]) -> str:
    return "[" + ",".join(t.model_dump_json() for t in techniques) + "]"


@mcp.tool()
async def search_techniques(query: str, max_results: int = 10) -> str:
    """Search ATLAS techniques by semantic similarity to ``query``."""
    try:
        results = await get_search().search(query, limit=max_results)
    except STIXLoadError as exc:
        logger.warning("atlas_stix_unavailable", error=str(exc))
        return _error_json(exc, "atlas_stix_unavailable")
    except Exception as exc:
        logger.exception("search_techniques_unexpected", query=query)
        return _error_json(exc, "internal_error")
    return _techniques_json(results)


@mcp.tool()
async def get_technique_detail(technique_id: str) -> str:
    """Return a single technique by ATLAS identifier (e.g. ``AML.T0042``)."""
    try:
        technique = get_search().get_by_id(technique_id)
    except STIXLoadError as exc:
        logger.warning("atlas_stix_unavailable", error=str(exc))
        return _error_json(exc, "atlas_stix_unavailable")
    except Exception as exc:
        logger.exception("get_technique_detail_unexpected", technique_id=technique_id)
        return _error_json(exc, "internal_error")
    if technique is None:
        return MCPToolError(
            error=f"ATLAS technique not found: {technique_id}",
            error_type="not_found",
            retryable=False,
        ).model_dump_json()
    return technique.model_dump_json()


@mcp.tool()
async def search_by_tactic(tactic_name: str) -> str:
    """Return every technique whose kill-chain tactic matches ``tactic_name``."""
    try:
        results = get_search().filter_by_tactic(tactic_name)
    except STIXLoadError as exc:
        logger.warning("atlas_stix_unavailable", error=str(exc))
        return _error_json(exc, "atlas_stix_unavailable")
    except Exception as exc:
        logger.exception("search_by_tactic_unexpected", tactic=tactic_name)
        return _error_json(exc, "internal_error")
    return _techniques_json(results)


def main() -> None:
    """Entry point: load the STIX bundle and run the server over stdio."""
    asyncio.run(mcp.run_stdio_async())


if __name__ == "__main__":
    main()
