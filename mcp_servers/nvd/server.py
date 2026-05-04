"""NVD CVE MCP server — exposes 3 tools over stdio.

Tools:
    * ``search_cves(keyword, severity=None, max_results=20)``
        Search the NVD CVE database by keyword and optional severity filter.
        ``severity`` must be one of ``CRITICAL``, ``HIGH``, ``MEDIUM``, ``LOW``,
        or ``None``.
    * ``get_cve_detail(cve_id)``
        Fetch the full CVE record by ID (``CVE-YYYY-NNNNN``).
    * ``search_by_product(cpe_name, max_results=10)``
        Search CVEs affecting a specific product by CPE 2.3 name.

Every tool returns a JSON string. On failure the JSON is an
:class:`MCPToolError` payload — tools never raise to the MCP client.
"""

from __future__ import annotations

import asyncio

import structlog
from client import NVDAPIError, NVDClient
from mcp.server.fastmcp import FastMCP
from schemas import CVEEntry, MCPToolError

logger = structlog.get_logger(__name__)

mcp = FastMCP(name="nexus-mcp-nvd")

_client: NVDClient | None = None


def get_client() -> NVDClient:
    """Return the process-wide :class:`NVDClient`, instantiating on demand."""
    global _client
    if _client is None:
        _client = NVDClient()
    return _client


def set_client(client: NVDClient | None) -> None:
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


def _cves_json(cves: list[CVEEntry]) -> str:
    return "[" + ",".join(c.model_dump_json() for c in cves) + "]"


@mcp.tool()
async def search_cves(keyword: str, severity: str | None = None, max_results: int = 20) -> str:
    """Search NVD CVE database by keyword and optional severity filter.

    severity must be one of: CRITICAL, HIGH, MEDIUM, LOW or None.
    Returns JSON list of CVEEntry.
    """
    try:
        cves = await get_client().search_keyword(
            keyword, severity=severity, max_results=max_results
        )
    except NVDAPIError as exc:
        logger.warning("search_cves_failed", keyword=keyword, error=str(exc))
        return _error_json(exc, "nvd_api_error")
    except Exception as exc:
        logger.exception("search_cves_unexpected", keyword=keyword)
        return _error_json(exc, "internal_error")
    return _cves_json(cves)


@mcp.tool()
async def get_cve_detail(cve_id: str) -> str:
    """Get full CVE details by ID (format: CVE-YYYY-NNNNN). Returns CVEEntry JSON."""
    try:
        cve = await get_client().get_by_id(cve_id)
    except NVDAPIError as exc:
        logger.warning("get_cve_detail_failed", cve_id=cve_id, error=str(exc))
        return _error_json(exc, "nvd_api_error")
    except Exception as exc:
        logger.exception("get_cve_detail_unexpected", cve_id=cve_id)
        return _error_json(exc, "internal_error")
    return cve.model_dump_json()


@mcp.tool()
async def search_by_product(cpe_name: str, max_results: int = 10) -> str:
    """Search CVEs affecting a specific product by CPE name."""
    try:
        cves = await get_client().search_by_product(cpe_name, max_results=max_results)
    except NVDAPIError as exc:
        logger.warning("search_by_product_failed", cpe_name=cpe_name, error=str(exc))
        return _error_json(exc, "nvd_api_error")
    except Exception as exc:
        logger.exception("search_by_product_unexpected", cpe_name=cpe_name)
        return _error_json(exc, "internal_error")
    return _cves_json(cves)


def main() -> None:
    """Entry point: run the MCP server over stdio."""
    asyncio.run(mcp.run_stdio_async())


if __name__ == "__main__":
    main()
