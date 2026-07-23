"""Code Analysis MCP server — exposes 3 tools over stdio.

Tools:
    * ``analyze_dependencies(requirements_content)``
        Parse a ``requirements.txt`` or ``pyproject.toml`` and look up
        known CVEs for each dependency via NVD. Returns JSON
        list[DependencyFinding].
    * ``detect_patterns(code_content, language="python")``
        Run semgrep against a code snippet. Returns JSON list[PatternFinding].
    * ``extract_attack_surface(config_content, config_type)``
        Parse a docker-compose / kubernetes / openapi / terraform config
        and flag exposed ports, missing auth, privileged containers, open
        security groups, etc. Returns JSON AttackSurfaceSummary.

Every tool returns a JSON string. On failure the JSON is an
:class:`MCPToolError` payload — tools never raise to the MCP client.
"""

from __future__ import annotations

import asyncio

import httpx
import structlog
from attack_surface import AttackSurfaceParseError
from attack_surface import extract_attack_surface as _extract_attack_surface
from dependency_scanner import scan_dependencies
from mcp.server.fastmcp import FastMCP
from pattern_detector import PatternDetectionError, run_semgrep
from schemas import MCPToolError

logger = structlog.get_logger(__name__)

mcp = FastMCP(name="nexus-mcp-code-analysis")


def _error_json(exc: Exception, error_type: str, *, retryable: bool = False) -> str:
    return MCPToolError(
        error=str(exc), error_type=error_type, retryable=retryable
    ).model_dump_json()


@mcp.tool()
async def analyze_dependencies(requirements_content: str) -> str:
    """Parse requirements.txt or pyproject.toml and check each dep against NVD.

    Returns JSON list of {"package": str, "version": str | null, "cves": [...]}.
    """
    try:
        findings = await scan_dependencies(requirements_content)
    except httpx.HTTPError as exc:
        logger.warning("analyze_dependencies_network_error", error=str(exc))
        return _error_json(exc, "nvd_api_error", retryable=True)
    except Exception as exc:
        logger.exception("analyze_dependencies_unexpected")
        return _error_json(exc, "internal_error")
    return "[" + ",".join(f.model_dump_json() for f in findings) + "]"


@mcp.tool()
async def detect_patterns(code_content: str, language: str = "python") -> str:
    """Run semgrep against code_content using the OWASP + language ruleset.

    Returns JSON list of findings with rule_id, message, line, severity.
    """
    try:
        findings = await run_semgrep(code_content, language)
    except PatternDetectionError as exc:
        logger.warning("detect_patterns_failed", error=str(exc))
        return _error_json(exc, "semgrep_error")
    except Exception as exc:
        logger.exception("detect_patterns_unexpected")
        return _error_json(exc, "internal_error")
    return "[" + ",".join(f.model_dump_json() for f in findings) + "]"


@mcp.tool()
async def extract_attack_surface(config_content: str, config_type: str) -> str:
    """Identify exposed ports, missing auth, privileged containers, etc.

    config_type: "docker-compose" | "kubernetes" | "openapi" | "terraform"
    Returns JSON attack surface summary.
    """
    try:
        summary = _extract_attack_surface(config_content, config_type)
    except AttackSurfaceParseError as exc:
        logger.warning("extract_attack_surface_failed", config_type=config_type, error=str(exc))
        return _error_json(exc, "parse_error")
    except Exception as exc:
        logger.exception("extract_attack_surface_unexpected", config_type=config_type)
        return _error_json(exc, "internal_error")
    return summary.model_dump_json()


def main() -> None:
    """Entry point: run the MCP server over stdio."""
    asyncio.run(mcp.run_stdio_async())


if __name__ == "__main__":
    main()
