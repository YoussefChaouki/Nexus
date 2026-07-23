"""Tests for the Code Analysis MCP server tool functions.

Exercises the MCP tool functions directly (FastMCP's ``@tool()`` decorator
preserves the original async callable, same pattern as the NVD/arXiv
server tests) with the underlying scanners monkeypatched so nothing here
touches the network or shells out to semgrep.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
import server
from dependency_scanner import DependencyFinding
from pattern_detector import PatternDetectionError
from schemas import CVEEntry, MCPToolError, PatternFinding


@pytest.mark.asyncio
async def test_analyze_dependencies_returns_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_scan(content: str, **kwargs: Any) -> list[DependencyFinding]:
        return [
            DependencyFinding(
                package="requests",
                version="2.31.0",
                cves=[CVEEntry(cve_id="CVE-2023-0001", description="x", severity="HIGH")],
            )
        ]

    monkeypatch.setattr(server, "scan_dependencies", fake_scan)

    result = json.loads(await server.analyze_dependencies("requests==2.31.0"))

    assert result[0]["package"] == "requests"
    assert result[0]["cves"][0]["cve_id"] == "CVE-2023-0001"


@pytest.mark.asyncio
async def test_analyze_dependencies_error_envelope(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_scan(content: str, **kwargs: Any) -> list[DependencyFinding]:
        raise RuntimeError("boom")

    monkeypatch.setattr(server, "scan_dependencies", fake_scan)

    result = MCPToolError.model_validate_json(await server.analyze_dependencies("x"))
    assert result.error_type == "internal_error"


@pytest.mark.asyncio
async def test_detect_patterns_returns_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_run(code: str, language: str = "python", **kwargs: Any) -> list[PatternFinding]:
        return [PatternFinding(rule_id="r1", message="m", line=1, severity="warning")]

    monkeypatch.setattr(server, "run_semgrep", fake_run)

    result = json.loads(await server.detect_patterns("eval(x)"))
    assert result[0]["rule_id"] == "r1"


@pytest.mark.asyncio
async def test_detect_patterns_error_envelope(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_run(code: str, language: str = "python", **kwargs: Any) -> list[PatternFinding]:
        raise PatternDetectionError("semgrep is not installed")

    monkeypatch.setattr(server, "run_semgrep", fake_run)

    result = MCPToolError.model_validate_json(await server.detect_patterns("x"))
    assert result.error_type == "semgrep_error"
    assert "not installed" in result.error


@pytest.mark.asyncio
async def test_extract_attack_surface_returns_summary() -> None:
    result = json.loads(await server.extract_attack_surface('{"paths": {}}', "openapi"))

    assert result["config_type"] == "openapi"
    assert result["issues"] == []


@pytest.mark.asyncio
async def test_extract_attack_surface_error_envelope() -> None:
    result = MCPToolError.model_validate_json(
        await server.extract_attack_surface("{}", "unknown-type")
    )
    assert result.error_type == "parse_error"
