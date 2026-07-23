"""Pydantic schemas exposed by the Code Analysis MCP server.

Kept self-contained (no import of ``nexus.*``) so this server stays a
standalone package, matching ``mcp_servers/{arxiv,nvd,atlas}``.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class CVEEntry(BaseModel):
    """Slim CVE record — enough for a dependency-risk summary."""

    cve_id: str
    description: str
    severity: str | None = None
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)


class DependencyFinding(BaseModel):
    """One parsed dependency and any CVEs found for it."""

    package: str
    version: str | None = None
    cves: list[CVEEntry] = Field(default_factory=list)


class PatternFinding(BaseModel):
    """One semgrep match."""

    rule_id: str
    message: str
    line: int
    severity: str = "info"
    path: str | None = None


class AttackSurfaceIssue(BaseModel):
    """One identified exposure in a parsed config file."""

    category: str
    severity: str
    description: str
    location: str | None = None


class AttackSurfaceSummary(BaseModel):
    """Aggregate result for :func:`attack_surface.extract_attack_surface`."""

    config_type: str
    issues: list[AttackSurfaceIssue] = Field(default_factory=list)


class MCPToolError(BaseModel):
    """Standard MCP error envelope returned in place of a successful payload."""

    error: str
    error_type: str
    retryable: bool = False
