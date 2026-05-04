"""Pydantic schemas exposed by the NVD MCP server.

Mirrors :class:`nexus.schemas.models.CVEEntry` and ``MCPToolError`` so that
this MCP server stays a standalone package with no dependency on the
NEXUS application code.
"""

from pydantic import BaseModel, Field


class CVEEntry(BaseModel):
    """Single CVE record returned by the NVD API."""

    cve_id: str
    description: str
    severity: str | None = None
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    published_date: str
    last_modified_date: str
    affected_products: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class MCPToolError(BaseModel):
    """Standard MCP error envelope returned in place of a successful payload."""

    error: str
    error_type: str
    retryable: bool = False
