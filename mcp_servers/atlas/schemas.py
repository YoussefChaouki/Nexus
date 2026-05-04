"""Pydantic schemas exposed by the MITRE ATLAS MCP server.

Mirrors :class:`nexus.schemas.models.ATLASTechnique` and ``MCPToolError`` so
that the server stays a standalone package with no dependency on the NEXUS
application code.
"""

from pydantic import BaseModel, Field


class ATLASTechnique(BaseModel):
    """Single MITRE ATLAS technique parsed from the STIX 2.1 bundle."""

    technique_id: str
    name: str
    description: str
    tactic: str
    subtechniques: list[str] = Field(default_factory=list)
    case_studies: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)
    url: str


class MCPToolError(BaseModel):
    """Standard MCP error envelope returned in place of a successful payload."""

    error: str
    error_type: str
    retryable: bool = False
