"""Pydantic v2 schemas — single source of truth for all NEXUS data models.

Never redefine these elsewhere; always import from this module.
"""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, TypedDict
from uuid import uuid4

from langchain_core.messages import BaseMessage
from langgraph.graph import add_messages
from pydantic import BaseModel, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class FocusArea(StrEnum):
    """Attack category targeted by a ResearchTask."""

    INJECTION = "injection"
    DATA_LEAKAGE = "data_leakage"
    SUPPLY_CHAIN = "supply_chain"
    DENIAL_OF_SERVICE = "dos"
    MODEL_EXTRACTION = "model_extraction"
    OTHER = "other"


class Priority(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SourceType(StrEnum):
    ARXIV = "arxiv"
    NVD = "nvd"
    ATLAS = "atlas"
    WEB = "web"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Recommendation(StrEnum):
    APPROVE = "approve"
    RE_RESEARCH = "re_research"


# ---------------------------------------------------------------------------
# Core pipeline models
# ---------------------------------------------------------------------------


class ResearchTask(BaseModel):
    """Research task produced by the Planner."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    description: str = Field(min_length=10)
    focus_area: FocusArea
    priority: Priority
    search_queries: list[str] = Field(default_factory=list)


class FindingResult(BaseModel):
    """Single research result returned by the Researcher."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    task_id: str
    source_type: SourceType
    title: str
    summary: str = Field(min_length=20)
    relevance_score: Annotated[float, Field(ge=0.0, le=1.0)]
    url: str | None = None
    identifiers: list[str] = Field(
        default_factory=list,
        description="CVE-2024-XXXX | arxiv:2401.XXXXX | ATLAS-T0001 | OWASP-LLM01",
    )

    @field_validator("relevance_score")
    @classmethod
    def round_score(cls, v: float) -> float:
        """Round relevance score to 4 decimal places."""
        return round(v, 4)


class ThreatSurface(BaseModel):
    """Attack surface identified by the Analyst."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    description: str = Field(min_length=30)
    severity: Severity
    attack_vectors: list[str]
    evidence: list[FindingResult] = Field(default_factory=list)
    mitigations: list[str] = Field(min_length=1)
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    owasp_category: str | None = None

    @model_validator(mode="after")
    def require_evidence(self) -> "ThreatSurface":
        """Ensure at least one FindingResult is attached as evidence."""
        if not self.evidence:
            raise ValueError("ThreatSurface must have at least one FindingResult as evidence")
        return self


class CriticReport(BaseModel):
    """Evaluation report produced by the Critic."""

    overall_score: Annotated[float, Field(ge=0.0, le=1.0)]
    gaps: list[str]
    bias_warnings: list[str] = Field(default_factory=list)
    recommendation: Recommendation
    re_research_tasks: list[ResearchTask] = Field(default_factory=list)

    @model_validator(mode="after")
    def tasks_required_for_re_research(self) -> "CriticReport":
        """Require re_research_tasks when recommendation is RE_RESEARCH."""
        if self.recommendation == Recommendation.RE_RESEARCH and not self.re_research_tasks:
            raise ValueError(
                "re_research_tasks must be non-empty when recommendation is RE_RESEARCH"
            )
        return self


class ThreatReport(BaseModel):
    """Final report produced by the Writer."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    target_description: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    threat_surfaces: list[ThreatSurface] = Field(min_length=1)
    critic_report: CriticReport
    iteration_count: int = Field(ge=1, le=3)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ThreatReportSummary(BaseModel):
    """Condensed version stored in episodic memory (pgvector).

    Never store a full ThreatReport in episodic memory — always ThreatReportSummary.
    """

    id: str
    session_id: str
    target_description: str
    created_at: datetime
    surface_count: int = Field(ge=0)
    severity_breakdown: dict[str, int]
    focus_areas_covered: list[FocusArea]
    top_attack_vectors: list[str] = Field(max_length=5)
    overall_critic_score: float = Field(ge=0.0, le=1.0)
    iteration_count: int


# ---------------------------------------------------------------------------
# LangGraph state
# ---------------------------------------------------------------------------


class AgentState(TypedDict):
    """Shared mutable state passed between LangGraph nodes.

    Never mutate in place — always return a new dict with updated fields.
    """

    messages: Annotated[list[BaseMessage], add_messages]
    target_description: str
    session_id: str
    plan: list[ResearchTask]
    findings: list[FindingResult]
    threat_surfaces: list[ThreatSurface]
    critic_report: CriticReport | None
    threat_report: ThreatReport | None
    iteration_count: int
    should_continue: bool


# ---------------------------------------------------------------------------
# MCP server return types
# ---------------------------------------------------------------------------


class ArxivPaper(BaseModel):
    """Returned by arXiv MCP tools."""

    arxiv_id: str
    title: str
    authors: list[str]
    abstract: str
    published: str
    url: str
    categories: list[str]
    full_text: str | None = None


class CVEEntry(BaseModel):
    """Returned by NVD MCP tools."""

    cve_id: str
    description: str
    severity: str | None = None
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    published_date: str
    last_modified_date: str
    affected_products: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class ATLASTechnique(BaseModel):
    """Returned by MITRE ATLAS MCP tools."""

    technique_id: str
    name: str
    description: str
    tactic: str
    subtechniques: list[str] = Field(default_factory=list)
    case_studies: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)
    url: str


class MCPToolError(BaseModel):
    """Standard error format for all MCP servers."""

    error: str
    error_type: str
    retryable: bool = False


# ---------------------------------------------------------------------------
# API schemas
# ---------------------------------------------------------------------------


class AnalyzeRequest(BaseModel):
    """Body for POST /analyze."""

    target_description: str = Field(min_length=20, max_length=2000)
    session_id: str | None = None


class AgentEvent(BaseModel):
    """SSE payload for /analyze/stream."""

    session_id: str
    agent: str
    event_type: str
    payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# Semantic memory
# ---------------------------------------------------------------------------


class ThreatPattern(BaseModel):
    """Entry in the Threat Pattern Library (semantic memory).

    Ingested by scripts/ingest_patterns.py from ATLAS and OWASP.
    Read-only at runtime.
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    source_type: str
    pattern_id: str
    name: str
    pattern_text: str
    metadata: dict[str, Any] = Field(default_factory=dict)
