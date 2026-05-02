# NEXUS — Data Models (Source de Vérité)

Ce document est la référence pour tous les schémas Pydantic v2 du projet.
**Implémentation :** `src/nexus/schemas/models.py`
**Règle :** toujours importer depuis ce module. Ne jamais redéfinir.

---

## Enums

```python
from enum import StrEnum


class FocusArea(StrEnum):
    """Catégorie d'attaque ciblée par une ResearchTask."""
    INJECTION = "injection"              # Prompt injection, indirect injection
    DATA_LEAKAGE = "data_leakage"        # PII extraction, training data leakage
    SUPPLY_CHAIN = "supply_chain"        # Dependency poisoning, model tampering
    DENIAL_OF_SERVICE = "dos"            # Token flooding, context manipulation
    MODEL_EXTRACTION = "model_extraction" # Model stealing, membership inference
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
```

---

## Modèles Core

```python
from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


class ResearchTask(BaseModel):
    """Tâche de recherche produite par le Planner."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    description: str = Field(min_length=10)
    focus_area: FocusArea
    priority: Priority
    search_queries: list[str] = Field(
        default_factory=list,
        description="Queries pré-générées par le Planner pour chaque MCP server"
    )


class FindingResult(BaseModel):
    """Résultat unique de recherche retourné par le Researcher."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    task_id: str = Field(description="ID de la ResearchTask associée")
    source_type: SourceType
    title: str
    summary: str = Field(min_length=20)
    relevance_score: Annotated[float, Field(ge=0.0, le=1.0)]
    url: str | None = None
    identifiers: list[str] = Field(
        default_factory=list,
        description="CVE-2024-XXXX | arxiv:2401.XXXXX | ATLAS-T0001 | OWASP-LLM01"
    )

    @field_validator("relevance_score")
    @classmethod
    def round_score(cls, v: float) -> float:
        return round(v, 4)


class ThreatSurface(BaseModel):
    """Surface d'attaque identifiée par l'Analyst."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str = Field(
        description="Ex: 'Indirect Prompt Injection via Retrieved Documents'"
    )
    description: str = Field(min_length=30)
    severity: Severity
    attack_vectors: list[str] = Field(
        description="IDs ATLAS (ATLAS-T0054) ou free-text"
    )
    evidence: list[FindingResult] = Field(min_length=1)
    mitigations: list[str] = Field(min_length=1)
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    owasp_category: str | None = Field(
        default=None,
        description="Ex: 'LLM01: Prompt Injection'"
    )

    @model_validator(mode="after")
    def require_evidence(self) -> ThreatSurface:
        if not self.evidence:
            raise ValueError("ThreatSurface must have at least one FindingResult as evidence")
        return self


class CriticReport(BaseModel):
    """Rapport d'évaluation produit par le Critic."""
    overall_score: Annotated[float, Field(ge=0.0, le=1.0)]
    gaps: list[str] = Field(
        description="Vecteurs d'attaque non couverts, ex: 'Model extraction attacks'"
    )
    bias_warnings: list[str] = Field(
        default_factory=list,
        description="Biais détectés, ex: 'Over-weighted injection attacks'"
    )
    recommendation: Recommendation
    re_research_tasks: list[ResearchTask] = Field(
        default_factory=list,
        description="Tâches de re-recherche (uniquement si recommendation==RE_RESEARCH)"
    )

    @model_validator(mode="after")
    def tasks_required_for_re_research(self) -> CriticReport:
        if (
            self.recommendation == Recommendation.RE_RESEARCH
            and not self.re_research_tasks
        ):
            raise ValueError(
                "re_research_tasks must be non-empty when recommendation is RE_RESEARCH"
            )
        return self


class ThreatReport(BaseModel):
    """Rapport final produit par le Writer."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    target_description: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    threat_surfaces: list[ThreatSurface] = Field(min_length=1)
    critic_report: CriticReport
    iteration_count: int = Field(ge=1, le=3)
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="total_tokens: int, estimated_cost_usd: float, latency_seconds: float, "
                    "source_breakdown: dict[SourceType, int]"
    )


class ThreatReportSummary(BaseModel):
    """Version condensée pour la mémoire épisodique (pgvector).
    
    JAMAIS stocker ThreatReport complet en mémoire épisodique — toujours ThreatReportSummary.
    """
    id: str
    session_id: str
    target_description: str
    created_at: datetime
    surface_count: int = Field(ge=0)
    severity_breakdown: dict[str, int] = Field(
        description="{'critical': 1, 'high': 2, 'medium': 3, 'low': 1}"
    )
    focus_areas_covered: list[FocusArea]
    top_attack_vectors: list[str] = Field(
        max_length=5,
        description="Top 5 vecteurs — utilisés pour la recherche de similarité épisodique"
    )
    overall_critic_score: float = Field(ge=0.0, le=1.0)
    iteration_count: int
```

---

## LangGraph State

```python
from typing import TypedDict, Annotated
from langchain_core.messages import BaseMessage
from langgraph.graph import add_messages


class AgentState(TypedDict):
    # Messages LangGraph (append-only via add_messages reducer)
    messages: Annotated[list[BaseMessage], add_messages]
    
    # Input
    target_description: str
    session_id: str
    
    # Pipeline state (mis à jour par chaque agent)
    plan: list[ResearchTask]            # Planner → []
    findings: list[FindingResult]       # Researcher → [] (cumulatif sur itérations)
    threat_surfaces: list[ThreatSurface] # Analyst → []
    critic_report: CriticReport | None  # Critic → None
    threat_report: ThreatReport | None  # Writer → None
    
    # Control flow
    iteration_count: int                # incrémenté par Researcher, max=3
    should_continue: bool               # posé par Critic (True=re-research, False=write)
```

---

## Return Types MCP Servers

```python
class ArxivPaper(BaseModel):
    """Retourné par arXiv MCP tools."""
    arxiv_id: str = Field(description="Ex: '2401.12345'")
    title: str
    authors: list[str]
    abstract: str
    published: str = Field(description="ISO date string")
    url: str
    categories: list[str]
    full_text: str | None = None  # Présent uniquement si get_full_text appelé


class CVEEntry(BaseModel):
    """Retourné par NVD MCP tools."""
    cve_id: str = Field(description="Format: CVE-YYYY-NNNNN")
    description: str
    severity: str | None = Field(description="CRITICAL|HIGH|MEDIUM|LOW")
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    published_date: str
    last_modified_date: str
    affected_products: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class ATLASTechnique(BaseModel):
    """Retourné par MITRE ATLAS MCP tools."""
    technique_id: str = Field(description="Ex: 'AML.T0054'")
    name: str
    description: str
    tactic: str = Field(description="Ex: 'ML Attack Staging'")
    subtechniques: list[str] = Field(default_factory=list)
    case_studies: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)
    url: str


class MCPError(BaseModel):
    """Format standard d'erreur pour tous les MCP servers."""
    error: str
    error_type: str  # "rate_limit" | "not_found" | "api_error" | "parse_error"
    retryable: bool = False
```

---

## API Schemas

```python
class AnalyzeRequest(BaseModel):
    """Body de POST /analyze."""
    target_description: str = Field(
        min_length=20,
        max_length=2000,
        description="Description naturelle de l'architecture AI à auditer"
    )
    session_id: str | None = Field(
        default=None,
        description="Optionnel — généré automatiquement si absent"
    )


class AgentEvent(BaseModel):
    """Payload SSE pour /analyze/stream."""
    session_id: str
    agent: str = Field(
        description="planner | researcher | analyst | critic | writer"
    )
    event_type: str = Field(
        description="started | finding | surface | gap | completed | error"
    )
    payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
```

---

## Threat Pattern Library (Semantic Memory)

```python
class ThreatPattern(BaseModel):
    """Entrée dans la Threat Pattern Library (mémoire sémantique).
    
    Ingérée par scripts/ingest_patterns.py depuis ATLAS et OWASP.
    Read-only au runtime.
    """
    id: str = Field(default_factory=lambda: str(uuid4()))
    source_type: str = Field(description="'atlas' | 'owasp_llm'")
    pattern_id: str = Field(description="AML.T0054 | LLM01")
    name: str
    pattern_text: str = Field(description="Texte combiné name + description pour embedding")
    metadata: dict[str, Any] = Field(default_factory=dict)
    # embedding: vector(1536) — stocké dans pgvector, pas dans ce modèle
```

---

## Notes d'implémentation

### Validators critiques
1. `ThreatSurface.evidence` : ne peut jamais être vide (model_validator "after")
2. `CriticReport.re_research_tasks` : requis si `recommendation==RE_RESEARCH`
3. `ThreatReport.iteration_count` : borné [1, 3] (ge=1, le=3)
4. `FindingResult.relevance_score` : arrondi à 4 décimales

### Sérialisation / Désérialisation
```python
# Toujours utiliser model_dump_json() pour la sérialisation
report_json = threat_report.model_dump_json()

# Pour les nested models avec Union types
report = ThreatReport.model_validate_json(json_string)

# Encodage datetime : ISO format avec timezone
model_config = ConfigDict(json_encoders={datetime: lambda v: v.isoformat()})
```

### Gestion des None dans AgentState
```python
# Pattern recommandé dans les agents pour les champs optionnels
critic_report = state.get("critic_report")  # peut être None
if critic_report is None:
    # Premier passage — pas encore évalué
    ...
```
