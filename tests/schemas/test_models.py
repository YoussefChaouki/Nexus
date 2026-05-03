"""Tests for src/nexus/schemas/models.py."""

import pytest
from pydantic import ValidationError

from nexus.schemas.models import (
    AgentState,
    AnalyzeRequest,
    ArxivPaper,
    ATLASTechnique,
    CriticReport,
    CVEEntry,
    FindingResult,
    FocusArea,
    MCPToolError,
    Priority,
    Recommendation,
    ResearchTask,
    Severity,
    SourceType,
    ThreatPattern,
    ThreatReport,
    ThreatReportSummary,
    ThreatSurface,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def research_task() -> ResearchTask:
    return ResearchTask(
        description="Research prompt injection vulnerabilities in RAG pipelines",
        focus_area=FocusArea.INJECTION,
        priority=Priority.HIGH,
        search_queries=["prompt injection RAG", "indirect injection LLM"],
    )


@pytest.fixture
def finding_result(research_task: ResearchTask) -> FindingResult:
    return FindingResult(
        task_id=research_task.id,
        source_type=SourceType.ARXIV,
        title="Prompt Injection Attacks and Defenses",
        summary="A comprehensive survey of prompt injection attack vectors and mitigation strategies.",
        relevance_score=0.9,
        url="https://arxiv.org/abs/2401.12345",
        identifiers=["arxiv:2401.12345"],
    )


@pytest.fixture
def threat_surface(finding_result: FindingResult) -> ThreatSurface:
    return ThreatSurface(
        name="Indirect Prompt Injection via Retrieved Documents",
        description=(
            "Malicious instructions embedded in retrieved documents can hijack the LLM "
            "and exfiltrate sensitive data."
        ),
        severity=Severity.CRITICAL,
        attack_vectors=["ATLAS-T0054", "indirect document injection"],
        evidence=[finding_result],
        mitigations=["Sanitize retrieved content", "Use output filters"],
        owasp_category="LLM01: Prompt Injection",
    )


@pytest.fixture
def critic_report_approve(research_task: ResearchTask) -> CriticReport:
    return CriticReport(
        overall_score=0.85,
        gaps=["Model extraction not covered"],
        recommendation=Recommendation.APPROVE,
    )


@pytest.fixture
def threat_report(threat_surface: ThreatSurface, critic_report_approve: CriticReport) -> ThreatReport:
    return ThreatReport(
        target_description="FastAPI + pgvector RAG pipeline",
        threat_surfaces=[threat_surface],
        critic_report=critic_report_approve,
        iteration_count=1,
    )


# ---------------------------------------------------------------------------
# ResearchTask
# ---------------------------------------------------------------------------


def test_research_task_happy_path(research_task: ResearchTask) -> None:
    assert research_task.focus_area == FocusArea.INJECTION
    assert research_task.priority == Priority.HIGH
    assert len(research_task.id) > 0


def test_research_task_description_too_short() -> None:
    with pytest.raises(ValidationError):
        ResearchTask(
            description="short",
            focus_area=FocusArea.INJECTION,
            priority=Priority.LOW,
        )


# ---------------------------------------------------------------------------
# FindingResult
# ---------------------------------------------------------------------------


def test_finding_result_happy_path(finding_result: FindingResult) -> None:
    assert finding_result.source_type == SourceType.ARXIV
    assert 0.0 <= finding_result.relevance_score <= 1.0


def test_finding_result_score_rounded(research_task: ResearchTask) -> None:
    f = FindingResult(
        task_id=research_task.id,
        source_type=SourceType.NVD,
        title="CVE test",
        summary="A detailed summary of the CVE vulnerability that meets minimum length.",
        relevance_score=0.123456789,
    )
    assert f.relevance_score == round(0.123456789, 4)


def test_finding_result_score_out_of_range(research_task: ResearchTask) -> None:
    with pytest.raises(ValidationError):
        FindingResult(
            task_id=research_task.id,
            source_type=SourceType.WEB,
            title="Test",
            summary="A detailed summary that is definitely long enough to pass validation.",
            relevance_score=1.5,
        )


# ---------------------------------------------------------------------------
# ThreatSurface
# ---------------------------------------------------------------------------


def test_threat_surface_happy_path(threat_surface: ThreatSurface) -> None:
    assert threat_surface.severity == Severity.CRITICAL
    assert len(threat_surface.evidence) >= 1


def test_threat_surface_empty_evidence(finding_result: FindingResult) -> None:
    with pytest.raises(ValidationError, match="at least one FindingResult"):
        ThreatSurface(
            name="Test Surface",
            description="A sufficiently long description for this threat surface.",
            severity=Severity.LOW,
            attack_vectors=["vector1"],
            evidence=[],
            mitigations=["mitigation1"],
        )


# ---------------------------------------------------------------------------
# CriticReport
# ---------------------------------------------------------------------------


def test_critic_report_approve_empty_tasks() -> None:
    report = CriticReport(
        overall_score=0.9,
        gaps=[],
        recommendation=Recommendation.APPROVE,
    )
    assert report.recommendation == Recommendation.APPROVE
    assert report.re_research_tasks == []


def test_critic_report_re_research_requires_tasks() -> None:
    with pytest.raises(ValidationError, match="re_research_tasks must be non-empty"):
        CriticReport(
            overall_score=0.4,
            gaps=["Missing supply chain analysis"],
            recommendation=Recommendation.RE_RESEARCH,
            re_research_tasks=[],
        )


def test_critic_report_re_research_with_tasks() -> None:
    task = ResearchTask(
        description="Research supply chain vulnerabilities in ML pipelines",
        focus_area=FocusArea.SUPPLY_CHAIN,
        priority=Priority.HIGH,
    )
    report = CriticReport(
        overall_score=0.4,
        gaps=["Missing supply chain analysis"],
        recommendation=Recommendation.RE_RESEARCH,
        re_research_tasks=[task],
    )
    assert len(report.re_research_tasks) == 1


# ---------------------------------------------------------------------------
# ThreatReport
# ---------------------------------------------------------------------------


def test_threat_report_happy_path(threat_report: ThreatReport) -> None:
    assert threat_report.iteration_count == 1
    assert len(threat_report.threat_surfaces) >= 1
    assert len(threat_report.id) > 0


def test_threat_report_iteration_count_too_low(
    threat_surface: ThreatSurface,
    critic_report_approve: CriticReport,
) -> None:
    with pytest.raises(ValidationError):
        ThreatReport(
            target_description="test",
            threat_surfaces=[threat_surface],
            critic_report=critic_report_approve,
            iteration_count=0,
        )


def test_threat_report_iteration_count_too_high(
    threat_surface: ThreatSurface,
    critic_report_approve: CriticReport,
) -> None:
    with pytest.raises(ValidationError):
        ThreatReport(
            target_description="test",
            threat_surfaces=[threat_surface],
            critic_report=critic_report_approve,
            iteration_count=4,
        )


# ---------------------------------------------------------------------------
# ThreatReportSummary
# ---------------------------------------------------------------------------


def test_threat_report_summary_happy_path() -> None:
    from datetime import UTC, datetime

    summary = ThreatReportSummary(
        id="abc",
        session_id="sess-1",
        target_description="RAG pipeline",
        created_at=datetime.now(UTC),
        surface_count=3,
        severity_breakdown={"critical": 1, "high": 2},
        focus_areas_covered=[FocusArea.INJECTION],
        top_attack_vectors=["indirect injection", "prompt hijack"],
        overall_critic_score=0.8,
        iteration_count=2,
    )
    assert summary.surface_count == 3


# ---------------------------------------------------------------------------
# AgentState
# ---------------------------------------------------------------------------


def test_agent_state_structure() -> None:
    keys = AgentState.__annotations__.keys()
    assert "messages" in keys
    assert "target_description" in keys
    assert "plan" in keys
    assert "findings" in keys
    assert "threat_surfaces" in keys
    assert "critic_report" in keys
    assert "threat_report" in keys
    assert "iteration_count" in keys
    assert "should_continue" in keys


# ---------------------------------------------------------------------------
# MCP return types
# ---------------------------------------------------------------------------


def test_arxiv_paper_happy_path() -> None:
    paper = ArxivPaper(
        arxiv_id="2401.12345",
        title="Test Paper",
        authors=["Alice", "Bob"],
        abstract="An abstract.",
        published="2024-01-15",
        url="https://arxiv.org/abs/2401.12345",
        categories=["cs.CR"],
    )
    assert paper.full_text is None


def test_cve_entry_happy_path() -> None:
    cve = CVEEntry(
        cve_id="CVE-2024-12345",
        description="A critical vulnerability.",
        severity="CRITICAL",
        cvss_score=9.8,
        published_date="2024-01-01",
        last_modified_date="2024-01-10",
    )
    assert cve.cvss_score == 9.8


def test_atlas_technique_happy_path() -> None:
    tech = ATLASTechnique(
        technique_id="AML.T0054",
        name="Prompt Injection",
        description="Adversary injects malicious instructions.",
        tactic="ML Attack Staging",
        url="https://atlas.mitre.org/techniques/AML.T0054",
    )
    assert tech.subtechniques == []


def test_mcp_tool_error_happy_path() -> None:
    err = MCPToolError(error="Rate limit exceeded", error_type="rate_limit", retryable=True)
    assert err.retryable is True


# ---------------------------------------------------------------------------
# API schemas
# ---------------------------------------------------------------------------


def test_analyze_request_happy_path() -> None:
    req = AnalyzeRequest(
        target_description="FastAPI backend with OpenAI integration and no authentication layer."
    )
    assert req.session_id is None


def test_analyze_request_too_short() -> None:
    with pytest.raises(ValidationError):
        AnalyzeRequest(target_description="short")


# ---------------------------------------------------------------------------
# ThreatPattern
# ---------------------------------------------------------------------------


def test_threat_pattern_happy_path() -> None:
    pattern = ThreatPattern(
        source_type="atlas",
        pattern_id="AML.T0054",
        name="Prompt Injection",
        pattern_text="Prompt Injection. Adversary manipulates LLM via crafted inputs.",
    )
    assert pattern.metadata == {}
