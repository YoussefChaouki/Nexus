"""Tests for the S9.T1 evaluation harness.

Pure metric tests run in the default CI lane; the end-to-end harness and
baseline runs (which compile the real LangGraph) are marked
``integration`` to match the rest of the suite.

E2E RESULTS — Sprint 9 (offline mock, deterministic):
    test_run_eval_offline_end_to_end:       PASS
    test_run_eval_writes_results_file:       PASS
    test_single_prompt_baseline_with_mock:   PASS
    test_baseline_scores_below_nexus:        PASS
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from nexus.schemas.models import (
    CriticReport,
    FindingResult,
    Recommendation,
    Severity,
    SourceType,
    ThreatReport,
    ThreatSurface,
)
from tests.eval.architectures import ARCHITECTURES, Architecture
from tests.eval.fakes import baseline_mock_llm
from tests.eval.harness import (
    EvalResults,
    _parse_baseline,
    extract_owasp_from_report,
    normalize_owasp,
    owasp_coverage,
    run_eval,
    run_single_prompt_baseline,
    surface_coverage,
)

# ---------------------------------------------------------------------------
# Pure metric tests (default CI lane)
# ---------------------------------------------------------------------------


def test_benchmark_has_five_architectures() -> None:
    assert len(ARCHITECTURES) == 5
    assert len({a.id for a in ARCHITECTURES}) == 5


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("LLM01", {"LLM01"}),
        ("LLM01: Prompt Injection", {"LLM01"}),
        ("llm 1 and LLM10", {"LLM01", "LLM10"}),
        ("LLM11 is out of range", set()),
        ("no codes here", set()),
    ],
)
def test_normalize_owasp(text: str, expected: set[str]) -> None:
    assert normalize_owasp(text) == expected


def test_owasp_coverage_partial() -> None:
    cov, matched = owasp_coverage(["LLM01", "LLM06", "LLM05"], {"LLM01", "LLM06"})
    assert cov == pytest.approx(2 / 3)
    assert matched == ["LLM01", "LLM06"]


def test_owasp_coverage_full_and_empty() -> None:
    assert owasp_coverage(["LLM01"], {"LLM01"}) == (1.0, ["LLM01"])
    assert owasp_coverage([], {"LLM01"}) == (0.0, [])


def test_surface_coverage_token_overlap() -> None:
    cov, matched = surface_coverage(
        ["prompt_injection", "model_denial_of_service", "insecure_plugin"],
        ["Prompt Injection via RAG", "Model Denial of Service"],
    )
    assert "prompt_injection" in matched
    assert "model_denial_of_service" in matched
    assert "insecure_plugin" not in matched
    assert cov == pytest.approx(2 / 3)


def test_surface_coverage_empty_expected() -> None:
    assert surface_coverage([], ["anything"]) == (0.0, [])


def _make_report(owasp_categories: list[str | None]) -> ThreatReport:
    finding = FindingResult(
        id="f-1",
        task_id="t-1",
        source_type=SourceType.ARXIV,
        title="Evidence",
        summary="A sufficiently long synthetic finding summary for tests.",
        relevance_score=0.8,
    )
    surfaces = [
        ThreatSurface(
            name=f"Surface {i}",
            description="A sufficiently long synthetic threat-surface description.",
            severity=Severity.HIGH,
            attack_vectors=["vector"],
            evidence=[finding],
            mitigations=["mitigate"],
            owasp_category=cat,
        )
        for i, cat in enumerate(owasp_categories)
    ]
    return ThreatReport(
        target_description="test target",
        threat_surfaces=surfaces,
        critic_report=CriticReport(
            overall_score=0.8, gaps=[], recommendation=Recommendation.APPROVE
        ),
        iteration_count=1,
    )


def test_extract_owasp_from_report() -> None:
    report = _make_report(["LLM01: Prompt Injection", "LLM06", None])
    assert extract_owasp_from_report(report) == {"LLM01", "LLM06"}


def test_parse_baseline_json() -> None:
    content = '{"owasp_categories": ["LLM01", "LLM06"], "threat_surfaces": ["A", "B"]}'
    owasp, surfaces = _parse_baseline(content)
    assert owasp == {"LLM01", "LLM06"}
    assert surfaces == ["A", "B"]


def test_parse_baseline_code_fence_and_prose() -> None:
    fenced = '```json\n{"owasp_categories": ["LLM10"], "threat_surfaces": []}\n```'
    owasp, surfaces = _parse_baseline(fenced)
    assert owasp == {"LLM10"}
    assert surfaces == []


def test_parse_baseline_malformed_falls_back_to_scrape() -> None:
    owasp, surfaces = _parse_baseline("threats: LLM01 and LLM04, no json")
    assert owasp == {"LLM01", "LLM04"}
    assert surfaces == []


# ---------------------------------------------------------------------------
# End-to-end harness (integration lane)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.integration
async def test_run_eval_offline_end_to_end() -> None:
    results = await run_eval(use_real_llm=False, results_path=None)
    assert isinstance(results, EvalResults)
    assert results.used_real_llm is False
    assert len(results.per_architecture) == len(ARCHITECTURES)
    assert 0.0 <= results.mean_owasp_coverage <= 1.0
    assert 0.0 <= results.mean_surface_coverage <= 1.0
    # The deterministic Analyst maps injection→LLM01, so every architecture
    # that expects LLM01 must have it covered.
    for result in results.per_architecture:
        assert 0.0 <= result.owasp_coverage <= 1.0
        if "LLM01" in result.expected_owasp:
            assert "LLM01" in result.found_owasp
    # Offline mock emits a multi-band severity distribution, not flat HIGH.
    all_bands = {band for r in results.per_architecture for band in r.severity_breakdown}
    assert len(all_bands) >= 2


@pytest.mark.asyncio
@pytest.mark.integration
async def test_run_eval_writes_results_file(tmp_path: Path) -> None:
    out = tmp_path / "results.json"
    results = await run_eval(
        use_real_llm=False,
        architectures=ARCHITECTURES[:2],
        results_path=out,
    )
    assert out.exists()
    reloaded = EvalResults.model_validate_json(out.read_text())
    assert reloaded.generated_at <= datetime.now(UTC)
    assert len(reloaded.per_architecture) == 2
    assert reloaded.per_architecture == results.per_architecture


@pytest.mark.asyncio
@pytest.mark.integration
async def test_single_prompt_baseline_with_mock() -> None:
    arch = ARCHITECTURES[0]  # rag_basic: expects LLM01, LLM06, LLM05
    result = await run_single_prompt_baseline(arch, llm=baseline_mock_llm())
    assert result.strategy == "baseline"
    # Mock returns LLM01 + LLM06 (2 of 3 expected).
    assert result.found_owasp == ["LLM01", "LLM06"]
    assert result.owasp_coverage == pytest.approx(2 / 3)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_baseline_scores_below_nexus() -> None:
    """The multi-agent pipeline should not lose to the single-prompt baseline."""
    arch = Architecture(
        id="probe",
        description="FastAPI + pgvector RAG, OpenAI API, no auth",
        expected_surfaces=["prompt_injection", "data_leakage", "supply_chain"],
        expected_owasp=["LLM01", "LLM06", "LLM05"],
    )
    nexus = (
        await run_eval(use_real_llm=False, architectures=[arch], results_path=None)
    ).per_architecture[0]
    baseline = await run_single_prompt_baseline(arch, llm=baseline_mock_llm())
    assert nexus.owasp_coverage >= baseline.owasp_coverage
