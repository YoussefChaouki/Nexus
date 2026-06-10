"""NEXUS evaluation harness (S9.T1).

Runs the full pipeline (or a single-prompt baseline) over the benchmark
:data:`~tests.eval.architectures.ARCHITECTURES` and scores two metrics:

* **owasp_coverage** — fraction of each architecture's ``expected_owasp``
  categories that appear in the produced output.
* **surface_coverage** — fraction of ``expected_surfaces`` matched by
  name similarity (token overlap / sequence ratio) against the produced
  surface names.

Both the multi-agent pipeline and the single-prompt baseline are scored
with the *same* extractors and metric functions so the comparison in
``scripts/compare_baseline.py`` is apples-to-apples.
"""

from __future__ import annotations

import difflib
import re
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import structlog
from pydantic import BaseModel, Field

from nexus.exceptions import AgentError
from nexus.schemas.models import ThreatReport
from tests.eval.architectures import ARCHITECTURES, Architecture

logger = structlog.get_logger(__name__)

RESULTS_PATH = Path(__file__).parent / "results.json"

_STOPWORDS = frozenset(
    {"of", "the", "via", "and", "a", "an", "to", "in", "on", "at", "for", "with"}
)
_OWASP_RE = re.compile(r"LLM\s*0*(\d{1,2})", re.IGNORECASE)
_SURFACE_MATCH_THRESHOLD = 0.5
_SEQUENCE_MATCH_THRESHOLD = 0.7


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------


class CoverageResult(BaseModel):
    """Coverage outcome for one architecture under one strategy."""

    architecture_id: str
    strategy: str  # "nexus" | "baseline"
    expected_owasp: list[str]
    found_owasp: list[str]
    owasp_coverage: float = Field(ge=0.0, le=1.0)
    expected_surfaces: list[str]
    matched_surfaces: list[str]
    surface_names: list[str]
    surface_coverage: float = Field(ge=0.0, le=1.0)
    surface_count: int = Field(ge=0)
    severity_breakdown: dict[str, int] = Field(default_factory=dict)
    iteration_count: int = Field(default=0, ge=0)
    latency_seconds: float = Field(default=0.0, ge=0.0)


class EvalResults(BaseModel):
    """Aggregate eval output, persisted to ``results.json``."""

    generated_at: datetime
    used_real_llm: bool
    per_architecture: list[CoverageResult]
    mean_owasp_coverage: float = Field(ge=0.0, le=1.0)
    mean_surface_coverage: float = Field(ge=0.0, le=1.0)
    total_latency_seconds: float = Field(ge=0.0)


# ---------------------------------------------------------------------------
# Metric primitives
# ---------------------------------------------------------------------------


def normalize_owasp(text: str) -> set[str]:
    """Extract canonical ``LLM01``..``LLM10`` codes from free text.

    Handles ``"LLM01"``, ``"LLM01: Prompt Injection"``, ``"llm 1"`` and
    similar; ignores out-of-range numbers.
    """
    out: set[str] = set()
    for match in _OWASP_RE.finditer(text):
        n = int(match.group(1))
        if 1 <= n <= 10:
            out.add(f"LLM{n:02d}")
    return out


def _tokens(name: str) -> set[str]:
    cleaned = re.sub(r"[^a-z0-9]+", " ", name.lower())
    return {t for t in cleaned.split() if t and t not in _STOPWORDS}


def owasp_coverage(expected: list[str], found: set[str]) -> tuple[float, list[str]]:
    """Fraction of ``expected`` OWASP codes present in ``found``."""
    expected_codes = {c.upper() for c in expected}
    if not expected_codes:
        return 0.0, []
    matched = sorted(expected_codes & found)
    return len(matched) / len(expected_codes), matched


def _surface_matches(expected: str, found_names: list[str]) -> bool:
    expected_tokens = _tokens(expected)
    if not expected_tokens:
        return False
    expected_phrase = expected.replace("_", " ").lower()
    for name in found_names:
        found_tokens = _tokens(name)
        if found_tokens:
            overlap = len(expected_tokens & found_tokens) / len(expected_tokens)
            if overlap >= _SURFACE_MATCH_THRESHOLD:
                return True
        ratio = difflib.SequenceMatcher(None, expected_phrase, name.lower()).ratio()
        if ratio >= _SEQUENCE_MATCH_THRESHOLD:
            return True
    return False


def surface_coverage(expected: list[str], found_names: list[str]) -> tuple[float, list[str]]:
    """Fraction of ``expected`` surfaces matched by name similarity."""
    if not expected:
        return 0.0, []
    matched = [e for e in expected if _surface_matches(e, found_names)]
    return len(matched) / len(expected), matched


def extract_owasp_from_report(report: ThreatReport) -> set[str]:
    """Collect OWASP codes referenced across a report's threat surfaces."""
    found: set[str] = set()
    for surface in report.threat_surfaces:
        if surface.owasp_category:
            found |= normalize_owasp(surface.owasp_category)
    return found


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------


def _score_nexus(arch: Architecture, report: ThreatReport, latency: float) -> CoverageResult:
    found_owasp = extract_owasp_from_report(report)
    o_cov, o_matched = owasp_coverage(arch.expected_owasp, found_owasp)
    names = [s.name for s in report.threat_surfaces]
    s_cov, s_matched = surface_coverage(arch.expected_surfaces, names)
    severity = dict(Counter(s.severity.value for s in report.threat_surfaces))
    return CoverageResult(
        architecture_id=arch.id,
        strategy="nexus",
        expected_owasp=arch.expected_owasp,
        found_owasp=sorted(found_owasp),
        owasp_coverage=o_cov,
        expected_surfaces=arch.expected_surfaces,
        matched_surfaces=s_matched,
        surface_names=names,
        surface_coverage=s_cov,
        surface_count=len(report.threat_surfaces),
        severity_breakdown=severity,
        iteration_count=report.iteration_count,
        latency_seconds=latency,
    )


def _score_baseline(
    arch: Architecture,
    found_owasp: set[str],
    surface_names: list[str],
    latency: float,
) -> CoverageResult:
    o_cov, _ = owasp_coverage(arch.expected_owasp, found_owasp)
    s_cov, s_matched = surface_coverage(arch.expected_surfaces, surface_names)
    return CoverageResult(
        architecture_id=arch.id,
        strategy="baseline",
        expected_owasp=arch.expected_owasp,
        found_owasp=sorted(found_owasp),
        owasp_coverage=o_cov,
        expected_surfaces=arch.expected_surfaces,
        matched_surfaces=s_matched,
        surface_names=surface_names,
        surface_coverage=s_cov,
        surface_count=len(surface_names),
        latency_seconds=latency,
    )


def _write_results(path: Path, results: EvalResults) -> None:
    """Persist results as JSON (sync helper: keeps file IO out of async scope)."""
    path.write_text(results.model_dump_json(indent=2), encoding="utf-8")
    logger.info("eval_results_written", path=str(path))


def _aggregate(results: list[CoverageResult], *, used_real_llm: bool) -> EvalResults:
    n = len(results) or 1
    return EvalResults(
        generated_at=datetime.now(UTC),
        used_real_llm=used_real_llm,
        per_architecture=results,
        mean_owasp_coverage=sum(r.owasp_coverage for r in results) / n,
        mean_surface_coverage=sum(r.surface_coverage for r in results) / n,
        total_latency_seconds=sum(r.latency_seconds for r in results),
    )


# ---------------------------------------------------------------------------
# Pipeline drivers
# ---------------------------------------------------------------------------


def _build_mock_pipeline() -> Any:  # noqa: ANN401 — CompiledStateGraph has no stable type.
    """Compile the real graph wired to the deterministic offline fakes."""
    from langgraph.graph import END, StateGraph

    from nexus.agents.analyst import AnalystAgent
    from nexus.agents.critic import CriticAgent
    from nexus.agents.planner import PlannerAgent
    from nexus.agents.researcher import ResearcherAgent
    from nexus.agents.writer import WriterAgent
    from nexus.graph.edges import route_after_critic
    from nexus.schemas.models import AgentState, FindingResult, ResearchTask
    from tests.eval.fakes import EvalMockLLM
    from tests.integration.conftest import _FakeMCPClient

    llm = EvalMockLLM()

    async def _score(_task: ResearchTask, _finding: FindingResult) -> float:
        return 0.8  # above researcher_min_relevance so findings survive

    planner = PlannerAgent(llm=llm)
    # embed_fn=None disables the context-relevance filter for the offline run.
    researcher = ResearcherAgent(
        mcp_client=cast(Any, _FakeMCPClient()),
        scoring_fn=_score,
        embed_fn=None,
    )
    analyst = AnalystAgent(llm=llm)
    critic = CriticAgent(llm=llm)
    writer = WriterAgent(episodic_memory=None, embed_fn=None)

    graph: StateGraph = StateGraph(AgentState)  # type: ignore[type-arg]
    graph.add_node("planner", planner.run)
    graph.add_node("researcher", researcher.run)
    graph.add_node("analyst", analyst.run)
    graph.add_node("critic", critic.run)
    graph.add_node("writer", writer.run)
    graph.set_entry_point("planner")
    graph.add_edge("planner", "researcher")
    graph.add_edge("researcher", "analyst")
    graph.add_edge("analyst", "critic")
    graph.add_conditional_edges(
        "critic",
        route_after_critic,
        {"researcher": "researcher", "writer": "writer"},
    )
    graph.add_edge("writer", END)
    return graph.compile()


async def _run_nexus(arch: Architecture, *, use_real_llm: bool) -> ThreatReport:
    if use_real_llm:
        from nexus.graph.graph import run_pipeline

        return await run_pipeline(arch.description)

    from langchain_core.messages import HumanMessage

    from nexus.schemas.models import AgentState

    pipeline = _build_mock_pipeline()
    initial: AgentState = cast(
        "AgentState",
        {
            "messages": [HumanMessage(content=arch.description)],
            "target_description": arch.description,
            "session_id": f"eval-{arch.id}",
            "plan": [],
            "findings": [],
            "threat_surfaces": [],
            "critic_report": None,
            "threat_report": None,
            "iteration_count": 0,
            "should_continue": True,
            "session_start_time": time.time(),
        },
    )
    final = cast("AgentState", await pipeline.ainvoke(initial))
    report = final["threat_report"]
    if report is None:
        raise AgentError(f"Eval pipeline produced no ThreatReport for {arch.id}")
    return report


async def run_eval(
    *,
    use_real_llm: bool = False,
    architectures: list[Architecture] | None = None,
    results_path: Path | None = RESULTS_PATH,
) -> EvalResults:
    """Run NEXUS over the benchmark and return scored coverage.

    Args:
        use_real_llm: When ``True`` run the live pipeline (requires
            ``OPENAI_API_KEY`` plus Redis/Postgres); otherwise use the
            deterministic offline mock.
        architectures: Override the benchmark set (defaults to
            :data:`ARCHITECTURES`).
        results_path: Where to write the JSON results; pass ``None`` to
            skip writing (used by tests that assert on the return value).

    Returns:
        Aggregate :class:`EvalResults`.
    """
    targets = architectures if architectures is not None else ARCHITECTURES
    results: list[CoverageResult] = []
    for arch in targets:
        start = time.perf_counter()
        report = await _run_nexus(arch, use_real_llm=use_real_llm)
        latency = time.perf_counter() - start
        result = _score_nexus(arch, report, latency)
        results.append(result)
        logger.info(
            "eval_architecture_done",
            architecture=arch.id,
            owasp_coverage=round(result.owasp_coverage, 3),
            surface_coverage=round(result.surface_coverage, 3),
        )

    eval_results = _aggregate(results, used_real_llm=use_real_llm)
    if results_path is not None:
        _write_results(results_path, eval_results)
    return eval_results


# ---------------------------------------------------------------------------
# Single-prompt baseline
# ---------------------------------------------------------------------------

_BASELINE_PROMPT = (
    "You are a security expert. Identify all security threats in the AI system "
    "described below. Respond ONLY with a JSON object of the form "
    '{{"owasp_categories": ["LLM01", ...], "threat_surfaces": ["short name", ...]}} '
    "using OWASP LLM Top 10 codes.\n\nSystem: {description}"
)


def _real_baseline_llm() -> Any:  # noqa: ANN401 — langchain generics contaminate types.
    from langchain_openai import ChatOpenAI

    from nexus.settings import get_settings

    settings = get_settings()
    return ChatOpenAI(
        model=settings.llm_model,
        openai_api_key=settings.openai_api_key.get_secret_value(),
        temperature=0,
    )


def _parse_baseline(content: str) -> tuple[set[str], list[str]]:
    """Extract OWASP codes and surface names from a baseline response.

    Falls back to scraping OWASP codes from raw text if the JSON object
    is missing or malformed.
    """
    import json

    text = content.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text.split("\n", 1)[-1] if "\n" in text else text
    try:
        start, end = text.index("{"), text.rindex("}") + 1
        data = json.loads(text[start:end])
    except (ValueError, json.JSONDecodeError):
        return normalize_owasp(content), []

    owasp: set[str] = set()
    for item in data.get("owasp_categories", []):
        owasp |= normalize_owasp(str(item))
    surfaces = [str(s) for s in data.get("threat_surfaces", [])]
    return owasp, surfaces


async def run_single_prompt_baseline(
    architecture: Architecture,
    *,
    llm: Any | None = None,  # noqa: ANN401 — accepts real or fake LLM.
) -> CoverageResult:
    """Score a single-LLM-call baseline for one architecture.

    Args:
        architecture: The benchmark target.
        llm: Optional LLM with ``async ainvoke(prompt)``; a live
            ChatOpenAI is built from Settings when omitted.

    Returns:
        A :class:`CoverageResult` with ``strategy="baseline"``.
    """
    model = llm if llm is not None else _real_baseline_llm()
    prompt = _BASELINE_PROMPT.format(description=architecture.description)
    start = time.perf_counter()
    response = await model.ainvoke(prompt)
    latency = time.perf_counter() - start
    content = str(getattr(response, "content", response))
    found_owasp, surface_names = _parse_baseline(content)
    return _score_baseline(architecture, found_owasp, surface_names, latency)
