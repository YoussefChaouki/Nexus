"""Integration tests for the Planner → Researcher → Analyst pipeline.

Real LangGraph + real Pydantic + real agent code — only the LLM and the
MCP transport are faked (see :mod:`tests.integration.conftest`).
"""

from __future__ import annotations

from typing import Any, cast

import pytest
from langgraph.graph import END, StateGraph

from nexus.agents.analyst import AnalystAgent
from nexus.agents.critic import CriticAgent
from nexus.agents.planner import PlannerAgent
from nexus.agents.researcher import ResearcherAgent
from nexus.agents.writer import WriterAgent
from nexus.exceptions import AgentError
from nexus.graph.edges import route_after_critic
from nexus.schemas.models import (
    AgentState,
    FindingResult,
    ResearchTask,
    Severity,
    SourceType,
    ThreatSurface,
)
from tests.integration.conftest import _FakeMCPClient, _FakeRoutingLLM

pytestmark = pytest.mark.integration


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


async def _fake_score(_task: ResearchTask, _finding: FindingResult) -> float:
    return 0.7


def _build_pipeline(llm: _FakeRoutingLLM, mcp: _FakeMCPClient) -> Any:
    """Build the full pipeline graph wired with fake LLM + fake MCP."""
    planner = PlannerAgent(llm=llm)
    researcher = ResearcherAgent(mcp_client=cast(Any, mcp), scoring_fn=_fake_score)
    analyst = AnalystAgent(llm=llm)
    critic = CriticAgent()
    writer = WriterAgent()

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


def _initial_state(target: str) -> AgentState:
    return cast(
        AgentState,
        {
            "messages": [],
            "target_description": target,
            "session_id": "integration-test",
            "plan": [],
            "findings": [],
            "threat_surfaces": [],
            "critic_report": None,
            "threat_report": None,
            "iteration_count": 0,
            "should_continue": True,
        },
    )


_TARGET = "FastAPI + pgvector RAG, OpenAI API, no auth"


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------


async def test_planner_to_researcher(
    mock_llm: _FakeRoutingLLM,
    mock_mcp_client: _FakeMCPClient,
) -> None:
    pipeline = _build_pipeline(mock_llm, mock_mcp_client)

    final = await pipeline.ainvoke(_initial_state(_TARGET))

    plan = final["plan"]
    findings = final["findings"]
    assert 4 <= len(plan) <= 6, f"plan has {len(plan)} tasks; expected 4-6"
    assert all(isinstance(t, ResearchTask) for t in plan)
    assert len(findings) >= 5, f"only {len(findings)} findings collected"
    assert all(isinstance(f, FindingResult) for f in findings)
    # Researcher increments iteration_count once per pass; placeholder
    # critic always APPROVEs so we never re-loop.
    assert final["iteration_count"] == 1


async def test_researcher_to_analyst(
    mock_llm: _FakeRoutingLLM,
    mock_mcp_client: _FakeMCPClient,
) -> None:
    pipeline = _build_pipeline(mock_llm, mock_mcp_client)

    final = await pipeline.ainvoke(_initial_state(_TARGET))

    surfaces = final["threat_surfaces"]
    assert len(surfaces) >= 2, f"only {len(surfaces)} threat surfaces produced"
    assert all(isinstance(s, ThreatSurface) for s in surfaces)
    assert all(s.evidence for s in surfaces), "every surface must have evidence"
    assert any(s.severity in (Severity.CRITICAL, Severity.HIGH) for s in surfaces), (
        "expected at least one CRITICAL/HIGH surface"
    )


async def test_partial_mcp_failure(
    mock_llm: _FakeRoutingLLM,
) -> None:
    """NVD raises mid-pipeline — arXiv + ATLAS still produce findings."""
    mcp = _FakeMCPClient(error_servers={"nvd"})
    pipeline = _build_pipeline(mock_llm, mcp)

    final = await pipeline.ainvoke(_initial_state(_TARGET))

    findings = final["findings"]
    assert findings, "pipeline must continue when one MCP server fails"
    sources = {f.source_type for f in findings}
    assert SourceType.NVD not in sources
    assert SourceType.ARXIV in sources or SourceType.ATLAS in sources
    # NVD was still attempted (and failed) for every task; assert the call
    # actually happened so the test fails loudly if routing changes.
    nvd_calls = [c for c in mcp.calls if c[0] == "nvd"]
    assert nvd_calls, "expected NVD to be called at least once"


async def test_empty_findings_raises(
    mock_llm: _FakeRoutingLLM,
) -> None:
    """All MCPs return empty → Researcher raises AgentError."""
    mcp = _FakeMCPClient(empty_servers={"arxiv", "nvd", "atlas"})
    pipeline = _build_pipeline(mock_llm, mcp)

    with pytest.raises(AgentError, match="zero findings"):
        await pipeline.ainvoke(_initial_state(_TARGET))
