"""End-to-end integration tests for the full 5-agent NEXUS pipeline.

These tests compile the real LangGraph, wire the real Planner /
Researcher / Analyst / Critic / Writer agents, and only stub the LLM
(:class:`ContextAwareMockLLM`), the MCP transport (:class:`_FakeMCPClient`)
and the episodic memory layer. They are the Sprint 5 acceptance suite.

Run with ``pytest tests/integration/test_full_pipeline.py -v -m integration``.

E2E TEST RESULTS — Sprint 5 (2026-05-11, mocked LLM + MCP):
    test_full_pipeline_two_iterations:        PASS (0.08s, latency 0.08s)
    test_full_pipeline_single_iteration:      PASS (0.01s)
    test_full_pipeline_max_iterations_forced: PASS (0.01s)
    test_full_pipeline_episodic_memory_written: PASS (0.01s)

Latency P50 cible < 60s : largement tenu (suite mockée). La cible
réelle sera mesurée en S6.T1 quand Langfuse capture les vraies durées
LLM/MCP — c'est le NFR à valider avant Sprint 7.
"""

# ruff: noqa: T201 — print() used intentionally for latency telemetry.

from __future__ import annotations

import time
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest
from langchain_core.messages import HumanMessage
from langgraph.graph import END, StateGraph

from nexus.agents.analyst import AnalystAgent
from nexus.agents.critic import CriticAgent
from nexus.agents.planner import PlannerAgent
from nexus.agents.researcher import ResearcherAgent
from nexus.agents.writer import WriterAgent
from nexus.graph.edges import route_after_critic
from nexus.schemas.models import (
    AgentState,
    FindingResult,
    Recommendation,
    ResearchTask,
    ThreatReport,
    ThreatReportSummary,
)
from tests.integration.conftest import ContextAwareMockLLM, _FakeMCPClient

pytestmark = [pytest.mark.asyncio, pytest.mark.integration]

_TARGET = "FastAPI + pgvector RAG, OpenAI API, no auth, documents uploaded by users"


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _scoring_via_llm(llm: ContextAwareMockLLM) -> Any:
    """Wrap the mock LLM as a Researcher ``scoring_fn`` so each scoring
    call lands in ``llm.agent_calls`` tagged ``researcher_scoring``."""

    async def _score(task: ResearchTask, finding: FindingResult) -> float:
        prompt = (
            f"On a scale from 0.0 to 1.0, how relevant is this finding "
            f"to the task '{task.description}'? Title: {finding.title}"
        )
        response = await llm.ainvoke(prompt)
        try:
            return float(str(response.content).strip())
        except ValueError:
            return 0.5

    return _score


async def _noop_embed(_text: str) -> list[float]:
    return [0.0] * 1536


def _build_pipeline(
    llm: ContextAwareMockLLM,
    mcp: _FakeMCPClient,
    *,
    episodic_memory: Any | None = None,
) -> Any:
    planner = PlannerAgent(llm=llm)
    researcher = ResearcherAgent(
        mcp_client=cast(Any, mcp),
        scoring_fn=_scoring_via_llm(llm),
    )
    analyst = AnalystAgent(llm=llm)
    critic = CriticAgent(llm=llm)
    writer = WriterAgent(episodic_memory=episodic_memory, embed_fn=_noop_embed)

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


def _initial_state(target: str = _TARGET) -> AgentState:
    return cast(
        AgentState,
        {
            "messages": [HumanMessage(content=target)],
            "target_description": target,
            "session_id": "e2e-test",
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


def _unique_transitions(agent_calls: list[str]) -> list[str]:
    """Collapse consecutive duplicates so we can assert on agent transitions."""
    out: list[str] = []
    for call in agent_calls:
        if not out or out[-1] != call:
            out.append(call)
    return out


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------


async def test_full_pipeline_two_iterations() -> None:
    llm = ContextAwareMockLLM([Recommendation.RE_RESEARCH, Recommendation.APPROVE])
    mcp = _FakeMCPClient()
    pipeline = _build_pipeline(llm, mcp)

    started = time.time()
    final = await pipeline.ainvoke(_initial_state())
    elapsed = time.time() - started

    report = final["threat_report"]
    assert isinstance(report, ThreatReport)
    assert report.iteration_count == 2
    assert report.critic_report.recommendation == Recommendation.APPROVE
    assert len(report.threat_surfaces) >= 1
    assert all(len(s.evidence) > 0 for s in report.threat_surfaces)
    assert report.metadata["total_tokens"] > 0
    assert report.metadata["latency_seconds"] > 0
    assert report.metadata["estimated_cost_usd"] > 0
    assert report.metadata["source_breakdown"]

    # Critic ran twice (filter + eval per iteration).
    assert llm.critic_filter_calls == 2
    assert llm.critic_eval_calls == 2

    # Planner once, then two cycles of researcher_scoring → analyst → critic.
    transitions = _unique_transitions(llm.agent_calls)
    assert transitions == [
        "planner",
        "researcher_scoring",
        "analyst",
        "critic",
        "researcher_scoring",
        "analyst",
        "critic",
    ]

    print(
        f"Pipeline completed: {report.iteration_count} iterations, "
        f"{len(report.threat_surfaces)} surfaces in {elapsed:.2f}s "
        f"(metadata.latency_seconds={report.metadata['latency_seconds']:.2f}s)",
    )


async def test_full_pipeline_single_iteration() -> None:
    llm = ContextAwareMockLLM([Recommendation.APPROVE])
    mcp = _FakeMCPClient()
    pipeline = _build_pipeline(llm, mcp)

    final = await pipeline.ainvoke(_initial_state())

    report = final["threat_report"]
    assert isinstance(report, ThreatReport)
    assert report.iteration_count == 1
    assert report.critic_report.recommendation == Recommendation.APPROVE
    assert llm.critic_eval_calls == 1


async def test_full_pipeline_max_iterations_forced() -> None:
    # Queue 4 RE_RESEARCH — the 4th must never be consumed because the
    # critic guardrail forces APPROVE at iteration_count == max_iterations.
    llm = ContextAwareMockLLM([Recommendation.RE_RESEARCH] * 4)
    mcp = _FakeMCPClient()
    pipeline = _build_pipeline(llm, mcp)

    final = await pipeline.ainvoke(_initial_state())

    report = final["threat_report"]
    assert isinstance(report, ThreatReport)
    assert report.iteration_count == 3
    assert report.critic_report.recommendation == Recommendation.APPROVE  # forced
    assert llm.critic_eval_calls == 3
    assert len(llm._recs) == 1, "4th recommendation must stay unconsumed"


async def test_full_pipeline_episodic_memory_written() -> None:
    llm = ContextAwareMockLLM([Recommendation.APPROVE])
    mcp = _FakeMCPClient()
    episodic_memory = AsyncMock()
    episodic_memory.store = AsyncMock()
    pipeline = _build_pipeline(llm, mcp, episodic_memory=episodic_memory)

    final = await pipeline.ainvoke(_initial_state())
    report = final["threat_report"]
    assert isinstance(report, ThreatReport)

    episodic_memory.store.assert_awaited_once()
    summary, embedding = episodic_memory.store.call_args.args
    assert isinstance(summary, ThreatReportSummary)
    assert summary.surface_count == len(report.threat_surfaces)
    assert summary.focus_areas_covered, "summary must list focus_areas covered"
    # ``focus_areas_covered`` is derived from ``state['plan']`` (Planner output).
    plan_focuses = {t.focus_area for t in final["plan"]}
    assert set(summary.focus_areas_covered) == plan_focuses
    assert len(embedding) == 1536  # text-embedding-3-small dim
