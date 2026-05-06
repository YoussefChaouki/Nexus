"""Smoke tests for the placeholder agent nodes.

These exercise the run() methods of every agent so that the LangGraph
skeleton (Sprint 1) is verified end-to-end before real implementations
land in later sprints.
"""

from typing import cast

import pytest

from nexus.agents.analyst import AnalystAgent
from nexus.agents.critic import CriticAgent
from nexus.agents.planner import PlannerAgent
from nexus.agents.writer import WriterAgent
from nexus.exceptions import AgentError
from nexus.schemas.models import (
    AgentState,
    CriticReport,
    FindingResult,
    Recommendation,
    Severity,
    SourceType,
    ThreatSurface,
)


@pytest.fixture()
def state() -> AgentState:
    return cast(
        AgentState,
        {
            "messages": [],
            "target_description": "FastAPI + pgvector RAG",
            "session_id": "test-placeholders",
            "plan": [],
            "findings": [],
            "threat_surfaces": [],
            "critic_report": None,
            "threat_report": None,
            "iteration_count": 0,
            "should_continue": True,
        },
    )


async def test_planner_returns_state_with_plan_key(state: AgentState) -> None:
    out = await PlannerAgent().run(state)
    assert "plan" in out


async def test_analyst_returns_state_with_surfaces_key(state: AgentState) -> None:
    out = await AnalystAgent().run(state)
    assert "threat_surfaces" in out


async def test_critic_produces_critic_report(state: AgentState) -> None:
    out = await CriticAgent().run(state)
    report = out["critic_report"]
    assert isinstance(report, CriticReport)
    assert report.recommendation == Recommendation.APPROVE


async def test_writer_requires_critic_report(state: AgentState) -> None:
    with pytest.raises(AgentError):
        await WriterAgent().run(state)


async def test_writer_assembles_threat_report(state: AgentState) -> None:
    critic = CriticReport(
        overall_score=0.9,
        gaps=[],
        recommendation=Recommendation.APPROVE,
    )
    finding = FindingResult(
        task_id="task-1",
        source_type=SourceType.ARXIV,
        title="Prompt injection survey",
        summary="A survey of prompt injection techniques against LLM applications.",
        relevance_score=0.8,
    )
    surface = ThreatSurface(
        name="Prompt Injection",
        description="Attackers manipulate model behavior via crafted prompts.",
        severity=Severity.HIGH,
        attack_vectors=["direct injection"],
        evidence=[finding],
        mitigations=["input validation"],
    )
    populated = cast(
        AgentState,
        {**state, "critic_report": critic, "threat_surfaces": [surface], "iteration_count": 1},
    )
    out = await WriterAgent().run(populated)
    report = out["threat_report"]
    assert report is not None
    assert report.iteration_count == 1
