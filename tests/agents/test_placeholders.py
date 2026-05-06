"""Smoke tests for the agent nodes that still ship the Sprint 1 placeholder.

Analyst and Critic gain dedicated test suites in later sprints; until
then these tests verify their placeholder run() methods stay wired into
the LangGraph skeleton.
"""

from typing import cast

import pytest

from nexus.agents.analyst import AnalystAgent
from nexus.agents.critic import CriticAgent
from nexus.schemas.models import (
    AgentState,
    CriticReport,
    Recommendation,
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


async def test_analyst_returns_state_with_surfaces_key(state: AgentState) -> None:
    out = await AnalystAgent().run(state)
    assert "threat_surfaces" in out


async def test_critic_produces_critic_report(state: AgentState) -> None:
    out = await CriticAgent().run(state)
    report = out["critic_report"]
    assert isinstance(report, CriticReport)
    assert report.recommendation == Recommendation.APPROVE
