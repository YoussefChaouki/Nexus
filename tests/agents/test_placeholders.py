"""Smoke tests for the agent nodes that still ship the Sprint 1 placeholder.

Critic gains a dedicated test suite in a later sprint; until then this
test verifies its placeholder run() method stays wired into the
LangGraph skeleton.
"""

from typing import cast

import pytest

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


async def test_critic_produces_critic_report(state: AgentState) -> None:
    out = await CriticAgent().run(state)
    report = out["critic_report"]
    assert isinstance(report, CriticReport)
    assert report.recommendation == Recommendation.APPROVE
