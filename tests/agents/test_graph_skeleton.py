"""Tests for the LangGraph routing logic and graph construction."""

from typing import cast

import pytest

from nexus.graph.edges import route_after_critic
from nexus.graph.graph import build_graph
from nexus.graph.state import AgentState
from nexus.schemas.models import (
    CriticReport,
    FocusArea,
    Priority,
    Recommendation,
    ResearchTask,
)
from nexus.settings import get_settings

_MAX_ITERATIONS = get_settings().max_iterations


@pytest.fixture()
def base_state() -> AgentState:
    return cast(
        AgentState,
        {
            "messages": [],
            "target_description": "FastAPI + pgvector RAG, OpenAI API, no auth",
            "session_id": "test-session-001",
            "plan": [],
            "findings": [],
            "threat_surfaces": [],
            "critic_report": None,
            "threat_report": None,
            "iteration_count": 1,
            "should_continue": True,
        },
    )


@pytest.fixture()
def approve_report() -> CriticReport:
    return CriticReport(
        overall_score=0.9,
        gaps=[],
        recommendation=Recommendation.APPROVE,
    )


@pytest.fixture()
def re_research_report() -> CriticReport:
    return CriticReport(
        overall_score=0.45,
        gaps=["insufficient denial-of-service coverage"],
        recommendation=Recommendation.RE_RESEARCH,
        re_research_tasks=[
            ResearchTask(
                description="Investigate denial-of-service vectors for LLM endpoints",
                focus_area=FocusArea.DENIAL_OF_SERVICE,
                priority=Priority.HIGH,
            )
        ],
    )


def test_route_approve(base_state: AgentState, approve_report: CriticReport) -> None:
    state = cast(AgentState, {**base_state, "critic_report": approve_report})
    assert route_after_critic(state) == "writer"


def test_route_re_research(base_state: AgentState, re_research_report: CriticReport) -> None:
    state = cast(
        AgentState, {**base_state, "critic_report": re_research_report, "iteration_count": 1}
    )
    assert route_after_critic(state) == "researcher"


def test_route_re_research_at_max_iterations(
    base_state: AgentState, re_research_report: CriticReport
) -> None:
    state = cast(
        AgentState,
        {**base_state, "critic_report": re_research_report, "iteration_count": _MAX_ITERATIONS},
    )
    assert route_after_critic(state) == "writer"


def test_route_no_critic_report(base_state: AgentState) -> None:
    assert route_after_critic(base_state) == "writer"


def test_route_re_research_below_max(
    base_state: AgentState, re_research_report: CriticReport
) -> None:
    state = cast(
        AgentState,
        {**base_state, "critic_report": re_research_report, "iteration_count": _MAX_ITERATIONS - 1},
    )
    assert route_after_critic(state) == "researcher"


def test_route_respects_settings_max_iterations(
    base_state: AgentState,
    re_research_report: CriticReport,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Routing must read Settings, not a hardcoded constant."""
    monkeypatch.setattr(get_settings(), "max_iterations", 2)
    state = cast(
        AgentState,
        {**base_state, "critic_report": re_research_report, "iteration_count": 2},
    )
    assert route_after_critic(state) == "writer"


def test_build_graph_returns_compiled_graph() -> None:
    compiled = build_graph()
    assert compiled is not None


def test_build_graph_with_none_checkpointer() -> None:
    compiled = build_graph(checkpointer=None)
    assert compiled is not None
