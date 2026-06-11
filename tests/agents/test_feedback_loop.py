"""Feedback loop integration tests with a controllable Critic stub.

These tests exercise the real LangGraph routing logic
(:func:`route_after_critic`) and the real agents (Planner, Researcher,
Analyst, Writer) while replacing the placeholder Critic with
:class:`ControllableCriticStub` so we can drive the loop into every
branch (single approve, multi-iteration, forced termination).

Goal: validate the feedback-loop mechanics (cumulative findings,
re-research task selection, max-iteration cap) BEFORE introducing the
real LLM-based Critic in S5.T2.
"""

from __future__ import annotations

from typing import Any, cast

import pytest
from langgraph.graph import END, StateGraph

from nexus.agents.analyst import AnalystAgent
from nexus.agents.planner import PlannerAgent
from nexus.agents.researcher import ResearcherAgent
from nexus.agents.writer import WriterAgent
from nexus.graph.edges import route_after_critic
from nexus.schemas.models import (
    AgentState,
    FindingResult,
    FocusArea,
    Recommendation,
    ResearchTask,
    ThreatReport,
)
from tests.agents.conftest import ControllableCriticStub
from tests.integration.conftest import _FakeMCPClient, _FakeRoutingLLM

pytestmark = pytest.mark.asyncio


# --------------------------------------------------------------------------
# Spies
# --------------------------------------------------------------------------


class _SpyResearcher(ResearcherAgent):
    """Researcher that records (a) the task list per iteration, and
    (b) the size of ``state['findings']`` on entry to each iteration."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.task_lists_seen: list[list[ResearchTask]] = []
        self.findings_before_iteration: list[int] = []

    async def run(self, state: AgentState) -> AgentState:
        self.findings_before_iteration.append(len(state["findings"]))
        return await super().run(state)

    def _tasks_to_research(self, state: AgentState) -> list[ResearchTask]:
        tasks = super()._tasks_to_research(state)
        self.task_lists_seen.append(list(tasks))
        return tasks


# --------------------------------------------------------------------------
# Pipeline builder
# --------------------------------------------------------------------------


async def _fake_score(_task: ResearchTask, _finding: FindingResult) -> float:
    return 0.7


def _build_pipeline(
    llm: _FakeRoutingLLM,
    mcp: _FakeMCPClient,
    critic: ControllableCriticStub,
    *,
    researcher: ResearcherAgent | None = None,
) -> Any:
    planner = PlannerAgent(llm=llm)
    researcher = researcher or ResearcherAgent(
        mcp_client=cast(Any, mcp),
        scoring_fn=_fake_score,
    )
    analyst = AnalystAgent(llm=llm)
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


def _initial_state(target: str = "FastAPI + pgvector RAG, no auth") -> AgentState:
    return cast(
        AgentState,
        {
            "messages": [],
            "target_description": target,
            "session_id": "test-feedback",
            "plan": [],
            "findings": [],
            "threat_surfaces": [],
            "critic_report": None,
            "threat_report": None,
            "iteration_count": 0,
            "should_continue": True,
        },
    )


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------


async def test_single_iteration_approve() -> None:
    llm = _FakeRoutingLLM()
    mcp = _FakeMCPClient()
    critic = ControllableCriticStub([Recommendation.APPROVE])
    pipeline = _build_pipeline(llm, mcp, critic)

    final = await pipeline.ainvoke(_initial_state())

    assert final["iteration_count"] == 1
    report = final["threat_report"]
    assert isinstance(report, ThreatReport)
    assert report.iteration_count == 1
    # Only one Critic call → routing went straight to writer (never RE_RESEARCH).
    assert critic.calls == 1
    assert report.critic_report.recommendation == Recommendation.APPROVE


async def test_two_iterations_then_approve() -> None:
    llm = _FakeRoutingLLM()
    mcp = _FakeMCPClient()
    critic = ControllableCriticStub([Recommendation.RE_RESEARCH, Recommendation.APPROVE])
    researcher = _SpyResearcher(mcp_client=cast(Any, mcp), scoring_fn=_fake_score)
    pipeline = _build_pipeline(llm, mcp, critic, researcher=researcher)

    final = await pipeline.ainvoke(_initial_state())

    report = final["threat_report"]
    assert isinstance(report, ThreatReport)
    assert report.iteration_count == 2
    assert final["iteration_count"] == 2
    assert critic.calls == 2
    assert report.critic_report.recommendation == Recommendation.APPROVE

    # Findings cumulative: iter-1 task_ids come from the original plan,
    # iter-2 task_ids from the re_research_tasks. The spy captured both
    # task lists — final["plan"] can't tell them apart any more because
    # the Researcher merges executed re-research tasks into the plan.
    original_plan_ids = {t.id for t in researcher.task_lists_seen[0]}
    re_research_ids = {t.id for t in researcher.task_lists_seen[1]}
    findings = final["findings"]
    iter1_finding_ids = {f.id for f in findings if f.task_id in original_plan_ids}
    iter2_finding_ids = {f.id for f in findings if f.task_id in re_research_ids}
    assert iter1_finding_ids, "expected findings tied to the original plan"
    assert iter2_finding_ids, "expected findings tied to re_research tasks"
    assert len(findings) > researcher.findings_before_iteration[1]

    # The merge itself: the final plan covers BOTH task lists, so the
    # Analyst can credit re-research findings to their focus areas.
    assert {t.id for t in final["plan"]} == original_plan_ids | re_research_ids

    # Surfaces produced in iteration 2 collectively reference findings from
    # both iterations (analyst sees the cumulative findings list).
    surface_evidence_ids = {e.id for s in final["threat_surfaces"] for e in s.evidence}
    assert surface_evidence_ids & iter1_finding_ids, "surfaces missing iter-1 evidence"
    assert surface_evidence_ids & iter2_finding_ids, "surfaces missing iter-2 evidence"


async def test_max_iterations_forced_termination() -> None:
    llm = _FakeRoutingLLM()
    mcp = _FakeMCPClient()
    # Queue 4 RE_RESEARCH; the 4th must never be consumed.
    critic = ControllableCriticStub([Recommendation.RE_RESEARCH] * 4)
    pipeline = _build_pipeline(llm, mcp, critic)

    final = await pipeline.ainvoke(_initial_state())

    report = final["threat_report"]
    assert isinstance(report, ThreatReport)
    assert final["iteration_count"] == 3
    assert report.iteration_count == 3
    assert critic.calls == 3, "loop must terminate after max_iterations even on RE_RESEARCH"
    assert len(critic.recommendations) == 1, "4th recommendation must remain unconsumed"


async def test_re_research_uses_critic_tasks_not_original_plan() -> None:
    llm = _FakeRoutingLLM()
    mcp = _FakeMCPClient()
    critic = ControllableCriticStub([Recommendation.RE_RESEARCH, Recommendation.APPROVE])
    researcher = _SpyResearcher(mcp_client=cast(Any, mcp), scoring_fn=_fake_score)
    pipeline = _build_pipeline(llm, mcp, critic, researcher=researcher)

    final = await pipeline.ainvoke(_initial_state())

    assert len(researcher.task_lists_seen) == 2, "researcher must run exactly twice"
    iter1_tasks, iter2_tasks = researcher.task_lists_seen

    iter1_ids = {t.id for t in iter1_tasks}
    iter2_ids = {t.id for t in iter2_tasks}

    # Iteration 2 used the Critic's re_research_tasks — disjoint from the
    # original plan (captured by the spy at iteration 1).
    assert iter2_ids.isdisjoint(iter1_ids)
    # And the stub's re_research_task targets MODEL_EXTRACTION as documented.
    assert len(iter2_tasks) == 1
    assert iter2_tasks[0].focus_area == FocusArea.MODEL_EXTRACTION
    # After the run, the plan contains both lists (re-research merge).
    assert {t.id for t in final["plan"]} == iter1_ids | iter2_ids


async def test_findings_are_cumulative_across_iterations() -> None:
    llm = _FakeRoutingLLM()
    mcp = _FakeMCPClient()
    critic = ControllableCriticStub([Recommendation.RE_RESEARCH, Recommendation.APPROVE])
    researcher = _SpyResearcher(mcp_client=cast(Any, mcp), scoring_fn=_fake_score)
    pipeline = _build_pipeline(llm, mcp, critic, researcher=researcher)

    final = await pipeline.ainvoke(_initial_state())

    findings = final["findings"]
    # findings_before_iteration[0] = 0 (entering iter 1)
    # findings_before_iteration[1] = N1 (entering iter 2 — equals findings after iter 1)
    assert researcher.findings_before_iteration[0] == 0
    n_after_iter1 = researcher.findings_before_iteration[1]
    n_final = len(findings)
    assert n_after_iter1 > 0, "iter 1 must produce findings"
    assert n_final > n_after_iter1, "iter 2 must append, not replace, findings"

    # No duplicates by id.
    ids = [f.id for f in findings]
    assert len(set(ids)) == len(ids)
