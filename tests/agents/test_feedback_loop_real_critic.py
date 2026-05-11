"""Feedback-loop validation with the real (LLM-driven) CriticAgent.

Mirror of :mod:`tests.agents.test_feedback_loop` but swaps the
:class:`ControllableCriticStub` for the real :class:`CriticAgent`. The
LLM is mocked via :class:`_CriticAwareLLM`, which intercepts the
Critic's two prompts (filter + evaluation) and synthesises a JSON
:class:`CriticReport` that mirrors the queued recommendation. Other
agents (Planner, Analyst) keep their existing :class:`_FakeRoutingLLM`
behaviour.

Together these tests prove the real Critic stays compatible with the
routing logic validated in S5.T1.
"""

from __future__ import annotations

import json
from typing import Any, cast

import pytest
from langgraph.graph import END, StateGraph

from nexus.agents.analyst import AnalystAgent
from nexus.agents.critic import OWASP_LLM_TOP10, CriticAgent
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
from tests.integration.conftest import _FakeMCPClient, _FakeResp, _FakeRoutingLLM

pytestmark = pytest.mark.asyncio


# --------------------------------------------------------------------------
# Critic-aware LLM
# --------------------------------------------------------------------------


def _re_research_task_payload(call_index: int) -> dict[str, Any]:
    # Distinct query per iteration so the Researcher's deduplication
    # (stable id from (server, query, idx)) keeps the new findings.
    return {
        "description": "Investigate model extraction attacks against the OpenAI API.",
        "focus_area": FocusArea.MODEL_EXTRACTION.value,
        "priority": "high",
        "search_queries": [f"model extraction follow-up iter{call_index}"],
    }


def _critic_payload(rec: Recommendation, call_index: int) -> str:
    if rec == Recommendation.RE_RESEARCH:
        body = {
            "overall_score": 0.45,
            "gaps": ["LLM10 not covered"],
            "bias_warnings": [],
            "recommendation": rec.value,
            "re_research_tasks": [_re_research_task_payload(call_index)],
        }
    else:
        body = {
            "overall_score": 0.85,
            "gaps": [],
            "bias_warnings": [],
            "recommendation": rec.value,
            "re_research_tasks": [],
        }
    return json.dumps(body)


class _CriticAwareLLM(_FakeRoutingLLM):
    """Routes Critic prompts through a recommendation queue.

    All non-Critic prompts (Planner / Analyst / Researcher scoring) fall
    through to :class:`_FakeRoutingLLM`.
    """

    def __init__(self, recommendations: list[Recommendation]) -> None:
        super().__init__()
        self._recs: list[Recommendation] = list(recommendations)
        self.critic_eval_calls: int = 0
        self.critic_filter_calls: int = 0

    async def ainvoke(self, prompt: str, **kwargs: Any) -> _FakeResp:
        if "senior AI security auditor" in prompt:
            self.critic_eval_calls += 1
            if not self._recs:
                raise RuntimeError(
                    "_CriticAwareLLM exhausted — enqueue at least max_iterations recommendations",
                )
            rec = self._recs.pop(0)
            return _FakeResp(_critic_payload(rec, self.critic_eval_calls))
        if "OWASP LLM Top 10 catalogue" in prompt:
            self.critic_filter_calls += 1
            # Force all categories applicable so the threshold maths is predictable.
            return _FakeResp(json.dumps(list(OWASP_LLM_TOP10)))
        return await super().ainvoke(prompt, **kwargs)


# --------------------------------------------------------------------------
# Spy researcher (copied from test_feedback_loop for parity)
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
    llm: _CriticAwareLLM,
    mcp: _FakeMCPClient,
    *,
    researcher: ResearcherAgent | None = None,
) -> Any:
    planner = PlannerAgent(llm=llm)
    researcher = researcher or ResearcherAgent(
        mcp_client=cast(Any, mcp),
        scoring_fn=_fake_score,
    )
    analyst = AnalystAgent(llm=llm)
    critic = CriticAgent(llm=llm)
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
            "session_id": "test-feedback-real-critic",
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
    llm = _CriticAwareLLM([Recommendation.APPROVE])
    mcp = _FakeMCPClient()
    pipeline = _build_pipeline(llm, mcp)

    final = await pipeline.ainvoke(_initial_state())

    assert final["iteration_count"] == 1
    report = final["threat_report"]
    assert isinstance(report, ThreatReport)
    assert report.iteration_count == 1
    assert llm.critic_eval_calls == 1
    assert report.critic_report.recommendation == Recommendation.APPROVE


async def test_two_iterations_then_approve() -> None:
    llm = _CriticAwareLLM([Recommendation.RE_RESEARCH, Recommendation.APPROVE])
    mcp = _FakeMCPClient()
    researcher = _SpyResearcher(mcp_client=cast(Any, mcp), scoring_fn=_fake_score)
    pipeline = _build_pipeline(llm, mcp, researcher=researcher)

    final = await pipeline.ainvoke(_initial_state())

    report = final["threat_report"]
    assert isinstance(report, ThreatReport)
    assert report.iteration_count == 2
    assert final["iteration_count"] == 2
    assert llm.critic_eval_calls == 2
    assert report.critic_report.recommendation == Recommendation.APPROVE

    plan_ids = {t.id for t in final["plan"]}
    findings = final["findings"]
    iter1_finding_ids = {f.id for f in findings if f.task_id in plan_ids}
    iter2_finding_ids = {f.id for f in findings if f.task_id not in plan_ids}
    assert iter1_finding_ids
    assert iter2_finding_ids
    assert len(findings) > researcher.findings_before_iteration[1]

    surface_evidence_ids = {e.id for s in final["threat_surfaces"] for e in s.evidence}
    assert surface_evidence_ids & iter1_finding_ids
    assert surface_evidence_ids & iter2_finding_ids


async def test_max_iterations_forced_termination() -> None:
    llm = _CriticAwareLLM([Recommendation.RE_RESEARCH] * 4)
    mcp = _FakeMCPClient()
    pipeline = _build_pipeline(llm, mcp)

    final = await pipeline.ainvoke(_initial_state())

    report = final["threat_report"]
    assert isinstance(report, ThreatReport)
    assert final["iteration_count"] == 3
    assert report.iteration_count == 3
    assert llm.critic_eval_calls == 3, "loop must terminate after max_iterations"
    assert len(llm._recs) == 1, "4th recommendation must remain unconsumed"
    # Guardrail forces APPROVE at iteration_count == max_iterations even though
    # the queued recommendation was RE_RESEARCH.
    assert report.critic_report.recommendation == Recommendation.APPROVE


async def test_re_research_uses_critic_tasks_not_original_plan() -> None:
    llm = _CriticAwareLLM([Recommendation.RE_RESEARCH, Recommendation.APPROVE])
    mcp = _FakeMCPClient()
    researcher = _SpyResearcher(mcp_client=cast(Any, mcp), scoring_fn=_fake_score)
    pipeline = _build_pipeline(llm, mcp, researcher=researcher)

    final = await pipeline.ainvoke(_initial_state())

    assert len(researcher.task_lists_seen) == 2
    iter1_tasks, iter2_tasks = researcher.task_lists_seen

    plan_ids = {t.id for t in final["plan"]}
    iter1_ids = {t.id for t in iter1_tasks}
    iter2_ids = {t.id for t in iter2_tasks}

    assert iter1_ids == plan_ids
    assert iter2_ids.isdisjoint(plan_ids)
    assert iter1_ids != iter2_ids
    assert len(iter2_tasks) == 1
    assert iter2_tasks[0].focus_area == FocusArea.MODEL_EXTRACTION


async def test_findings_are_cumulative_across_iterations() -> None:
    llm = _CriticAwareLLM([Recommendation.RE_RESEARCH, Recommendation.APPROVE])
    mcp = _FakeMCPClient()
    researcher = _SpyResearcher(mcp_client=cast(Any, mcp), scoring_fn=_fake_score)
    pipeline = _build_pipeline(llm, mcp, researcher=researcher)

    final = await pipeline.ainvoke(_initial_state())

    findings = final["findings"]
    assert researcher.findings_before_iteration[0] == 0
    n_after_iter1 = researcher.findings_before_iteration[1]
    n_final = len(findings)
    assert n_after_iter1 > 0
    assert n_final > n_after_iter1

    ids = [f.id for f in findings]
    assert len(set(ids)) == len(ids)
