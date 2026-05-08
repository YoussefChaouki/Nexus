"""Shared fixtures and helpers for the agent test suite.

Currently exposes :class:`ControllableCriticStub` — a deterministic stand-in
for :class:`nexus.agents.critic.CriticAgent` whose recommendations are
driven by a queue. The stub lets the feedback-loop tests exercise the
real ``route_after_critic`` logic without depending on the real LLM
Critic (still planned for S5.T2).
"""

from __future__ import annotations

from typing import cast

from nexus.schemas.models import (
    AgentState,
    CriticReport,
    FocusArea,
    Priority,
    Recommendation,
    ResearchTask,
)


class ControllableCriticStub:
    """Critic stand-in that returns a queued sequence of recommendations.

    Each call to :meth:`run` pops the next :class:`Recommendation` from
    ``recommendations``. ``RE_RESEARCH`` calls produce a fresh
    :class:`ResearchTask` targeting :class:`FocusArea.MODEL_EXTRACTION`
    (uncovered by the default mock plan). ``APPROVE`` calls produce a
    score=0.85 report with empty ``re_research_tasks``.

    Args:
        recommendations: Ordered list of recommendations the stub will
            emit, one per ``run`` call.

    Raises:
        RuntimeError: When called more times than ``len(recommendations)``.
            Always indicates a test setup error, never a pipeline bug.
    """

    agent_name = "critic"

    def __init__(self, recommendations: list[Recommendation]) -> None:
        self.recommendations: list[Recommendation] = list(recommendations)
        self.calls: int = 0
        self.reports_emitted: list[CriticReport] = []

    async def run(self, state: AgentState) -> AgentState:
        if not self.recommendations:
            raise RuntimeError(
                f"ControllableCriticStub exhausted after {self.calls} calls "
                "— test setup must enqueue at least max_iterations recommendations"
            )

        rec = self.recommendations.pop(0)
        self.calls += 1
        if rec == Recommendation.RE_RESEARCH:
            report = CriticReport(
                overall_score=0.45,
                gaps=["Model extraction not assessed"],
                recommendation=rec,
                re_research_tasks=[
                    ResearchTask(
                        description=(
                            "Investigate model extraction attacks against the OpenAI API."
                        ),
                        focus_area=FocusArea.MODEL_EXTRACTION,
                        priority=Priority.HIGH,
                        search_queries=[f"model extraction attack iter{self.calls}"],
                    ),
                ],
            )
        else:
            report = CriticReport(
                overall_score=0.85,
                gaps=["Model extraction not assessed"],
                recommendation=rec,
            )
        self.reports_emitted.append(report)
        return cast(AgentState, {**state, "critic_report": report})
