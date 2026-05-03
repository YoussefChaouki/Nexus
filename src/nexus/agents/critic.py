"""Critic agent — evaluates threat surfaces and recommends approve or re-research."""

from typing import cast

from nexus.agents.base import AgentBase
from nexus.schemas.models import AgentState, CriticReport, Recommendation


class CriticAgent(AgentBase):
    """Scores completeness, identifies gaps, and gates the final report."""

    agent_name = "critic"

    async def run(self, state: AgentState) -> AgentState:
        """Evaluate the current threat surfaces and produce a CriticReport.

        Args:
            state: Current pipeline state.

        Returns:
            State with `critic_report` set.
        """
        self._log_start(state)
        # TODO(S2.T4): LLM-based quality evaluation with gap detection
        placeholder_report = CriticReport(
            overall_score=1.0,
            gaps=[],
            recommendation=Recommendation.APPROVE,
        )
        return cast(AgentState, {**state, "critic_report": placeholder_report})
