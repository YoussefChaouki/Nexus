"""Writer agent — assembles the final ThreatReport from approved surfaces."""

from datetime import UTC, datetime
from typing import cast

from nexus.agents.base import AgentBase
from nexus.exceptions import AgentError
from nexus.schemas.models import AgentState, ThreatReport


class WriterAgent(AgentBase):
    """Formats approved threat surfaces into a structured ThreatReport."""

    agent_name = "writer"

    async def run(self, state: AgentState) -> AgentState:
        """Produce the final ThreatReport.

        Args:
            state: Current pipeline state; must contain an approved critic_report.

        Returns:
            State with `threat_report` set.

        Raises:
            AgentError: If critic_report is missing.
        """
        self._log_start(state)
        critic_report = state["critic_report"]
        if critic_report is None:
            raise AgentError("WriterAgent requires a CriticReport in state")
        # TODO(S2.T5): Full report assembly with citations and executive summary
        report = ThreatReport(
            target_description=state["target_description"],
            created_at=datetime.now(UTC),
            threat_surfaces=state["threat_surfaces"],
            critic_report=critic_report,
            iteration_count=max(1, state["iteration_count"]),
        )
        return cast(AgentState, {**state, "threat_report": report})
