"""Researcher agent — queries MCP servers to gather FindingResult objects."""

from typing import cast

from nexus.agents.base import AgentBase
from nexus.schemas.models import AgentState


class ResearcherAgent(AgentBase):
    """Executes MCP tool calls for each ResearchTask in the plan."""

    agent_name = "researcher"

    async def run(self, state: AgentState) -> AgentState:
        """Gather findings for all tasks in the current plan.

        Args:
            state: Current pipeline state.

        Returns:
            State with `findings` appended and `iteration_count` incremented.
        """
        self._log_start(state)
        # TODO(S2.T2): MCP-backed research via arxiv / nvd / atlas servers
        return cast(
            AgentState,
            {**state, "findings": [], "iteration_count": state["iteration_count"] + 1},
        )
