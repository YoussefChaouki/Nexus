"""Edge routing functions for the NEXUS LangGraph pipeline."""

from typing import Literal

import structlog

from nexus.schemas.models import AgentState, Recommendation

logger = structlog.get_logger(__name__)

# Mirrors Settings.max_iterations and ThreatReport.iteration_count Field(le=3).
_MAX_ITERATIONS = 3


def route_after_critic(state: AgentState) -> Literal["researcher", "writer"]:
    """Route to researcher for re-research or to writer for final report.

    Args:
        state: Current pipeline state.

    Returns:
        Name of the next graph node.
    """
    critic_report = state["critic_report"]
    iteration_count = state["iteration_count"]

    if (
        critic_report is not None
        and critic_report.recommendation == Recommendation.RE_RESEARCH
        and iteration_count < _MAX_ITERATIONS
    ):
        logger.info("routing", decision="re_research", iteration=iteration_count)
        return "researcher"

    logger.info("routing", decision="writer", iteration=iteration_count)
    return "writer"
