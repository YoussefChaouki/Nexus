"""Edge routing functions for the NEXUS LangGraph pipeline."""

from typing import Literal

import structlog

from nexus.schemas.models import AgentState, Recommendation
from nexus.settings import get_settings

logger = structlog.get_logger(__name__)


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
        and iteration_count < get_settings().max_iterations
    ):
        logger.info("routing", decision="re_research", iteration=iteration_count)
        return "researcher"

    logger.info("routing", decision="writer", iteration=iteration_count)
    return "writer"
