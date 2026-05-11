"""LangGraph pipeline construction and execution entry point."""

import time
from typing import Any, cast
from uuid import uuid4

import structlog

from nexus.agents.analyst import AnalystAgent
from nexus.agents.critic import CriticAgent
from nexus.agents.planner import PlannerAgent
from nexus.agents.researcher import ResearcherAgent
from nexus.agents.writer import WriterAgent
from nexus.exceptions import AgentError
from nexus.graph.edges import route_after_critic
from nexus.graph.state import AgentState
from nexus.schemas.models import ThreatReport

logger = structlog.get_logger(__name__)


def build_graph(checkpointer: Any = None) -> Any:  # noqa: ANN401
    """Compile and return the NEXUS StateGraph.

    Args:
        checkpointer: Optional LangGraph checkpointer (e.g. AsyncRedisSaver).
            Justified Any: CompiledStateGraph has no stable public import across
            LangGraph minor versions.

    Returns:
        Compiled StateGraph ready for ainvoke.
    """
    from langgraph.graph import END, StateGraph

    planner = PlannerAgent()
    researcher = ResearcherAgent()
    analyst = AnalystAgent()
    critic = CriticAgent()
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

    return graph.compile(checkpointer=checkpointer)


async def run_pipeline(
    target_description: str,
    session_id: str | None = None,
    checkpointer: Any = None,  # noqa: ANN401
) -> ThreatReport:
    """Execute the full NEXUS pipeline and return a ThreatReport.

    Args:
        target_description: AI system architecture description to analyse.
        session_id: Optional session ID; a UUID is generated when omitted.
        checkpointer: Optional LangGraph checkpointer for working memory.

    Returns:
        Completed ThreatReport.

    Raises:
        AgentError: If the pipeline completes without generating a report.
    """
    resolved_id = session_id or str(uuid4())
    compiled = build_graph(checkpointer)

    initial_state: AgentState = {
        "messages": [],
        "target_description": target_description,
        "session_id": resolved_id,
        "plan": [],
        "findings": [],
        "threat_surfaces": [],
        "critic_report": None,
        "threat_report": None,
        "iteration_count": 0,
        "should_continue": True,
        "session_start_time": time.time(),
    }
    config = {"configurable": {"thread_id": resolved_id}}

    logger.info("pipeline_start", session_id=resolved_id, target=target_description[:80])
    result: AgentState = cast(AgentState, await compiled.ainvoke(initial_state, config))

    report = result["threat_report"]
    if report is None:
        raise AgentError(f"Pipeline completed without a ThreatReport for session {resolved_id}")
    return report
