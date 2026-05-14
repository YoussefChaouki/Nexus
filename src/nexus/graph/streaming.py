"""Streaming wrapper around the NEXUS LangGraph pipeline.

:func:`stream_pipeline_events` runs ``build_graph()`` in streaming mode
and yields one :class:`AgentEvent` per node transition. The FastAPI SSE
endpoint (``GET /analyze/stream``) consumes this generator; the events
are also useful for log replay and frontend progress UIs.

The generator never raises through to the caller: failures are surfaced
as a terminal ``event_type="error"`` event so the SSE connection stays
well-formed and the frontend can render the failure inline.
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from typing import Any
from uuid import uuid4

import structlog
from langchain_core.messages import HumanMessage

from nexus.graph.graph import build_graph
from nexus.schemas.models import AgentEvent, AgentState

logger = structlog.get_logger(__name__)


def _seed_state(target_description: str, session_id: str) -> AgentState:
    """Return the initial AgentState for a fresh pipeline run.

    Kept in lock-step with :func:`nexus.graph.graph.run_pipeline` so
    streaming and non-streaming entry points yield the same trace
    shape in Langfuse and the same end-state shape in Redis.
    """
    state: AgentState = {
        "messages": [HumanMessage(content=target_description)],
        "target_description": target_description,
        "session_id": session_id,
        "plan": [],
        "findings": [],
        "threat_surfaces": [],
        "critic_report": None,
        "threat_report": None,
        "iteration_count": 0,
        "should_continue": True,
        "session_start_time": time.time(),
    }
    return state


async def stream_pipeline_events(
    target_description: str,
    session_id: str | None = None,
    checkpointer: Any = None,  # noqa: ANN401
) -> AsyncIterator[AgentEvent]:
    """Yield AgentEvent objects as the pipeline progresses.

    The first event is always ``event_type="started"``. Each subsequent
    event corresponds to a LangGraph node returning; the final event
    is ``event_type="completed"`` (or ``"error"`` on failure).

    Args:
        target_description: AI system architecture description.
        session_id: Optional session ID; one is generated when missing.
        checkpointer: Optional LangGraph checkpointer for working memory.

    Yields:
        :class:`AgentEvent` per node transition + start/completed/error.
    """
    resolved_id = session_id or str(uuid4())
    initial_state = _seed_state(target_description, resolved_id)

    yield AgentEvent(
        session_id=resolved_id,
        agent="pipeline",
        event_type="started",
        payload={"target_description": target_description[:200]},
    )

    compiled = build_graph(checkpointer)
    config = {"configurable": {"thread_id": resolved_id}}

    try:
        async for chunk in compiled.astream(initial_state, config):
            for node_name, node_state in chunk.items():
                yield AgentEvent(
                    session_id=resolved_id,
                    agent=str(node_name),
                    event_type="node_completed",
                    payload=_summarise_node_state(node_state),
                )
    except Exception as exc:  # noqa: BLE001 — funnel all errors into a terminal event
        logger.warning(
            "pipeline_stream_failed",
            session_id=resolved_id,
            error=str(exc),
            error_type=type(exc).__name__,
        )
        yield AgentEvent(
            session_id=resolved_id,
            agent="pipeline",
            event_type="error",
            payload={"error": str(exc), "error_type": type(exc).__name__},
        )
        return

    yield AgentEvent(
        session_id=resolved_id,
        agent="pipeline",
        event_type="completed",
        payload={},
    )


def _summarise_node_state(node_state: Any) -> dict[str, Any]:  # noqa: ANN401
    """Reduce a LangGraph node state delta to a compact, SSE-friendly dict.

    LangGraph yields the full ``AgentState`` after each node; sending it
    over SSE would echo every finding/surface back to the client. We
    keep only counters and the critic recommendation, which is what
    progress UIs actually consume.
    """
    if not isinstance(node_state, dict):
        return {}
    summary: dict[str, Any] = {}
    for key in (
        "plan",
        "findings",
        "threat_surfaces",
        "iteration_count",
    ):
        value = node_state.get(key)
        if isinstance(value, list):
            summary[f"{key}_count"] = len(value)
        elif isinstance(value, int):
            summary[key] = value
    critic = node_state.get("critic_report")
    if critic is not None and hasattr(critic, "recommendation"):
        summary["critic_recommendation"] = critic.recommendation.value
        summary["critic_score"] = round(float(critic.overall_score), 4)
    report = node_state.get("threat_report")
    if report is not None and hasattr(report, "id"):
        summary["report_id"] = report.id
    return summary
