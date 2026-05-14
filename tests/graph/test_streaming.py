"""Tests for ``nexus.graph.streaming.stream_pipeline_events``."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from nexus.graph.streaming import _summarise_node_state, stream_pipeline_events
from nexus.schemas.models import AgentEvent


async def _drain(stream: Any) -> list[AgentEvent]:
    return [event async for event in stream]


def _stub_compiled(chunks: list[dict[str, Any]]) -> Any:
    """LangGraph .astream yields one chunk per node transition."""

    class _Stub:
        def __init__(self, items: list[dict[str, Any]]) -> None:
            self._items = items

        def astream(self, *_args: Any, **_kwargs: Any) -> Any:
            async def gen() -> Any:
                for item in self._items:
                    yield item

            return gen()

    return _Stub(chunks)


async def test_stream_emits_started_node_completed_events() -> None:
    chunks = [
        {"planner": {"plan": [object(), object()], "iteration_count": 0}},
        {"researcher": {"findings": [object()] * 7, "iteration_count": 1}},
    ]

    with patch(
        "nexus.graph.streaming.build_graph",
        return_value=_stub_compiled(chunks),
    ):
        events = await _drain(
            stream_pipeline_events(
                "A long-enough target description for the streaming pipeline.",
                session_id="sess-stream-1",
            )
        )

    types = [event.event_type for event in events]
    assert types == ["started", "node_completed", "node_completed", "completed"]
    assert events[1].agent == "planner"
    assert events[1].payload["plan_count"] == 2
    assert events[2].agent == "researcher"
    assert events[2].payload["findings_count"] == 7
    assert events[2].payload["iteration_count"] == 1


async def test_stream_funnels_errors_into_terminal_event() -> None:
    class _BrokenStub:
        def astream(self, *_args: Any, **_kwargs: Any) -> Any:
            async def gen() -> Any:
                yield {"planner": {"plan": []}}
                raise RuntimeError("kapow")

            return gen()

    with patch("nexus.graph.streaming.build_graph", return_value=_BrokenStub()):
        events = await _drain(
            stream_pipeline_events(
                "A long-enough target description for the streaming pipeline.",
                session_id="sess-stream-err",
            )
        )

    # started + node_completed + error — no terminal "completed".
    assert [event.event_type for event in events] == [
        "started",
        "node_completed",
        "error",
    ]
    err_payload = events[-1].payload
    assert err_payload["error"] == "kapow"
    assert err_payload["error_type"] == "RuntimeError"


def test_summarise_node_state_extracts_critic_recommendation() -> None:
    critic = MagicMock(recommendation=MagicMock(value="approve"), overall_score=0.91)
    summary = _summarise_node_state(
        {
            "plan": [object(), object()],
            "findings": [object()] * 3,
            "threat_surfaces": [],
            "iteration_count": 2,
            "critic_report": critic,
        },
    )
    assert summary == {
        "plan_count": 2,
        "findings_count": 3,
        "threat_surfaces_count": 0,
        "iteration_count": 2,
        "critic_recommendation": "approve",
        "critic_score": 0.91,
    }


def test_summarise_node_state_handles_non_dict_input() -> None:
    assert _summarise_node_state("not a dict") == {}
