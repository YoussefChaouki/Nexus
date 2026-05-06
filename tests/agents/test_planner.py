"""Tests for the Planner agent.

The LLM is replaced with a hand-rolled fake that returns a configurable
canned response. EpisodicMemory is mocked via :class:`unittest.mock.AsyncMock`
so the test never touches Postgres.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest

from nexus.agents.planner import PlannerAgent
from nexus.exceptions import AgentError
from nexus.schemas.models import (
    AgentState,
    FocusArea,
    Priority,
    ThreatReportSummary,
)

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


class _FakeLLM:
    """Minimal ChatOpenAI stand-in. Returns a configurable string response."""

    def __init__(self, content: str = "[]") -> None:
        self.content = content
        self.calls: list[str] = []

    async def ainvoke(self, prompt: str, **_: Any) -> Any:
        self.calls.append(prompt)
        return type("FakeResp", (), {"content": self.content})()


def _valid_plan_payload(n: int = 5) -> str:
    items = [
        {
            "description": (f"Investigate vector {i} affecting the target architecture."),
            "focus_area": (
                FocusArea.INJECTION.value if i % 2 == 0 else FocusArea.SUPPLY_CHAIN.value
            ),
            "priority": Priority.HIGH.value,
            "search_queries": [f"query {i}"],
        }
        for i in range(n)
    ]
    return json.dumps(items)


def _state(target: str = "FastAPI + pgvector RAG") -> AgentState:
    return cast(
        AgentState,
        {
            "messages": [],
            "target_description": target,
            "session_id": "test-planner",
            "plan": [],
            "findings": [],
            "threat_surfaces": [],
            "critic_report": None,
            "threat_report": None,
            "iteration_count": 0,
            "should_continue": True,
        },
    )


def _summary(target: str, score: float) -> ThreatReportSummary:
    return ThreatReportSummary(
        id="00000000-0000-0000-0000-000000000001",
        session_id="prior-001",
        target_description=target,
        created_at=datetime.now(UTC),
        surface_count=3,
        severity_breakdown={"critical": 1, "high": 2, "medium": 0, "low": 0},
        focus_areas_covered=[FocusArea.INJECTION],
        top_attack_vectors=["prompt injection"],
        overall_critic_score=score,
        iteration_count=2,
    )


async def _embed(_text: str) -> list[float]:
    return [0.0] * 1536


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------


async def test_planner_produces_5_tasks() -> None:
    llm = _FakeLLM(content=_valid_plan_payload(5))
    agent = PlannerAgent(llm=llm)

    out = await agent.run(_state())

    assert len(out["plan"]) == 5
    assert all(t.focus_area in FocusArea for t in out["plan"])
    assert all(len(t.search_queries) >= 1 for t in out["plan"])


async def test_planner_accepts_min_and_max_task_counts() -> None:
    for count in (4, 6):
        llm = _FakeLLM(content=_valid_plan_payload(count))
        out = await PlannerAgent(llm=llm).run(_state())
        assert len(out["plan"]) == count


async def test_planner_rejects_too_few_tasks() -> None:
    llm = _FakeLLM(content=_valid_plan_payload(2))
    with pytest.raises(AgentError, match="2 tasks"):
        await PlannerAgent(llm=llm).run(_state())


async def test_planner_rejects_too_many_tasks() -> None:
    llm = _FakeLLM(content=_valid_plan_payload(8))
    with pytest.raises(AgentError, match="8 tasks"):
        await PlannerAgent(llm=llm).run(_state())


async def test_planner_includes_episodic_context_in_prompt() -> None:
    llm = _FakeLLM(content=_valid_plan_payload(4))
    memory = AsyncMock()
    memory.search_similar = AsyncMock(
        return_value=[_summary("Past RAG with no auth", 0.42)],
    )

    agent = PlannerAgent(llm=llm, episodic_memory=memory, embed_fn=_embed)
    await agent.run(_state())

    assert agent.last_prompt is not None
    assert "Past similar architectures" in agent.last_prompt
    assert "Past RAG with no auth" in agent.last_prompt
    memory.search_similar.assert_awaited_once()
    args, kwargs = memory.search_similar.call_args
    assert kwargs["threshold"] == 0.85
    assert kwargs["limit"] == 3


async def test_planner_omits_episodic_block_when_no_results() -> None:
    llm = _FakeLLM(content=_valid_plan_payload(4))
    memory = AsyncMock()
    memory.search_similar = AsyncMock(return_value=[])

    agent = PlannerAgent(llm=llm, episodic_memory=memory, embed_fn=_embed)
    await agent.run(_state())

    assert agent.last_prompt is not None
    assert "Past similar architectures" not in agent.last_prompt


async def test_planner_skips_episodic_when_memory_missing() -> None:
    llm = _FakeLLM(content=_valid_plan_payload(4))
    agent = PlannerAgent(llm=llm)  # no memory, no embed fn

    out = await agent.run(_state())

    assert len(out["plan"]) == 4
    assert agent.last_prompt is not None
    assert "Past similar architectures" not in agent.last_prompt


async def test_planner_invalid_json_raises_agent_error() -> None:
    llm = _FakeLLM(content="this is not JSON at all")
    with pytest.raises(AgentError, match="parse LLM JSON"):
        await PlannerAgent(llm=llm).run(_state())


async def test_planner_invalid_research_task_raises_agent_error() -> None:
    llm = _FakeLLM(
        content=json.dumps(
            [
                {
                    "description": "valid item with enough characters here",
                    "focus_area": "injection",
                    "priority": "high",
                    "search_queries": ["q"],
                },
                {"description": "x"},  # too short, missing fields
            ],
        ),
    )
    with pytest.raises(AgentError, match="invalid ResearchTask"):
        await PlannerAgent(llm=llm).run(_state())


async def test_planner_strips_markdown_code_fences() -> None:
    fenced = "```json\n" + _valid_plan_payload(4) + "\n```"
    llm = _FakeLLM(content=fenced)
    out = await PlannerAgent(llm=llm).run(_state())
    assert len(out["plan"]) == 4


async def test_planner_episodic_failure_does_not_abort() -> None:
    llm = _FakeLLM(content=_valid_plan_payload(4))
    memory = AsyncMock()
    memory.search_similar = AsyncMock(side_effect=RuntimeError("db is down"))

    agent = PlannerAgent(llm=llm, episodic_memory=memory, embed_fn=_embed)
    out = await agent.run(_state())

    # Lookup failed, but the plan was still generated.
    assert len(out["plan"]) == 4


async def test_planner_llm_failure_raises_agent_error() -> None:
    llm = _FakeLLM()

    async def bad_invoke(_prompt: str, **_: Any) -> Any:
        raise RuntimeError("rate limited")

    llm.ainvoke = bad_invoke  # type: ignore[method-assign]
    with pytest.raises(AgentError, match="LLM call failed"):
        await PlannerAgent(llm=llm).run(_state())
