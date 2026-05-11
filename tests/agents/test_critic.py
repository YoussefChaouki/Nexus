"""Tests for the real OWASP-driven CriticAgent.

The LLM is replaced with a hand-rolled fake whose ``ainvoke`` returns
queued JSON strings — one for the applicable-category filter, one for
the main evaluation, plus an optional retry. A queued ``RuntimeError``
exercises the network-failure branch.
"""

from __future__ import annotations

import json
from typing import Any, cast
from unittest.mock import patch

import pytest

from nexus.agents.critic import OWASP_LLM_TOP10, CriticAgent
from nexus.exceptions import AgentError
from nexus.schemas.models import (
    AgentState,
    FindingResult,
    FocusArea,
    Recommendation,
    Severity,
    SourceType,
    ThreatSurface,
)

pytestmark = pytest.mark.asyncio


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


class _FakeLLM:
    """ChatOpenAI stand-in. Pops queued responses on each ainvoke call.

    Each queued entry is either a ``str`` (used as ``response.content``)
    or an ``Exception`` instance to raise.
    """

    def __init__(self, responses: list[str | Exception]) -> None:
        self.responses: list[str | Exception] = list(responses)
        self.calls: list[str] = []
        self.configs: list[dict[str, Any]] = []

    async def ainvoke(self, prompt: str, **kwargs: Any) -> Any:
        self.calls.append(prompt)
        self.configs.append(kwargs.get("config", {}))
        if not self.responses:
            return type("FakeResp", (), {"content": "{}"})()
        next_resp = self.responses.pop(0)
        if isinstance(next_resp, Exception):
            raise next_resp
        return type("FakeResp", (), {"content": next_resp})()


def _finding(task_id: str = "task-x") -> FindingResult:
    return FindingResult(
        task_id=task_id,
        source_type=SourceType.ARXIV,
        title="A relevant paper",
        summary="A summary long enough to satisfy the validator easily.",
        relevance_score=0.7,
        identifiers=["arxiv:1234"],
    )


def _surface(
    *,
    name: str = "Prompt Injection",
    severity: Severity = Severity.HIGH,
    owasp: str | None = "LLM01",
) -> ThreatSurface:
    return ThreatSurface(
        name=name,
        description=f"{name} threat surface for the target system architecture.",
        severity=severity,
        attack_vectors=["direct injection"],
        evidence=[_finding()],
        mitigations=["validate inputs"],
        cvss_score=7.5,
        owasp_category=owasp,
    )


def _state(
    *,
    surfaces: list[ThreatSurface] | None = None,
    iteration_count: int = 1,
    session_id: str = "test-critic",
) -> AgentState:
    resolved = [_surface()] if surfaces is None else surfaces
    return cast(
        AgentState,
        {
            "messages": [],
            "target_description": "FastAPI + pgvector RAG, OpenAI API, no auth",
            "session_id": session_id,
            "plan": [],
            "findings": [_finding()],
            "threat_surfaces": resolved,
            "critic_report": None,
            "threat_report": None,
            "iteration_count": iteration_count,
            "should_continue": True,
        },
    )


def _critic_payload(
    *,
    score: float,
    recommendation: Recommendation,
    gaps: list[str] | None = None,
    re_research_tasks: list[dict[str, Any]] | None = None,
) -> str:
    return json.dumps(
        {
            "overall_score": score,
            "gaps": gaps or [],
            "bias_warnings": [],
            "recommendation": recommendation.value,
            "re_research_tasks": re_research_tasks or [],
        },
    )


def _re_research_task(focus_area: FocusArea) -> dict[str, Any]:
    return {
        "description": f"Investigate {focus_area.value} attacks against the target.",
        "focus_area": focus_area.value,
        "priority": "high",
        "search_queries": [f"{focus_area.value} attack survey"],
    }


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------


async def test_approve_when_score_above_threshold() -> None:
    llm = _FakeLLM(
        [
            json.dumps(["LLM01", "LLM06"]),  # filter
            _critic_payload(score=0.75, recommendation=Recommendation.APPROVE),
        ],
    )
    out = await CriticAgent(llm=llm).run(_state())

    report = out["critic_report"]
    assert report is not None
    assert report.overall_score == 0.75
    assert report.recommendation == Recommendation.APPROVE
    assert report.re_research_tasks == []
    # Filter + main eval = exactly two LLM calls.
    assert len(llm.calls) == 2


async def test_re_research_when_score_below_threshold() -> None:
    llm = _FakeLLM(
        [
            json.dumps(["LLM01", "LLM06", "LLM10"]),  # filter
            _critic_payload(
                score=0.45,
                recommendation=Recommendation.RE_RESEARCH,
                gaps=["LLM10 not covered"],
                re_research_tasks=[_re_research_task(FocusArea.MODEL_EXTRACTION)],
            ),
        ],
    )
    out = await CriticAgent(llm=llm).run(_state())

    report = out["critic_report"]
    assert report is not None
    assert report.recommendation == Recommendation.RE_RESEARCH
    assert len(report.re_research_tasks) == 1
    assert report.re_research_tasks[0].focus_area == FocusArea.MODEL_EXTRACTION


async def test_force_approve_at_max_iterations() -> None:
    """At iteration_count == max_iterations, RE_RESEARCH must be coerced to APPROVE."""
    llm = _FakeLLM(
        [
            json.dumps(["LLM01", "LLM10"]),
            _critic_payload(
                score=0.40,
                recommendation=Recommendation.RE_RESEARCH,
                gaps=["LLM10 not covered"],
                re_research_tasks=[_re_research_task(FocusArea.MODEL_EXTRACTION)],
            ),
        ],
    )
    out = await CriticAgent(llm=llm).run(_state(iteration_count=3))

    report = out["critic_report"]
    assert report is not None
    assert report.recommendation == Recommendation.APPROVE
    assert report.re_research_tasks == []
    assert report.overall_score == 0.40  # score preserved for transparency


async def test_force_approve_when_llm_returns_inconsistent_high_score() -> None:
    """LLM contradicts itself (score=0.9 but says RE_RESEARCH) — guardrail wins."""
    llm = _FakeLLM(
        [
            json.dumps(["LLM01"]),
            _critic_payload(
                score=0.9,
                recommendation=Recommendation.RE_RESEARCH,
                gaps=["nitpick"],
                re_research_tasks=[_re_research_task(FocusArea.INJECTION)],
            ),
        ],
    )
    out = await CriticAgent(llm=llm).run(_state(iteration_count=1))

    report = out["critic_report"]
    assert report is not None
    assert report.recommendation == Recommendation.APPROVE


async def test_re_research_tasks_target_uncovered_categories() -> None:
    """Verify the re-research task focus_area aligns with the gap reported."""
    surfaces = [_surface(name="Prompt Injection", owasp="LLM01")]  # covers LLM01 only
    llm = _FakeLLM(
        [
            json.dumps(["LLM01", "LLM06", "LLM10"]),  # 3 applicable
            _critic_payload(
                score=1 / 3,
                recommendation=Recommendation.RE_RESEARCH,
                gaps=["LLM06 not covered", "LLM10 not covered"],
                re_research_tasks=[
                    _re_research_task(FocusArea.DATA_LEAKAGE),
                    _re_research_task(FocusArea.MODEL_EXTRACTION),
                ],
            ),
        ],
    )

    out = await CriticAgent(llm=llm).run(_state(surfaces=surfaces))

    report = out["critic_report"]
    assert report is not None
    focus_areas = {t.focus_area for t in report.re_research_tasks}
    assert focus_areas == {FocusArea.DATA_LEAKAGE, FocusArea.MODEL_EXTRACTION}


async def test_langfuse_handler_called_with_session_id() -> None:
    llm = _FakeLLM(
        [
            json.dumps(["LLM01"]),
            _critic_payload(score=0.8, recommendation=Recommendation.APPROVE),
        ],
    )
    with patch("nexus.agents.critic.get_langfuse_handler") as handler_mock:
        handler_mock.return_value = None  # langfuse not installed in test env
        await CriticAgent(llm=llm).run(_state(session_id="sess-42"))

    handler_mock.assert_called_once_with("sess-42")
    # Both LLM calls received a callbacks list (even if empty) and metadata.
    assert len(llm.configs) == 2
    for cfg, step in zip(llm.configs, ["filter_categories", "evaluate"], strict=True):
        assert "callbacks" in cfg
        assert cfg["metadata"]["agent"] == "critic"
        assert cfg["metadata"]["step"] == step
        assert cfg["metadata"]["iteration"] == 1


async def test_langfuse_handler_attached_when_available() -> None:
    """When the handler factory returns a sentinel, both LLM calls receive it."""
    sentinel = object()
    llm = _FakeLLM(
        [
            json.dumps(["LLM01"]),
            _critic_payload(score=0.8, recommendation=Recommendation.APPROVE),
        ],
    )
    with patch("nexus.agents.critic.get_langfuse_handler", return_value=sentinel):
        await CriticAgent(llm=llm).run(_state())

    for cfg in llm.configs:
        assert cfg["callbacks"] == [sentinel]


async def test_filter_unparseable_falls_back_to_all_categories() -> None:
    llm = _FakeLLM(
        [
            "this is not a JSON array",  # filter — unparseable
            _critic_payload(score=0.8, recommendation=Recommendation.APPROVE),
        ],
    )
    await CriticAgent(llm=llm).run(_state())

    # The main eval prompt should mention every OWASP category.
    eval_prompt = llm.calls[1]
    for cat in OWASP_LLM_TOP10:
        assert cat in eval_prompt


async def test_filter_empty_array_falls_back_to_all_categories() -> None:
    llm = _FakeLLM(
        [
            "[]",  # filter — empty, must fall back
            _critic_payload(score=0.8, recommendation=Recommendation.APPROVE),
        ],
    )
    await CriticAgent(llm=llm).run(_state())

    eval_prompt = llm.calls[1]
    for cat in OWASP_LLM_TOP10:
        assert cat in eval_prompt


async def test_filter_ignores_unknown_category_ids() -> None:
    llm = _FakeLLM(
        [
            json.dumps(["LLM01", "LLM99", "garbage"]),
            _critic_payload(score=0.8, recommendation=Recommendation.APPROVE),
        ],
    )
    await CriticAgent(llm=llm).run(_state())

    eval_prompt = llm.calls[1]
    assert "LLM01" in eval_prompt
    assert "LLM99" not in eval_prompt


async def test_invalid_eval_response_retried_then_succeeds() -> None:
    llm = _FakeLLM(
        [
            json.dumps(["LLM01"]),
            "not a json object at all",  # first eval: invalid
            _critic_payload(score=0.8, recommendation=Recommendation.APPROVE),  # retry
        ],
    )
    out = await CriticAgent(llm=llm).run(_state())

    report = out["critic_report"]
    assert report is not None
    assert report.recommendation == Recommendation.APPROVE
    assert len(llm.calls) == 3  # filter + bad eval + retry


async def test_invalid_eval_response_after_retry_raises() -> None:
    llm = _FakeLLM(
        [
            json.dumps(["LLM01"]),
            "not json",
            "still not json",
        ],
    )
    with pytest.raises(AgentError, match="invalid CriticReport"):
        await CriticAgent(llm=llm).run(_state())


async def test_filter_llm_failure_raises_agent_error() -> None:
    llm = _FakeLLM([RuntimeError("rate limited")])
    with pytest.raises(AgentError, match="Critic filter LLM call failed"):
        await CriticAgent(llm=llm).run(_state())


async def test_eval_llm_failure_raises_agent_error() -> None:
    llm = _FakeLLM(
        [
            json.dumps(["LLM01"]),
            RuntimeError("upstream error"),
        ],
    )
    with pytest.raises(AgentError, match="Critic evaluation LLM call failed"):
        await CriticAgent(llm=llm).run(_state())


async def test_critic_requires_threat_surfaces() -> None:
    llm = _FakeLLM([])
    with pytest.raises(AgentError, match="at least one threat surface"):
        await CriticAgent(llm=llm).run(_state(surfaces=[]))


async def test_critic_re_research_without_tasks_fails_validation_then_retry() -> None:
    """A malformed CriticReport (RE_RESEARCH but no tasks) should be retried."""
    llm = _FakeLLM(
        [
            json.dumps(["LLM01", "LLM10"]),
            _critic_payload(
                score=0.40,
                recommendation=Recommendation.RE_RESEARCH,
                gaps=["LLM10 not covered"],
                re_research_tasks=[],  # invalid per the schema validator
            ),
            _critic_payload(
                score=0.40,
                recommendation=Recommendation.RE_RESEARCH,
                gaps=["LLM10 not covered"],
                re_research_tasks=[_re_research_task(FocusArea.MODEL_EXTRACTION)],
            ),
        ],
    )
    out = await CriticAgent(llm=llm).run(_state())
    report = out["critic_report"]
    assert report is not None
    assert report.recommendation == Recommendation.RE_RESEARCH
    assert len(report.re_research_tasks) == 1
