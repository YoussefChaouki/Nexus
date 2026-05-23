"""Tests for the Analyst agent.

The LLM is replaced with a hand-rolled fake whose ``ainvoke`` pops queued
responses (one per focus_area group). SemanticMemory is mocked via
:class:`unittest.mock.AsyncMock` so the test never touches Postgres.
"""

from __future__ import annotations

import json
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest

from nexus.agents.analyst import AnalystAgent
from nexus.exceptions import AgentError
from nexus.schemas.models import (
    AgentState,
    FindingResult,
    FocusArea,
    Priority,
    ResearchTask,
    SourceType,
    ThreatPattern,
)

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


class _FakeLLM:
    """ChatOpenAI stand-in. Returns queued responses, one per ainvoke call."""

    def __init__(self, responses: list[str] | str) -> None:
        if isinstance(responses, str):
            responses = [responses]
        self.responses = list(responses)
        self.calls: list[str] = []

    async def ainvoke(self, prompt: str, **_: Any) -> Any:
        self.calls.append(prompt)
        if self.responses:
            content = self.responses.pop(0)
        else:
            content = "{}"
        return type("FakeResp", (), {"content": content})()


def _surface_payload(
    *,
    name: str = "Prompt Injection",
    severity: str = "high",
    owasp: str | None = "LLM01",
    cvss: float | None = 7.5,
    vectors: list[str] | None = None,
    mitigations: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "description": f"{name} attack against the target system architecture.",
        "severity": severity,
        "attack_vectors": vectors or ["direct injection"],
        "mitigations": mitigations or ["validate inputs"],
        "cvss_score": cvss,
        "owasp_category": owasp,
    }


def _task(focus: FocusArea, *, task_id: str | None = None) -> ResearchTask:
    return ResearchTask(
        id=task_id or f"task-{focus.value}",
        description=f"Investigate {focus.value} attacks against the target.",
        focus_area=focus,
        priority=Priority.HIGH,
    )


def _finding(
    task_id: str,
    *,
    ident: str,
    title: str = "Some result",
    score: float = 0.7,
    source: SourceType = SourceType.ARXIV,
) -> FindingResult:
    return FindingResult(
        task_id=task_id,
        source_type=source,
        title=title,
        summary="A summary that is long enough to satisfy the validator.",
        relevance_score=score,
        identifiers=[ident],
    )


def _state(
    *,
    plan: list[ResearchTask],
    findings: list[FindingResult],
    iteration_count: int = 1,
) -> AgentState:
    return cast(
        AgentState,
        {
            "messages": [],
            "target_description": "FastAPI + pgvector RAG",
            "session_id": "test-analyst",
            "plan": plan,
            "findings": findings,
            "threat_surfaces": [],
            "critic_report": None,
            "threat_report": None,
            "iteration_count": iteration_count,
            "should_continue": True,
        },
    )


async def _embed(_text: str) -> list[float]:
    return [0.0] * 1536


def _pattern(name: str, source: str = "atlas") -> ThreatPattern:
    return ThreatPattern(
        source_type=source,
        pattern_id="T0001",
        name=name,
        pattern_text="Adversary attempts to manipulate model inputs.",
    )


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------


async def test_analyst_groups_findings_by_focus_area() -> None:
    plan = [
        _task(FocusArea.INJECTION, task_id="task-inj"),
        _task(FocusArea.SUPPLY_CHAIN, task_id="task-sup"),
    ]
    findings = [
        _finding("task-inj", ident="arxiv:1"),
        _finding("task-inj", ident="arxiv:2"),
        _finding("task-sup", ident="cve-1"),
    ]
    llm = _FakeLLM(
        [
            json.dumps(_surface_payload(name="Prompt Injection", severity="high")),
            json.dumps(
                _surface_payload(name="Supply Chain", severity="critical", owasp="LLM05"),
            ),
        ],
    )

    out = await AnalystAgent(llm=llm).run(_state(plan=plan, findings=findings))

    surfaces = out["threat_surfaces"]
    assert len(surfaces) == 2
    assert {s.name for s in surfaces} == {"Prompt Injection", "Supply Chain"}
    by_name = {s.name: s for s in surfaces}
    assert len(by_name["Prompt Injection"].evidence) == 2
    assert len(by_name["Supply Chain"].evidence) == 1


async def test_analyst_queries_semantic_memory_per_group() -> None:
    plan = [
        _task(FocusArea.INJECTION, task_id="task-inj"),
        _task(FocusArea.DATA_LEAKAGE, task_id="task-leak"),
    ]
    findings = [
        _finding("task-inj", ident="arxiv:1", title="Injection paper"),
        _finding("task-leak", ident="arxiv:2", title="Leakage paper"),
    ]
    llm = _FakeLLM(
        [
            json.dumps(_surface_payload(name="Prompt Injection")),
            json.dumps(_surface_payload(name="Data Leakage", severity="medium")),
        ],
    )
    memory = AsyncMock()
    memory.search_patterns = AsyncMock(return_value=[_pattern("Prompt Injection")])

    agent = AnalystAgent(llm=llm, semantic_memory=memory, embed_fn=_embed)
    await agent.run(_state(plan=plan, findings=findings))

    assert memory.search_patterns.await_count == 2
    for call in memory.search_patterns.call_args_list:
        assert call.kwargs["limit"] == 5
    # Pattern context surfaces in the prompt.
    assert any("Prompt Injection" in p for p in agent.last_prompts)


async def test_analyst_skips_semantic_memory_when_missing() -> None:
    plan = [_task(FocusArea.INJECTION, task_id="task-inj")]
    findings = [_finding("task-inj", ident="arxiv:1")]
    llm = _FakeLLM(json.dumps(_surface_payload()))

    agent = AnalystAgent(llm=llm)  # no memory, no embed fn
    out = await agent.run(_state(plan=plan, findings=findings))

    assert len(out["threat_surfaces"]) == 1
    assert "no related patterns" in agent.last_prompts[0]


async def test_analyst_semantic_failure_does_not_abort() -> None:
    plan = [_task(FocusArea.INJECTION, task_id="task-inj")]
    findings = [_finding("task-inj", ident="arxiv:1")]
    llm = _FakeLLM(json.dumps(_surface_payload()))
    memory = AsyncMock()
    memory.search_patterns = AsyncMock(side_effect=RuntimeError("pgvector down"))

    agent = AnalystAgent(llm=llm, semantic_memory=memory, embed_fn=_embed)
    out = await agent.run(_state(plan=plan, findings=findings))

    assert len(out["threat_surfaces"]) == 1


async def test_analyst_owasp_category_propagates() -> None:
    plan = [_task(FocusArea.INJECTION, task_id="task-inj")]
    # Two findings @ relevance 0.7 keep the evidence-quality heuristic happy.
    findings = [
        _finding("task-inj", ident="arxiv:1", score=0.7),
        _finding("task-inj", ident="arxiv:2", score=0.7),
    ]
    llm = _FakeLLM(json.dumps(_surface_payload(owasp="LLM01")))

    out = await AnalystAgent(llm=llm).run(_state(plan=plan, findings=findings))

    surface = out["threat_surfaces"][0]
    assert surface.owasp_category == "LLM01"
    assert surface.severity.value == "high"
    assert surface.cvss_score == 7.5


async def test_analyst_attaches_real_evidence_overriding_llm() -> None:
    plan = [_task(FocusArea.INJECTION, task_id="task-inj")]
    findings = [
        _finding("task-inj", ident="arxiv:real-1", title="Real paper 1"),
        _finding("task-inj", ident="arxiv:real-2", title="Real paper 2"),
    ]
    # LLM tries to inject fake evidence — agent must overwrite it.
    payload = _surface_payload()
    payload["evidence"] = [{"task_id": "fake", "title": "fake"}]
    llm = _FakeLLM(json.dumps(payload))

    out = await AnalystAgent(llm=llm).run(_state(plan=plan, findings=findings))

    surface = out["threat_surfaces"][0]
    titles = {e.title for e in surface.evidence}
    assert titles == {"Real paper 1", "Real paper 2"}


async def test_analyst_findings_with_unknown_task_id_use_other() -> None:
    plan = [_task(FocusArea.INJECTION, task_id="task-inj")]
    findings = [
        _finding("task-inj", ident="arxiv:1"),
        _finding("task-orphan", ident="arxiv:2"),
    ]
    llm = _FakeLLM(
        [
            json.dumps(_surface_payload(name="Prompt Injection")),
            json.dumps(_surface_payload(name="Misc Threat", severity="low", owasp=None)),
        ],
    )

    out = await AnalystAgent(llm=llm).run(_state(plan=plan, findings=findings))

    assert len(out["threat_surfaces"]) == 2
    assert {s.name for s in out["threat_surfaces"]} == {"Prompt Injection", "Misc Threat"}


async def test_analyst_invalid_llm_json_raises_agent_error() -> None:
    plan = [_task(FocusArea.INJECTION, task_id="task-inj")]
    findings = [_finding("task-inj", ident="arxiv:1")]
    llm = _FakeLLM("this response contains no json")

    with pytest.raises(AgentError, match="parse LLM JSON"):
        await AnalystAgent(llm=llm).run(_state(plan=plan, findings=findings))


async def test_analyst_invalid_threat_surface_raises_agent_error() -> None:
    plan = [_task(FocusArea.INJECTION, task_id="task-inj")]
    findings = [_finding("task-inj", ident="arxiv:1")]
    # description must be at least 30 chars (Pydantic min_length=30).
    bad_payload = _surface_payload()
    bad_payload["description"] = "too short"
    llm = _FakeLLM(json.dumps(bad_payload))

    with pytest.raises(AgentError, match="invalid ThreatSurface"):
        await AnalystAgent(llm=llm).run(_state(plan=plan, findings=findings))


async def test_analyst_llm_failure_raises_agent_error() -> None:
    plan = [_task(FocusArea.INJECTION, task_id="task-inj")]
    findings = [_finding("task-inj", ident="arxiv:1")]
    llm = _FakeLLM("[]")

    async def bad_invoke(_prompt: str, **_: Any) -> Any:
        raise RuntimeError("rate limited")

    llm.ainvoke = bad_invoke  # type: ignore[method-assign]
    with pytest.raises(AgentError, match="LLM call failed"):
        await AnalystAgent(llm=llm).run(_state(plan=plan, findings=findings))


async def test_analyst_no_findings_raises() -> None:
    plan = [_task(FocusArea.INJECTION, task_id="task-inj")]
    llm = _FakeLLM("{}")
    with pytest.raises(AgentError, match="at least one finding"):
        await AnalystAgent(llm=llm).run(_state(plan=plan, findings=[]))


async def test_analyst_no_plan_raises() -> None:
    findings = [_finding("task-inj", ident="arxiv:1")]
    llm = _FakeLLM("{}")
    with pytest.raises(AgentError, match="non-empty plan"):
        await AnalystAgent(llm=llm).run(_state(plan=[], findings=findings))


async def test_analyst_strips_markdown_code_fences() -> None:
    plan = [_task(FocusArea.INJECTION, task_id="task-inj")]
    findings = [_finding("task-inj", ident="arxiv:1")]
    fenced = "```json\n" + json.dumps(_surface_payload()) + "\n```"
    llm = _FakeLLM(fenced)

    out = await AnalystAgent(llm=llm).run(_state(plan=plan, findings=findings))
    assert len(out["threat_surfaces"]) == 1


async def test_analyst_embed_query_uses_top_findings_by_relevance() -> None:
    plan = [_task(FocusArea.INJECTION, task_id="task-inj")]
    findings = [
        _finding("task-inj", ident="arxiv:1", title="Low score paper", score=0.1),
        _finding("task-inj", ident="arxiv:2", title="High score paper", score=0.9),
    ]
    captured: list[str] = []

    async def capture_embed(text: str) -> list[float]:
        captured.append(text)
        return [0.0] * 1536

    memory = AsyncMock()
    memory.search_patterns = AsyncMock(return_value=[])
    llm = _FakeLLM(json.dumps(_surface_payload()))

    agent = AnalystAgent(llm=llm, semantic_memory=memory, embed_fn=capture_embed)
    await agent.run(_state(plan=plan, findings=findings))

    assert captured, "embed_fn should be called when memory is configured"
    # Top finding by relevance should appear first in the embed query.
    assert captured[0].startswith("High score paper")


# --------------------------------------------------------------------------
# Severity calibration (S8.T1)
# --------------------------------------------------------------------------


def _strong_findings(task_id: str, *, count: int = 2, score: float = 0.8) -> list[FindingResult]:
    """Findings that defeat the evidence-quality downgrade heuristic."""
    return [
        _finding(task_id, ident=f"src:{i}", score=score, title=f"Solid paper {i}")
        for i in range(count)
    ]


@pytest.mark.parametrize("band", ["critical", "high", "medium", "low"])
async def test_analyst_severity_round_trips(band: str) -> None:
    """With strong evidence the LLM-chosen severity is preserved verbatim."""
    plan = [_task(FocusArea.INJECTION, task_id="task-inj")]
    findings = _strong_findings("task-inj")
    payload = _surface_payload(severity=band, cvss=None)
    payload["severity_reasoning"] = f"{band} band: rubric example reasoning."
    llm = _FakeLLM(json.dumps(payload))

    out = await AnalystAgent(llm=llm).run(_state(plan=plan, findings=findings))

    surface = out["threat_surfaces"][0]
    assert surface.severity.value == band
    assert surface.severity_reasoning is not None
    assert band in surface.severity_reasoning.lower()


async def test_analyst_downgrades_severity_when_evidence_is_thin() -> None:
    """One finding triggers a one-band downgrade per the evidence rubric."""
    plan = [_task(FocusArea.INJECTION, task_id="task-inj")]
    findings = [_finding("task-inj", ident="arxiv:1", score=0.8)]  # len < 2
    llm = _FakeLLM(json.dumps(_surface_payload(severity="critical")))

    out = await AnalystAgent(llm=llm).run(_state(plan=plan, findings=findings))

    assert out["threat_surfaces"][0].severity.value == "high"


async def test_analyst_downgrades_severity_on_weak_relevance() -> None:
    """Top relevance < 0.6 triggers a downgrade even with multiple findings."""
    plan = [_task(FocusArea.INJECTION, task_id="task-inj")]
    findings = [
        _finding("task-inj", ident="arxiv:1", score=0.3),
        _finding("task-inj", ident="arxiv:2", score=0.4),
    ]
    llm = _FakeLLM(json.dumps(_surface_payload(severity="high")))

    out = await AnalystAgent(llm=llm).run(_state(plan=plan, findings=findings))

    assert out["threat_surfaces"][0].severity.value == "medium"


async def test_analyst_low_severity_is_a_fixed_point_when_downgrading() -> None:
    """LOW + thin evidence stays LOW (no band below)."""
    plan = [_task(FocusArea.INJECTION, task_id="task-inj")]
    findings = [_finding("task-inj", ident="arxiv:1", score=0.2)]
    llm = _FakeLLM(json.dumps(_surface_payload(severity="low")))

    out = await AnalystAgent(llm=llm).run(_state(plan=plan, findings=findings))

    assert out["threat_surfaces"][0].severity.value == "low"


async def test_analyst_prompt_includes_severity_rubric_and_examples() -> None:
    plan = [_task(FocusArea.INJECTION, task_id="task-inj")]
    findings = _strong_findings("task-inj")
    llm = _FakeLLM(json.dumps(_surface_payload()))

    agent = AnalystAgent(llm=llm)
    await agent.run(_state(plan=plan, findings=findings))

    prompt = agent.last_prompts[0]
    assert "Severity rubric" in prompt
    assert "CRITICAL" in prompt and "MEDIUM" in prompt
    assert "Example 1" in prompt and "Example 3" in prompt
    assert "severity_reasoning" in prompt


async def test_analyst_distribution_not_flat_on_s7_failure_case() -> None:
    """Regression: the S7 portfolio review showed 6/6 surfaces all HIGH.

    Feed the same target with mock evidence shaped to elicit at least two
    distinct severity bands. The Analyst (with downgrade) MUST produce a
    non-flat distribution.
    """
    plan = [
        _task(FocusArea.INJECTION, task_id="task-inj"),
        _task(FocusArea.DATA_LEAKAGE, task_id="task-leak"),
        _task(FocusArea.SUPPLY_CHAIN, task_id="task-sup"),
    ]
    # Mix evidence depth: injection has solid evidence, supply_chain has
    # one weak finding so HIGH should drop to MEDIUM.
    findings = [
        *_strong_findings("task-inj"),
        *_strong_findings("task-leak"),
        _finding("task-sup", ident="cve-1", score=0.4),
    ]
    llm = _FakeLLM(
        [
            json.dumps(_surface_payload(name="Prompt Injection", severity="critical")),
            json.dumps(_surface_payload(name="Data Leakage", severity="high", owasp="LLM06")),
            json.dumps(_surface_payload(name="Supply Chain", severity="high", owasp="LLM05")),
        ],
    )

    state = _state(
        plan=plan,
        findings=findings,
    )
    state["target_description"] = (
        "FastAPI backend with pgvector for a RAG pipeline, Streamlit frontend "
        "on AWS ECS, OpenAI GPT-4, no authentication, enterprise documents "
        "ingested via user upload"
    )

    out = await AnalystAgent(llm=llm).run(state)

    bands = {s.severity.value for s in out["threat_surfaces"]}
    assert len(bands) >= 2, f"severity distribution must not be flat: got {bands}"


async def test_analyst_normalizes_uppercase_severity_from_llm() -> None:
    """Real LLMs mimic the prompt's uppercase rubric (e.g. emit 'HIGH').

    The agent must lowercase before validation so the Severity enum accepts it.
    """
    plan = [_task(FocusArea.INJECTION, task_id="task-inj")]
    findings = _strong_findings("task-inj")
    payload = _surface_payload(severity="HIGH")  # uppercase
    llm = _FakeLLM(json.dumps(payload))

    out = await AnalystAgent(llm=llm).run(_state(plan=plan, findings=findings))

    assert out["threat_surfaces"][0].severity.value == "high"


def test_analyst_helpers_downgrade_severity() -> None:
    """Direct unit test on the band ordering."""
    from nexus.agents.analyst import _downgrade_severity
    from nexus.schemas.models import Severity

    assert _downgrade_severity(Severity.CRITICAL) == Severity.HIGH
    assert _downgrade_severity(Severity.HIGH) == Severity.MEDIUM
    assert _downgrade_severity(Severity.MEDIUM) == Severity.LOW
    assert _downgrade_severity(Severity.LOW) == Severity.LOW
