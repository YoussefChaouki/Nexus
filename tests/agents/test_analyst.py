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
    CriticReport,
    FindingResult,
    FocusArea,
    Priority,
    Recommendation,
    ResearchTask,
    SourceType,
    ThreatPattern,
)

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


class _FakeLLM:
    """ChatOpenAI stand-in.

    Returns queued responses, one per ``ainvoke`` call. Recognises the
    Analyst relevance-gate prompt (``"You gate the Analyst against
    off-topic synthesis."``) and auto-answers ``yes`` without consuming
    a queued response — keeps the synthesis-focused tests concise. Tests
    that need to exercise the gate can pass ``relevance_responses=...``.
    """

    def __init__(
        self,
        responses: list[str] | str,
        relevance_responses: list[str] | None = None,
    ) -> None:
        if isinstance(responses, str):
            responses = [responses]
        self.responses = list(responses)
        self.relevance_responses = list(relevance_responses) if relevance_responses else None
        self.calls: list[str] = []

    async def ainvoke(self, prompt: str, **_: Any) -> Any:
        self.calls.append(prompt)
        if "You gate the Analyst" in prompt:
            if self.relevance_responses is not None and self.relevance_responses:
                content = self.relevance_responses.pop(0)
            else:
                content = "yes - findings match the target architecture"
        elif self.responses:
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
    critic_report: CriticReport | None = None,
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
            "critic_report": critic_report,
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


async def test_analyst_prompt_includes_target_description() -> None:
    """S10: severity calibration needs the target's trust boundaries in-context."""
    plan = [_task(FocusArea.INJECTION, task_id="task-inj")]
    findings = _strong_findings("task-inj")
    llm = _FakeLLM(json.dumps(_surface_payload()))

    agent = AnalystAgent(llm=llm)
    state = _state(plan=plan, findings=findings)
    state["target_description"] = "Streamlit RAG on ECS, no auth, user uploads"
    await agent.run(state)

    prompt = agent.last_prompts[0]
    assert "Streamlit RAG on ECS, no auth, user uploads" in prompt
    assert "Target architecture under analysis" in prompt


async def test_analyst_prompt_caps_findings_and_ranks_by_relevance() -> None:
    """Only the strongest findings enter the prompt; weak tail is excluded."""
    plan = [_task(FocusArea.INJECTION, task_id="task-inj")]
    findings = [
        _finding("task-inj", ident=f"arxiv:{i}", title=f"Paper {i}", score=i / 100)
        for i in range(1, 21)  # scores 0.01 .. 0.20
    ]
    llm = _FakeLLM(json.dumps(_surface_payload()))

    agent = AnalystAgent(llm=llm)
    await agent.run(_state(plan=plan, findings=findings))

    prompt = agent.last_prompts[0]
    # Top-12 by relevance are Papers 9..20; the weakest 8 must be absent.
    assert "Paper 20" in prompt and "Paper 9" in prompt
    assert "Paper 8 " not in prompt and "Paper 1 " not in prompt


async def test_analyst_evidence_sorted_by_relevance_desc() -> None:
    plan = [_task(FocusArea.INJECTION, task_id="task-inj")]
    findings = [
        _finding("task-inj", ident="arxiv:lo", title="weak", score=0.55),
        _finding("task-inj", ident="arxiv:hi", title="strong", score=0.95),
        _finding("task-inj", ident="arxiv:mid", title="middle", score=0.7),
    ]
    llm = _FakeLLM(json.dumps(_surface_payload()))

    out = await AnalystAgent(llm=llm).run(_state(plan=plan, findings=findings))

    scores = [e.relevance_score for e in out["threat_surfaces"][0].evidence]
    assert scores == sorted(scores, reverse=True)


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


async def test_analyst_skips_off_target_group() -> None:
    """LLM gate answering 'no' must skip the surface, not synthesise it."""
    plan = [_task(FocusArea.INJECTION, task_id="task-inj")]
    findings = _strong_findings("task-inj")
    # Synthesis response is queued but should NEVER be consumed because the
    # gate says no.
    llm = _FakeLLM(
        [json.dumps(_surface_payload(name="Should-not-appear"))],
        relevance_responses=["no - this finding is about M-Banking, target is a RAG pipeline"],
    )

    out = await AnalystAgent(llm=llm).run(_state(plan=plan, findings=findings))

    assert out["threat_surfaces"] == []


async def test_analyst_keeps_on_target_group_when_gate_says_yes() -> None:
    plan = [_task(FocusArea.INJECTION, task_id="task-inj")]
    findings = _strong_findings("task-inj")
    llm = _FakeLLM(
        [json.dumps(_surface_payload(name="Prompt Injection"))],
        relevance_responses=["yes - prompt injection is a direct threat to the RAG endpoint"],
    )

    out = await AnalystAgent(llm=llm).run(_state(plan=plan, findings=findings))

    assert len(out["threat_surfaces"]) == 1
    assert out["threat_surfaces"][0].name == "Prompt Injection"


async def test_analyst_defaults_null_owasp_from_focus_area() -> None:
    """A null owasp_category on a mappable focus area gets the canonical code.

    Production regression: GPT-4o reads infra-style threats (endpoint
    flooding, SQL injection) as outside the OWASP *LLM* taxonomy and
    returns null — the Critic's coverage score then can't credit the
    surface and the loop freezes at a low score.
    """
    plan = [_task(FocusArea.DENIAL_OF_SERVICE, task_id="task-dos")]
    findings = _strong_findings("task-dos")
    llm = _FakeLLM(json.dumps(_surface_payload(name="Endpoint Flooding", owasp=None)))

    out = await AnalystAgent(llm=llm).run(_state(plan=plan, findings=findings))

    assert out["threat_surfaces"][0].owasp_category == "LLM04"


async def test_analyst_keeps_explicit_owasp_category() -> None:
    """An LLM-provided category must never be overwritten by the default."""
    plan = [_task(FocusArea.INJECTION, task_id="task-inj")]
    findings = _strong_findings("task-inj")
    llm = _FakeLLM(json.dumps(_surface_payload(owasp="LLM02")))

    out = await AnalystAgent(llm=llm).run(_state(plan=plan, findings=findings))

    assert out["threat_surfaces"][0].owasp_category == "LLM02"


async def test_analyst_other_focus_area_keeps_null_owasp() -> None:
    """FocusArea.OTHER has no canonical category — null stays null."""
    plan = [_task(FocusArea.OTHER, task_id="task-other")]
    findings = _strong_findings("task-other")
    llm = _FakeLLM(json.dumps(_surface_payload(name="Misc Threat", owasp=None)))

    out = await AnalystAgent(llm=llm).run(_state(plan=plan, findings=findings))

    assert out["threat_surfaces"][0].owasp_category is None


async def test_analyst_gate_bypassed_for_critic_demanded_focus_area() -> None:
    """A focus area the Critic re-researched must never be gate-skipped.

    Production regression: data_leakage was gated out three passes in a
    row on a target where the Critic explicitly demanded it — coverage
    could never improve and the loop burned its iterations.
    """
    plan = [_task(FocusArea.DATA_LEAKAGE, task_id="task-leak")]
    findings = [_finding("task-leak", ident="cve-weak", score=0.5)]
    critic = CriticReport(
        overall_score=0.2,
        gaps=["LLM06 not covered"],
        recommendation=Recommendation.RE_RESEARCH,
        re_research_tasks=[_task(FocusArea.DATA_LEAKAGE, task_id="task-redo")],
    )
    # A 'no' is queued: it must NOT be consumed because the gate is bypassed.
    llm = _FakeLLM(
        [json.dumps(_surface_payload(name="Data Leakage", owasp="LLM06"))],
        relevance_responses=["no - would normally be skipped"],
    )

    out = await AnalystAgent(llm=llm).run(
        _state(plan=plan, findings=findings, iteration_count=2, critic_report=critic),
    )

    assert len(out["threat_surfaces"]) == 1
    assert out["threat_surfaces"][0].name == "Data Leakage"
    assert llm.relevance_responses == ["no - would normally be skipped"], (
        "gate must not even be consulted for critic-demanded focus areas"
    )


async def test_analyst_gate_prompt_tolerates_weak_evidence() -> None:
    """The gate must only reject unrelated domains, not thin evidence."""
    plan = [_task(FocusArea.INJECTION, task_id="task-inj")]
    findings = _strong_findings("task-inj")
    llm = _FakeLLM([json.dumps(_surface_payload())])

    agent = AnalystAgent(llm=llm)
    await agent.run(_state(plan=plan, findings=findings))

    gate_prompt = next(c for c in llm.calls if "You gate the Analyst" in c)
    assert "unrelated domain" in gate_prompt
    assert "NOT a reason to answer no" in gate_prompt
    assert "When in doubt, answer yes" in gate_prompt


async def test_analyst_gate_failure_falls_back_to_keeping_group() -> None:
    """A gate LLM failure must NOT silently drop the surface."""
    plan = [_task(FocusArea.INJECTION, task_id="task-inj")]
    findings = _strong_findings("task-inj")

    llm = _FakeLLM(
        [json.dumps(_surface_payload(name="Prompt Injection"))],
    )

    original_ainvoke = llm.ainvoke
    gate_calls = {"n": 0}

    async def flaky_ainvoke(prompt: str, **kw: Any) -> Any:
        if "You gate the Analyst" in prompt:
            gate_calls["n"] += 1
            raise RuntimeError("rate limited on gate")
        return await original_ainvoke(prompt, **kw)

    llm.ainvoke = flaky_ainvoke  # type: ignore[method-assign]
    out = await AnalystAgent(llm=llm).run(_state(plan=plan, findings=findings))

    assert gate_calls["n"] == 1
    assert len(out["threat_surfaces"]) == 1


async def test_analyst_gate_runs_once_per_focus_group() -> None:
    """One gate call per focus_area, not one per finding."""
    plan = [
        _task(FocusArea.INJECTION, task_id="task-inj"),
        _task(FocusArea.DATA_LEAKAGE, task_id="task-leak"),
    ]
    findings = [
        *_strong_findings("task-inj"),
        *_strong_findings("task-leak"),
    ]
    llm = _FakeLLM(
        [
            json.dumps(_surface_payload(name="Prompt Injection")),
            json.dumps(_surface_payload(name="Data Leakage", severity="medium")),
        ],
    )

    await AnalystAgent(llm=llm).run(_state(plan=plan, findings=findings))

    gate_prompts = [p for p in llm.calls if "You gate the Analyst" in p]
    assert len(gate_prompts) == 2


def test_analyst_helpers_downgrade_severity() -> None:
    """Direct unit test on the band ordering."""
    from nexus.agents.analyst import _downgrade_severity
    from nexus.schemas.models import Severity

    assert _downgrade_severity(Severity.CRITICAL) == Severity.HIGH
    assert _downgrade_severity(Severity.HIGH) == Severity.MEDIUM
    assert _downgrade_severity(Severity.MEDIUM) == Severity.LOW
    assert _downgrade_severity(Severity.LOW) == Severity.LOW
