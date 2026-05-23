"""Tests for the Researcher agent.

The MCP layer is replaced by a hand-rolled fake that returns canned JSON
per ``(server_name, tool_name)`` pair. The LLM relevance scorer is also
injected so tests are deterministic and never touch the network.
"""

from __future__ import annotations

import json
from typing import Any, cast

import pytest

from nexus.agents.researcher import ResearcherAgent
from nexus.exceptions import AgentError, MCPClientError
from nexus.schemas.models import (
    AgentState,
    CriticReport,
    FindingResult,
    FocusArea,
    Priority,
    Recommendation,
    ResearchTask,
    SourceType,
)

# --------------------------------------------------------------------------
# Fixture data
# --------------------------------------------------------------------------


def _arxiv_papers(arxiv_id: str = "2401.12345v1") -> list[dict[str, Any]]:
    return [
        {
            "arxiv_id": arxiv_id,
            "title": "Prompt Injection Survey",
            "authors": ["Alice"],
            "abstract": (
                "A comprehensive survey of prompt injection vectors against "
                "LLM applications and proposed defences."
            ),
            "published": "2024-01-22",
            "url": f"http://arxiv.org/abs/{arxiv_id}",
            "categories": ["cs.CR"],
        },
    ]


def _nvd_cves() -> list[dict[str, Any]]:
    return [
        {
            "cve_id": "CVE-2024-12345",
            "description": "Buffer overflow in foo allows remote code execution.",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "published_date": "2024-01-15",
            "last_modified_date": "2024-02-01",
            "affected_products": [],
            "references": ["https://example.com/advisory/1"],
        },
    ]


def _atlas_techniques() -> list[dict[str, Any]]:
    return [
        {
            "technique_id": "AML.T0051",
            "name": "Prompt Injection",
            "description": (
                "Adversaries craft inputs that override system instructions in an LLM."
            ),
            "tactic": "ml-attack-staging",
            "subtechniques": [],
            "case_studies": [],
            "mitigations": [],
            "url": "https://atlas.mitre.org/techniques/AML.T0051",
        },
    ]


# --------------------------------------------------------------------------
# Fakes & helpers
# --------------------------------------------------------------------------


class FakeMCPClient:
    """Minimal MCPClient stand-in. Returns canned JSON per (server, tool)."""

    def __init__(
        self,
        responses: dict[tuple[str, str], str] | None = None,
        errors: dict[tuple[str, str], MCPClientError] | None = None,
    ) -> None:
        self.responses = responses or {}
        self.errors = errors or {}
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    async def call_tool(
        self,
        server_name: str,
        tool_name: str,
        **kwargs: Any,
    ) -> str:
        self.calls.append((server_name, tool_name, kwargs))
        key = (server_name, tool_name)
        if key in self.errors:
            raise self.errors[key]
        return self.responses.get(key, "[]")

    async def aclose(self) -> None:
        return None


def _all_three_responses() -> dict[tuple[str, str], str]:
    return {
        ("arxiv", "search_papers"): json.dumps(_arxiv_papers()),
        ("nvd", "search_cves"): json.dumps(_nvd_cves()),
        ("atlas", "search_techniques"): json.dumps(_atlas_techniques()),
    }


def _make_task(focus: FocusArea, query: str = "prompt injection") -> ResearchTask:
    return ResearchTask(
        description=f"Investigate {focus.value} for the target architecture.",
        focus_area=focus,
        priority=Priority.HIGH,
        search_queries=[query],
    )


def _state(
    *,
    plan: list[ResearchTask],
    findings: list[FindingResult] | None = None,
    iteration_count: int = 0,
    critic_report: CriticReport | None = None,
) -> AgentState:
    return cast(
        AgentState,
        {
            "messages": [],
            "target_description": "FastAPI + pgvector RAG",
            "session_id": "test-researcher",
            "plan": plan,
            "findings": findings or [],
            "threat_surfaces": [],
            "critic_report": critic_report,
            "threat_report": None,
            "iteration_count": iteration_count,
            "should_continue": True,
        },
    )


async def _fixed_score(_task: ResearchTask, _finding: FindingResult) -> float:
    return 0.75


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------


async def test_first_run_researches_all_plan_tasks() -> None:
    plan = [
        _make_task(FocusArea.INJECTION, "prompt injection"),
        _make_task(FocusArea.SUPPLY_CHAIN, "supply chain"),
    ]
    fake = FakeMCPClient(responses=_all_three_responses())
    agent = ResearcherAgent(mcp_client=fake, scoring_fn=_fixed_score)

    out = await agent.run(_state(plan=plan))

    # 2 tasks × 3 MCP servers = 6 calls
    assert len(fake.calls) == 6
    servers_called = {(s, t) for s, t, _ in fake.calls}
    assert servers_called == {
        ("arxiv", "search_papers"),
        ("nvd", "search_cves"),
        ("atlas", "search_techniques"),
    }
    # 1 finding per server per task → 6, but dedup collapses identical
    # arxiv/nvd/atlas IDs across the two tasks → 3 unique findings.
    assert len(out["findings"]) == 3


async def test_re_research_uses_critic_tasks_only() -> None:
    plan = [_make_task(FocusArea.INJECTION)]
    re_research = [_make_task(FocusArea.DENIAL_OF_SERVICE, "denial of service")]
    critic = CriticReport(
        overall_score=0.4,
        gaps=["denial of service coverage"],
        recommendation=Recommendation.RE_RESEARCH,
        re_research_tasks=re_research,
    )
    fake = FakeMCPClient(responses=_all_three_responses())
    agent = ResearcherAgent(mcp_client=fake, scoring_fn=_fixed_score)

    state = _state(plan=plan, iteration_count=1, critic_report=critic)
    out = await agent.run(state)

    # Only the re_research task should have been researched (1 task × 3 MCPs).
    assert len(fake.calls) == 3
    # Every call should reference the re-research task's id, not the plan task.
    for _, _, kwargs in fake.calls:
        query = kwargs.get("query") or kwargs.get("keyword")
        assert query == "denial of service"
    assert out["iteration_count"] == 2


async def test_iteration_count_is_incremented_on_first_run() -> None:
    plan = [_make_task(FocusArea.INJECTION)]
    fake = FakeMCPClient(responses=_all_three_responses())
    agent = ResearcherAgent(mcp_client=fake, scoring_fn=_fixed_score)

    out = await agent.run(_state(plan=plan, iteration_count=0))

    assert out["iteration_count"] == 1


async def test_findings_are_cumulative_across_iterations() -> None:
    plan = [_make_task(FocusArea.INJECTION)]
    re_research = [_make_task(FocusArea.DATA_LEAKAGE, "data leakage")]
    critic = CriticReport(
        overall_score=0.4,
        gaps=["data leakage"],
        recommendation=Recommendation.RE_RESEARCH,
        re_research_tasks=re_research,
    )

    # Pre-seed findings as if iteration 1 already ran.
    pre_existing = FindingResult(
        task_id=plan[0].id,
        source_type=SourceType.ARXIV,
        title="Earlier paper",
        summary="An earlier finding from the first iteration of research.",
        relevance_score=0.8,
        identifiers=["arxiv:9999.99999"],
    )

    fake = FakeMCPClient(
        responses={
            ("arxiv", "search_papers"): json.dumps(_arxiv_papers("2402.00001")),
            ("nvd", "search_cves"): "[]",
            ("atlas", "search_techniques"): "[]",
        },
    )
    agent = ResearcherAgent(mcp_client=fake, scoring_fn=_fixed_score)
    state = _state(
        plan=plan,
        findings=[pre_existing],
        iteration_count=1,
        critic_report=critic,
    )
    out = await agent.run(state)

    ids = {ident for f in out["findings"] for ident in f.identifiers}
    assert "arxiv:9999.99999" in ids
    assert "arxiv:2402.00001" in ids


async def test_partial_mcp_failure_does_not_abort_run() -> None:
    plan = [_make_task(FocusArea.INJECTION)]
    fake = FakeMCPClient(
        responses={
            ("arxiv", "search_papers"): json.dumps(_arxiv_papers()),
            ("atlas", "search_techniques"): json.dumps(_atlas_techniques()),
        },
        errors={
            ("nvd", "search_cves"): MCPClientError("nvd is on fire"),
        },
    )
    agent = ResearcherAgent(mcp_client=fake, scoring_fn=_fixed_score)

    out = await agent.run(_state(plan=plan))

    sources = {f.source_type for f in out["findings"]}
    assert SourceType.ARXIV in sources
    assert SourceType.ATLAS in sources
    assert SourceType.NVD not in sources


async def test_dedup_same_arxiv_id_across_tasks() -> None:
    plan = [
        _make_task(FocusArea.INJECTION, "injection"),
        _make_task(FocusArea.OTHER, "other"),
    ]
    # Same arxiv_id returned for both tasks.
    fake = FakeMCPClient(
        responses={
            ("arxiv", "search_papers"): json.dumps(_arxiv_papers("2401.99999")),
            ("nvd", "search_cves"): "[]",
            ("atlas", "search_techniques"): "[]",
        },
    )
    agent = ResearcherAgent(mcp_client=fake, scoring_fn=_fixed_score)

    out = await agent.run(_state(plan=plan))

    arxiv_findings = [f for f in out["findings"] if f.source_type == SourceType.ARXIV]
    assert len(arxiv_findings) == 1


async def test_zero_findings_raises_agent_error() -> None:
    plan = [_make_task(FocusArea.INJECTION)]
    fake = FakeMCPClient(
        responses={
            ("arxiv", "search_papers"): "[]",
            ("nvd", "search_cves"): "[]",
            ("atlas", "search_techniques"): "[]",
        },
    )
    agent = ResearcherAgent(mcp_client=fake, scoring_fn=_fixed_score)

    with pytest.raises(AgentError, match="zero findings"):
        await agent.run(_state(plan=plan))


async def test_no_tasks_raises_agent_error() -> None:
    fake = FakeMCPClient()
    agent = ResearcherAgent(mcp_client=fake, scoring_fn=_fixed_score)

    with pytest.raises(AgentError, match="no research tasks"):
        await agent.run(_state(plan=[]))


async def test_invalid_json_response_is_skipped() -> None:
    plan = [_make_task(FocusArea.INJECTION)]
    fake = FakeMCPClient(
        responses={
            ("arxiv", "search_papers"): json.dumps(_arxiv_papers()),
            ("nvd", "search_cves"): "not valid json",
            ("atlas", "search_techniques"): "[]",
        },
    )
    agent = ResearcherAgent(mcp_client=fake, scoring_fn=_fixed_score)

    out = await agent.run(_state(plan=plan))

    assert all(f.source_type == SourceType.ARXIV for f in out["findings"])


async def test_scoring_fn_is_applied_to_each_finding() -> None:
    plan = [_make_task(FocusArea.INJECTION)]
    fake = FakeMCPClient(responses=_all_three_responses())

    seen: list[tuple[str, str]] = []

    async def custom_score(task: ResearchTask, finding: FindingResult) -> float:
        seen.append((task.id, finding.source_type.value))
        return 0.72

    agent = ResearcherAgent(mcp_client=fake, scoring_fn=custom_score)

    out = await agent.run(_state(plan=plan))

    assert all(f.relevance_score == 0.72 for f in out["findings"])
    assert {entry[1] for entry in seen} == {"arxiv", "nvd", "atlas"}


async def test_re_research_without_critic_report_raises() -> None:
    plan = [_make_task(FocusArea.INJECTION)]
    fake = FakeMCPClient()
    agent = ResearcherAgent(mcp_client=fake, scoring_fn=_fixed_score)

    state = _state(plan=plan, iteration_count=2, critic_report=None)
    with pytest.raises(AgentError, match="no research tasks"):
        await agent.run(state)


async def test_non_list_json_payload_is_skipped() -> None:
    """An MCP server that returns a JSON object (not a list) is treated as empty."""
    plan = [_make_task(FocusArea.INJECTION)]
    fake = FakeMCPClient(
        responses={
            ("arxiv", "search_papers"): json.dumps({"unexpected": "shape"}),
            ("nvd", "search_cves"): "[]",
            ("atlas", "search_techniques"): json.dumps(_atlas_techniques()),
        },
    )
    agent = ResearcherAgent(mcp_client=fake, scoring_fn=_fixed_score)

    out = await agent.run(_state(plan=plan))

    assert all(f.source_type != SourceType.ARXIV for f in out["findings"])


async def test_scoring_fn_exception_falls_back_to_default_score() -> None:
    plan = [_make_task(FocusArea.INJECTION)]
    fake = FakeMCPClient(responses=_all_three_responses())

    async def broken_score(_t: ResearchTask, _f: FindingResult) -> float:
        raise RuntimeError("scoring is down")

    agent = ResearcherAgent(mcp_client=fake, scoring_fn=broken_score)

    out = await agent.run(_state(plan=plan))

    assert all(f.relevance_score == 0.5 for f in out["findings"])


async def test_default_score_returns_05_when_llm_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The default scorer must degrade to 0.5 when the LLM is unreachable."""
    from nexus.agents import researcher as researcher_module

    def fail_get_llm(self: Any) -> Any:
        raise RuntimeError("no llm in tests")

    monkeypatch.setattr(researcher_module.AgentBase, "_get_llm", fail_get_llm)

    agent = ResearcherAgent(mcp_client=FakeMCPClient())
    task = _make_task(FocusArea.INJECTION)
    finding = FindingResult(
        task_id=task.id,
        source_type=SourceType.ARXIV,
        title="x",
        summary="A summary that is long enough to satisfy the validator.",
        relevance_score=0.0,
        identifiers=["arxiv:1"],
    )

    score = await agent._default_score(task, finding)

    assert score == 0.5


async def test_findings_below_min_relevance_are_dropped() -> None:
    """LLM-scored relevance below settings.researcher_min_relevance must be dropped."""
    plan = [_make_task(FocusArea.INJECTION)]
    fake = FakeMCPClient(responses=_all_three_responses())

    async def low_score(_t: ResearchTask, _f: FindingResult) -> float:
        return 0.1  # below default 0.5

    agent = ResearcherAgent(mcp_client=fake, scoring_fn=low_score)
    with pytest.raises(AgentError, match="zero findings"):
        await agent.run(_state(plan=plan))


async def test_settings_knob_changes_relevance_threshold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Lowering researcher_min_relevance keeps findings that would otherwise be dropped."""
    from nexus.settings import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "researcher_min_relevance", 0.05)

    plan = [_make_task(FocusArea.INJECTION)]
    fake = FakeMCPClient(responses=_all_three_responses())

    async def low_score(_t: ResearchTask, _f: FindingResult) -> float:
        return 0.1

    agent = ResearcherAgent(mcp_client=fake, scoring_fn=low_score)
    out = await agent.run(_state(plan=plan))

    assert len(out["findings"]) >= 1


async def test_off_topic_findings_dropped_by_context_relevance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The M-Banking-on-RAG regression: cosine sim below threshold must be rejected."""
    from nexus.settings import get_settings

    monkeypatch.setattr(get_settings(), "researcher_min_context_relevance", 0.5)

    plan = [_make_task(FocusArea.INJECTION)]
    fake = FakeMCPClient(responses=_all_three_responses())

    # Embed target as one vector and findings as an orthogonal vector → cosine=0.
    async def orthogonal_embed(text: str) -> list[float]:
        if "FastAPI" in text or "pgvector" in text or "RAG" in text:
            return [1.0, 0.0, 0.0]
        return [0.0, 1.0, 0.0]

    agent = ResearcherAgent(
        mcp_client=fake,
        scoring_fn=_fixed_score,
        embed_fn=orthogonal_embed,
    )
    with pytest.raises(AgentError, match="zero findings"):
        await agent.run(_state(plan=plan))


async def test_on_topic_findings_kept_by_context_relevance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cosine sim above threshold lets the finding through the context gate."""
    from nexus.settings import get_settings

    monkeypatch.setattr(get_settings(), "researcher_min_context_relevance", 0.5)

    plan = [_make_task(FocusArea.INJECTION)]
    fake = FakeMCPClient(responses=_all_three_responses())

    async def aligned_embed(_text: str) -> list[float]:
        return [1.0, 0.0, 0.0]  # always the same vector → cosine=1.0

    agent = ResearcherAgent(
        mcp_client=fake,
        scoring_fn=_fixed_score,
        embed_fn=aligned_embed,
    )
    out = await agent.run(_state(plan=plan))

    assert len(out["findings"]) >= 1


async def test_embed_failure_keeps_findings() -> None:
    """A broken embed_fn must NOT drop findings — pipeline never aborts on observability."""
    plan = [_make_task(FocusArea.INJECTION)]
    fake = FakeMCPClient(responses=_all_three_responses())

    async def broken_embed(_text: str) -> list[float]:
        raise RuntimeError("openai is on fire")

    agent = ResearcherAgent(
        mcp_client=fake,
        scoring_fn=_fixed_score,
        embed_fn=broken_embed,
    )
    out = await agent.run(_state(plan=plan))

    assert len(out["findings"]) >= 1


async def test_short_summary_findings_are_filtered() -> None:
    """Items whose summary is shorter than 20 chars must not become FindingResults."""
    plan = [_make_task(FocusArea.INJECTION)]
    fake = FakeMCPClient(
        responses={
            ("arxiv", "search_papers"): json.dumps(
                [
                    {
                        "arxiv_id": "2401.short",
                        "title": "S",
                        "authors": [],
                        "abstract": "tiny",  # < 20 chars
                        "published": "2024",
                        "url": "",
                        "categories": [],
                    },
                ],
            ),
            ("nvd", "search_cves"): "[]",
            ("atlas", "search_techniques"): json.dumps(_atlas_techniques()),
        },
    )
    agent = ResearcherAgent(mcp_client=fake, scoring_fn=_fixed_score)

    out = await agent.run(_state(plan=plan))

    sources = {f.source_type for f in out["findings"]}
    assert SourceType.ARXIV not in sources
    assert SourceType.ATLAS in sources
