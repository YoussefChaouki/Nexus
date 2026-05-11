"""Tests for the Writer agent.

EpisodicMemory is mocked with :class:`unittest.mock.AsyncMock` so the
tests never touch Postgres. The embed function is a no-op returning a
1536-dim zero vector so the schema's dimension check is satisfied.
"""

from __future__ import annotations

import time
from typing import cast
from unittest.mock import AsyncMock

import pytest
from langchain_core.messages import AIMessage, HumanMessage

from nexus.agents.writer import WriterAgent
from nexus.exceptions import AgentError, MemoryLayerError
from nexus.schemas.models import (
    AgentState,
    CriticReport,
    FindingResult,
    FocusArea,
    Priority,
    Recommendation,
    ResearchTask,
    Severity,
    SourceType,
    ThreatReportSummary,
    ThreatSurface,
)

# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


def _finding(
    task_id: str,
    ident: str = "arxiv:1",
    *,
    source: SourceType = SourceType.ARXIV,
) -> FindingResult:
    return FindingResult(
        task_id=task_id,
        source_type=source,
        title="Some paper",
        summary="A summary that is long enough to satisfy the validator.",
        relevance_score=0.7,
        identifiers=[ident],
    )


def _surface(name: str, severity: Severity, vectors: list[str]) -> ThreatSurface:
    return ThreatSurface(
        name=name,
        description=f"{name} description that exceeds the 30-character minimum.",
        severity=severity,
        attack_vectors=vectors,
        evidence=[_finding("task-1")],
        mitigations=["validate inputs"],
    )


def _critic(score: float = 0.85) -> CriticReport:
    return CriticReport(
        overall_score=score,
        gaps=[],
        recommendation=Recommendation.APPROVE,
    )


def _task(focus: FocusArea = FocusArea.INJECTION) -> ResearchTask:
    return ResearchTask(
        description="Investigate an attack surface against the target.",
        focus_area=focus,
        priority=Priority.HIGH,
    )


def _state(
    *,
    surfaces: list[ThreatSurface] | None,
    critic: CriticReport | None,
    plan: list[ResearchTask] | None = None,
    iteration_count: int = 1,
    findings: list[FindingResult] | None = None,
    messages: list | None = None,
    session_start_time: float | None = None,
) -> AgentState:
    return cast(
        AgentState,
        {
            "messages": messages if messages is not None else [],
            "target_description": "FastAPI + pgvector RAG",
            "session_id": "test-writer",
            "plan": plan or [_task(), _task(FocusArea.SUPPLY_CHAIN)],
            "findings": findings if findings is not None else [_finding("task-1")],
            "threat_surfaces": surfaces or [],
            "critic_report": critic,
            "threat_report": None,
            "iteration_count": iteration_count,
            "should_continue": True,
            "session_start_time": (
                session_start_time if session_start_time is not None else time.time()
            ),
        },
    )


async def _embed(_text: str) -> list[float]:
    return [0.0] * 1536


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------


async def test_writer_assembles_threat_report() -> None:
    surfaces = [
        _surface("Prompt Injection", Severity.HIGH, ["direct injection", "jailbreak"]),
        _surface("Data Leakage", Severity.MEDIUM, ["log scraping"]),
    ]
    state = _state(surfaces=surfaces, critic=_critic())
    agent = WriterAgent()

    out = await agent.run(state)

    report = out["threat_report"]
    assert report is not None
    assert report.target_description == state["target_description"]
    assert len(report.threat_surfaces) == 2
    assert report.critic_report.overall_score == 0.85
    assert report.iteration_count == 1
    assert report.metadata["surface_count"] == 2
    assert report.metadata["finding_count"] == 1


async def test_metadata_contains_token_count() -> None:
    surfaces = [_surface("Prompt Injection", Severity.HIGH, ["x"])]
    messages = [
        HumanMessage(content="Analyse the architecture for prompt injection risks."),
        AIMessage(content="Identified two attack vectors in the RAG retrieval layer."),
    ]
    state = _state(surfaces=surfaces, critic=_critic(), messages=messages)

    out = await WriterAgent().run(state)
    assert out["threat_report"].metadata["total_tokens"] > 0  # type: ignore[union-attr]


async def test_metadata_token_count_zero_for_empty_messages() -> None:
    surfaces = [_surface("Prompt Injection", Severity.HIGH, ["x"])]
    state = _state(surfaces=surfaces, critic=_critic(), messages=[])

    out = await WriterAgent().run(state)
    assert out["threat_report"].metadata["total_tokens"] == 0  # type: ignore[union-attr]


async def test_metadata_contains_cost() -> None:
    surfaces = [_surface("Prompt Injection", Severity.HIGH, ["x"])]
    # ~ a few hundred tokens of content guarantees a non-zero cost.
    messages = [
        HumanMessage(content="Describe prompt injection threats. " * 40),
        AIMessage(content="Here is a detailed answer with attack vectors. " * 40),
    ]
    state = _state(surfaces=surfaces, critic=_critic(), messages=messages)

    out = await WriterAgent().run(state)
    metadata = out["threat_report"].metadata  # type: ignore[union-attr]
    assert metadata["estimated_cost_usd"] > 0.0
    # GPT-4o pricing: input $5/1M, output $15/1M with 70/30 split → $8/1M average.
    expected = metadata["total_tokens"] * 8.0 / 1_000_000
    assert metadata["estimated_cost_usd"] == pytest.approx(expected, rel=1e-3)


async def test_metadata_contains_latency() -> None:
    surfaces = [_surface("Prompt Injection", Severity.HIGH, ["x"])]
    # session_start_time well in the past so latency is clearly > 0.
    state = _state(
        surfaces=surfaces,
        critic=_critic(),
        session_start_time=time.time() - 1.5,
    )

    out = await WriterAgent().run(state)
    latency = out["threat_report"].metadata["latency_seconds"]  # type: ignore[union-attr]
    assert latency >= 1.5
    assert latency < 60  # sanity ceiling


async def test_metadata_latency_zero_when_session_start_time_unset() -> None:
    surfaces = [_surface("Prompt Injection", Severity.HIGH, ["x"])]
    state = _state(surfaces=surfaces, critic=_critic(), session_start_time=0.0)

    out = await WriterAgent().run(state)
    assert out["threat_report"].metadata["latency_seconds"] == 0.0  # type: ignore[union-attr]


async def test_metadata_source_breakdown() -> None:
    surfaces = [_surface("Prompt Injection", Severity.HIGH, ["x"])]
    findings = [
        _finding("task-1", "arxiv:1", source=SourceType.ARXIV),
        _finding("task-1", "arxiv:2", source=SourceType.ARXIV),
        _finding("task-1", "cve-1", source=SourceType.NVD),
        _finding("task-1", "atlas-1", source=SourceType.ATLAS),
        _finding("task-1", "atlas-2", source=SourceType.ATLAS),
        _finding("task-1", "atlas-3", source=SourceType.ATLAS),
    ]
    state = _state(surfaces=surfaces, critic=_critic(), findings=findings)

    out = await WriterAgent().run(state)
    breakdown = out["threat_report"].metadata["source_breakdown"]  # type: ignore[union-attr]
    assert breakdown == {"arxiv": 2, "nvd": 1, "atlas": 3, "web": 0}


async def test_episodic_memory_persisted() -> None:
    surfaces = [_surface("Prompt Injection", Severity.HIGH, ["x"])]
    state = _state(surfaces=surfaces, critic=_critic())
    memory = AsyncMock()
    memory.store = AsyncMock()
    agent = WriterAgent(episodic_memory=memory, embed_fn=_embed)

    await agent.run(state)
    memory.store.assert_awaited_once()


async def test_missing_episodic_memory_doesnt_raise() -> None:
    surfaces = [_surface("Prompt Injection", Severity.HIGH, ["x"])]
    state = _state(surfaces=surfaces, critic=_critic())
    agent = WriterAgent(episodic_memory=None, embed_fn=None)

    out = await agent.run(state)
    assert out["threat_report"] is not None


async def test_writer_persists_summary_via_episodic_memory() -> None:
    surfaces = [
        _surface("Prompt Injection", Severity.CRITICAL, ["direct injection"]),
        _surface("Supply Chain", Severity.HIGH, ["dependency confusion"]),
    ]
    state = _state(surfaces=surfaces, critic=_critic(0.9))

    memory = AsyncMock()
    memory.store = AsyncMock()
    agent = WriterAgent(episodic_memory=memory, embed_fn=_embed)

    out = await agent.run(state)

    memory.store.assert_awaited_once()
    summary, embedding = memory.store.call_args.args
    assert isinstance(summary, ThreatReportSummary)
    assert summary.surface_count == 2
    assert summary.severity_breakdown["critical"] == 1
    assert summary.severity_breakdown["high"] == 1
    assert summary.severity_breakdown["medium"] == 0
    assert summary.severity_breakdown["low"] == 0
    assert summary.overall_critic_score == 0.9
    assert FocusArea.INJECTION in summary.focus_areas_covered
    assert summary.id == out["threat_report"].id  # type: ignore[union-attr]
    assert len(embedding) == 1536


async def test_writer_top_attack_vectors_capped_at_five() -> None:
    surfaces = [_surface(f"Surface {i}", Severity.HIGH, [f"vector_{i}"] * 3) for i in range(8)]
    state = _state(surfaces=surfaces, critic=_critic())
    memory = AsyncMock()
    memory.store = AsyncMock()
    agent = WriterAgent(episodic_memory=memory, embed_fn=_embed)

    await agent.run(state)
    summary, _ = memory.store.call_args.args
    assert len(summary.top_attack_vectors) <= 5


async def test_writer_missing_critic_report_raises() -> None:
    surfaces = [_surface("Prompt Injection", Severity.HIGH, ["x"])]
    state = _state(surfaces=surfaces, critic=None)
    with pytest.raises(AgentError, match="CriticReport"):
        await WriterAgent().run(state)


async def test_writer_no_threat_surfaces_raises() -> None:
    state = _state(surfaces=[], critic=_critic())
    with pytest.raises(AgentError, match="ThreatSurface"):
        await WriterAgent().run(state)


async def test_writer_episodic_store_failure_does_not_abort() -> None:
    surfaces = [_surface("Prompt Injection", Severity.HIGH, ["x"])]
    state = _state(surfaces=surfaces, critic=_critic())

    memory = AsyncMock()
    memory.store = AsyncMock(side_effect=MemoryLayerError("db down"))
    agent = WriterAgent(episodic_memory=memory, embed_fn=_embed)

    # Storage failure logged, ThreatReport still returned.
    out = await agent.run(state)
    assert out["threat_report"] is not None


async def test_writer_episodic_unexpected_error_does_not_abort() -> None:
    surfaces = [_surface("Prompt Injection", Severity.HIGH, ["x"])]
    state = _state(surfaces=surfaces, critic=_critic())

    memory = AsyncMock()
    memory.store = AsyncMock(side_effect=RuntimeError("wat"))
    agent = WriterAgent(episodic_memory=memory, embed_fn=_embed)

    out = await agent.run(state)
    assert out["threat_report"] is not None


async def test_writer_skips_persistence_when_memory_missing() -> None:
    surfaces = [_surface("Prompt Injection", Severity.HIGH, ["x"])]
    state = _state(surfaces=surfaces, critic=_critic())
    agent = WriterAgent()  # no memory

    out = await agent.run(state)

    assert out["threat_report"] is not None  # no persistence attempted, no crash


async def test_writer_iteration_count_floored_at_one() -> None:
    surfaces = [_surface("Prompt Injection", Severity.HIGH, ["x"])]
    state = _state(surfaces=surfaces, critic=_critic(), iteration_count=0)
    out = await WriterAgent().run(state)
    assert out["threat_report"].iteration_count == 1  # type: ignore[union-attr]


async def test_writer_focus_areas_deduplicated_in_summary_order() -> None:
    surfaces = [_surface("Prompt Injection", Severity.HIGH, ["x"])]
    plan = [
        _task(FocusArea.INJECTION),
        _task(FocusArea.SUPPLY_CHAIN),
        _task(FocusArea.INJECTION),  # dup
    ]
    state = _state(surfaces=surfaces, critic=_critic(), plan=plan)
    memory = AsyncMock()
    memory.store = AsyncMock()
    agent = WriterAgent(episodic_memory=memory, embed_fn=_embed)

    await agent.run(state)
    summary, _ = memory.store.call_args.args
    assert summary.focus_areas_covered == [FocusArea.INJECTION, FocusArea.SUPPLY_CHAIN]
