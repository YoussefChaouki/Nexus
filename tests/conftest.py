"""Shared pytest fixtures for the NEXUS test suite.

The factories here are the canonical way to build NEXUS data objects in
tests. New tests should prefer ``sample_findings`` / ``sample_threat_*``
over hand-rolled literals so changes to the schemas propagate uniformly.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Generator
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest


@pytest.fixture(autouse=True, scope="session")
def _test_env() -> Generator[None, None, None]:
    """Set minimum required env vars so Settings() can be instantiated in tests."""
    os.environ.setdefault("OPENAI_API_KEY", "sk-test-00000000000000000000000000000000")
    os.environ.setdefault("LANGFUSE_PUBLIC_KEY", "pk-lf-test")
    os.environ.setdefault("LANGFUSE_SECRET_KEY", "sk-lf-test")

    import nexus.settings as _mod

    _mod._settings = None  # reset module-level cache so tests pick up env vars
    yield


# ---------------------------------------------------------------------------
# Infrastructure mocks — LLM, Redis, Postgres
# ---------------------------------------------------------------------------


class _RouterLLM:
    """Async LLM mock that routes prompts to substring-matched responses.

    Configure with ``mock_llm.set("substring", "response")``; ``ainvoke``
    returns the first match whose substring appears in the prompt. The
    default ``"<<unmocked>>"`` response makes accidental real calls
    immediately visible in test output.
    """

    def __init__(self) -> None:
        self._routes: list[tuple[str, str]] = []
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def set(self, substring: str, response: str) -> None:
        self._routes.append((substring, response))

    async def ainvoke(self, prompt: str, config: dict[str, Any] | None = None) -> MagicMock:
        self.calls.append((prompt, config or {}))
        for needle, payload in self._routes:
            if needle in prompt:
                return MagicMock(content=payload)
        return MagicMock(content="<<unmocked>>")


@pytest.fixture()
def mock_llm() -> _RouterLLM:
    """Async LLM whose responses are addressed by substring matching."""
    return _RouterLLM()


@pytest.fixture()
async def mock_redis() -> Any:
    """In-process Redis double via fakeredis — async API."""
    from fakeredis.aioredis import FakeRedis

    client = FakeRedis()
    try:
        yield client
    finally:
        await client.aclose()


def _make_asyncpg_pool(rows: list[dict[str, Any]] | None = None) -> Any:
    """Build a MagicMock asyncpg-style pool returning ``rows`` from .fetch()."""
    conn = MagicMock()
    conn.fetch = AsyncMock(return_value=list(rows or []))
    conn.fetchrow = AsyncMock(return_value=(rows or [None])[0])
    conn.execute = AsyncMock(return_value=None)
    transaction_cm = MagicMock()
    transaction_cm.__aenter__ = AsyncMock(return_value=None)
    transaction_cm.__aexit__ = AsyncMock(return_value=None)
    conn.transaction = MagicMock(return_value=transaction_cm)

    pool = MagicMock()
    acquire_cm = MagicMock()
    acquire_cm.__aenter__ = AsyncMock(return_value=conn)
    acquire_cm.__aexit__ = AsyncMock(return_value=None)
    pool.acquire = MagicMock(return_value=acquire_cm)
    return pool


@pytest.fixture()
def mock_asyncpg_pool() -> Callable[..., Any]:
    """Factory: ``mock_asyncpg_pool(rows=[...])`` returns a mock pool."""

    def _factory(rows: list[dict[str, Any]] | None = None) -> Any:
        return _make_asyncpg_pool(rows)

    return _factory


# ---------------------------------------------------------------------------
# Domain sample factories
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_research_tasks() -> Callable[..., list[Any]]:
    """Return a factory for a stable list of ``ResearchTask`` objects.

    Default returns 4 tasks (one per primary FocusArea) so callers can
    exercise the analyst grouping and re-research branching without
    redefining the plan.
    """
    from nexus.schemas.models import FocusArea, Priority, ResearchTask

    def _factory(count: int = 4) -> list[ResearchTask]:
        templates = [
            ("Investigate prompt-injection vectors in RAG retrieval.", FocusArea.INJECTION),
            ("Audit embeddings for PII leakage paths.", FocusArea.DATA_LEAKAGE),
            ("Survey supply-chain attacks against ML toolchains.", FocusArea.SUPPLY_CHAIN),
            ("Map denial-of-service vectors against model serving.", FocusArea.DENIAL_OF_SERVICE),
            (
                "Catalogue model-extraction techniques relevant to the target.",
                FocusArea.MODEL_EXTRACTION,
            ),
        ]
        return [
            ResearchTask(
                id=f"task-{i:02d}",
                description=desc,
                focus_area=focus,
                priority=Priority.HIGH if i < 2 else Priority.MEDIUM,
                search_queries=[desc.split(" ", 2)[0]],
            )
            for i, (desc, focus) in enumerate(templates[:count])
        ]

    return _factory


@pytest.fixture()
def sample_findings(sample_research_tasks: Callable[..., list[Any]]) -> Callable[..., list[Any]]:
    """Return a factory that builds a mixed-source list of ``FindingResult``.

    The default produces 10 findings spread across the four primary
    tasks emitted by ``sample_research_tasks`` and the three real
    ``SourceType`` values (arxiv, nvd, atlas).
    """
    from nexus.schemas.models import FindingResult, SourceType

    def _factory(count: int = 10) -> list[FindingResult]:
        tasks = sample_research_tasks()
        sources = [SourceType.ARXIV, SourceType.NVD, SourceType.ATLAS]
        out: list[FindingResult] = []
        for i in range(count):
            task = tasks[i % len(tasks)]
            source = sources[i % len(sources)]
            out.append(
                FindingResult(
                    id=f"finding-{i:02d}",
                    task_id=task.id,
                    source_type=source,
                    title=f"Finding {i:02d}",
                    summary=(
                        f"Synthetic finding {i:02d} attached to {task.focus_area.value}"
                        " for fixture use across tests."
                    ),
                    relevance_score=0.5 + (i % 5) * 0.1,
                    url=f"https://example.test/{source.value}/{i:02d}",
                    identifiers=[f"{source.value.upper()}-{i:04d}"],
                )
            )
        return out

    return _factory


@pytest.fixture()
def sample_threat_surfaces(sample_findings: Callable[..., list[Any]]) -> Callable[..., list[Any]]:
    """Return a factory that builds 3 ``ThreatSurface`` objects with evidence."""
    from nexus.schemas.models import Severity, ThreatSurface

    def _factory(count: int = 3) -> list[ThreatSurface]:
        findings = sample_findings()
        bucket_size = max(1, len(findings) // count)
        out: list[ThreatSurface] = []
        names = [
            ("Prompt Injection via RAG", Severity.HIGH, "LLM01"),
            ("Embedding-based PII leakage", Severity.MEDIUM, "LLM06"),
            ("Compromised model registry", Severity.CRITICAL, "LLM05"),
        ]
        for i in range(count):
            name, severity, owasp = names[i % len(names)]
            chunk = findings[i * bucket_size : (i + 1) * bucket_size] or findings[:1]
            out.append(
                ThreatSurface(
                    id=f"surface-{i:02d}",
                    name=name,
                    description=(
                        f"Synthetic threat surface {i} used by the conftest factory."
                        " It carries enough text to satisfy the 30-character min."
                    ),
                    severity=severity,
                    attack_vectors=[f"vector-{i}-a", f"vector-{i}-b"],
                    evidence=chunk,
                    mitigations=[f"mitigation-{i}-a"],
                    cvss_score=7.5,
                    owasp_category=owasp,
                )
            )
        return out

    return _factory


@pytest.fixture()
def sample_critic_approve() -> Callable[..., Any]:
    """Factory for a ``CriticReport`` with recommendation=APPROVE."""
    from nexus.schemas.models import CriticReport, Recommendation

    def _factory(score: float = 0.85) -> CriticReport:
        return CriticReport(
            overall_score=score,
            gaps=[],
            bias_warnings=[],
            recommendation=Recommendation.APPROVE,
            re_research_tasks=[],
        )

    return _factory


@pytest.fixture()
def sample_critic_re_research(
    sample_research_tasks: Callable[..., list[Any]],
) -> Callable[..., Any]:
    """Factory for a ``CriticReport`` with recommendation=RE_RESEARCH and 2 tasks."""
    from nexus.schemas.models import CriticReport, Recommendation

    def _factory(score: float = 0.3) -> CriticReport:
        return CriticReport(
            overall_score=score,
            gaps=["coverage missing for LLM06", "coverage missing for LLM10"],
            bias_warnings=["under-represented data leakage findings"],
            recommendation=Recommendation.RE_RESEARCH,
            re_research_tasks=sample_research_tasks(count=2),
        )

    return _factory


@pytest.fixture()
def sample_threat_report(
    sample_threat_surfaces: Callable[..., list[Any]],
    sample_critic_approve: Callable[..., Any],
) -> Callable[..., Any]:
    """Factory for a fully-populated ``ThreatReport``."""
    from nexus.schemas.models import ThreatReport

    def _factory(iteration_count: int = 1) -> ThreatReport:
        return ThreatReport(
            id="report-fixture-0001",
            target_description="FastAPI + pgvector RAG over OpenAI, no authentication.",
            created_at=datetime(2026, 5, 14, 12, 0, tzinfo=UTC),
            threat_surfaces=sample_threat_surfaces(),
            critic_report=sample_critic_approve(),
            iteration_count=iteration_count,
            metadata={
                "total_tokens": 1234,
                "estimated_cost_usd": 0.042,
                "latency_seconds": 12.5,
                "source_breakdown": {"arxiv": 3, "nvd": 4, "atlas": 3, "web": 0},
                "iteration_count": iteration_count,
                "finding_count": 10,
                "surface_count": 3,
            },
        )

    return _factory


# Re-export so static analysis sees the public surface.
__all__ = [
    "mock_asyncpg_pool",
    "mock_llm",
    "mock_redis",
    "sample_critic_approve",
    "sample_critic_re_research",
    "sample_findings",
    "sample_research_tasks",
    "sample_threat_report",
    "sample_threat_surfaces",
]
