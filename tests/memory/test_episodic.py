"""Tests for EpisodicMemory using mocked asyncpg pool."""

import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from nexus.exceptions import MemoryLayerError
from nexus.memory.episodic import _EMBEDDING_DIM, EpisodicMemory
from nexus.schemas.models import FocusArea, ThreatReportSummary


@pytest.fixture()
def sample_summary() -> ThreatReportSummary:
    return ThreatReportSummary(
        id="sum-001",
        session_id="sess-001",
        target_description="FastAPI + pgvector RAG, OpenAI API, no auth",
        created_at=datetime.now(UTC),
        surface_count=3,
        severity_breakdown={"critical": 1, "high": 2},
        focus_areas_covered=[FocusArea.INJECTION, FocusArea.DATA_LEAKAGE],
        top_attack_vectors=["prompt injection", "indirect injection"],
        overall_critic_score=0.82,
        iteration_count=1,
    )


@pytest.fixture()
def mock_pool() -> tuple[MagicMock, AsyncMock]:
    pool = MagicMock()
    conn = AsyncMock()
    ctx = AsyncMock()
    ctx.__aenter__ = AsyncMock(return_value=conn)
    ctx.__aexit__ = AsyncMock(return_value=None)
    pool.acquire.return_value = ctx
    return pool, conn


async def test_store_calls_execute(
    mock_pool: tuple[MagicMock, AsyncMock],
    sample_summary: ThreatReportSummary,
) -> None:
    pool, conn = mock_pool
    mem = EpisodicMemory(pool)
    embedding = [0.1] * _EMBEDDING_DIM
    await mem.store(sample_summary, embedding)
    conn.execute.assert_awaited_once()


async def test_store_raises_on_dimension_mismatch(
    mock_pool: tuple[MagicMock, AsyncMock],
    sample_summary: ThreatReportSummary,
) -> None:
    pool, _ = mock_pool
    mem = EpisodicMemory(pool)
    with pytest.raises(MemoryLayerError, match="dimension mismatch"):
        await mem.store(sample_summary, [0.1] * 128)


async def test_store_raises_memory_layer_error_on_db_failure(
    mock_pool: tuple[MagicMock, AsyncMock],
    sample_summary: ThreatReportSummary,
) -> None:
    pool, conn = mock_pool
    conn.execute.side_effect = RuntimeError("DB down")
    mem = EpisodicMemory(pool)
    with pytest.raises(MemoryLayerError):
        await mem.store(sample_summary, [0.1] * _EMBEDDING_DIM)


async def test_search_similar_returns_summaries(
    mock_pool: tuple[MagicMock, AsyncMock],
    sample_summary: ThreatReportSummary,
) -> None:
    pool, conn = mock_pool
    row = {
        "id": sample_summary.id,
        "session_id": sample_summary.session_id,
        "target_description": sample_summary.target_description,
        "created_at": sample_summary.created_at,
        "surface_count": sample_summary.surface_count,
        "severity_breakdown": json.dumps(sample_summary.severity_breakdown),
        "focus_areas_covered": json.dumps([f.value for f in sample_summary.focus_areas_covered]),
        "top_attack_vectors": json.dumps(sample_summary.top_attack_vectors),
        "overall_critic_score": sample_summary.overall_critic_score,
        "iteration_count": sample_summary.iteration_count,
    }
    conn.fetch.return_value = [row]
    mem = EpisodicMemory(pool)
    results = await mem.search_similar([0.1] * _EMBEDDING_DIM)
    assert len(results) == 1
    assert results[0].id == sample_summary.id


async def test_search_similar_returns_empty_on_db_error(
    mock_pool: tuple[MagicMock, AsyncMock],
) -> None:
    pool, conn = mock_pool
    conn.fetch.side_effect = RuntimeError("connection lost")
    mem = EpisodicMemory(pool)
    results = await mem.search_similar([0.1] * _EMBEDDING_DIM)
    assert results == []


async def test_get_by_id_returns_none_when_not_found(
    mock_pool: tuple[MagicMock, AsyncMock],
) -> None:
    pool, conn = mock_pool
    conn.fetchrow.return_value = None
    mem = EpisodicMemory(pool)
    result = await mem.get_by_id("missing-id")
    assert result is None


async def test_get_by_id_returns_summary(
    mock_pool: tuple[MagicMock, AsyncMock],
    sample_summary: ThreatReportSummary,
) -> None:
    pool, conn = mock_pool
    row = {
        "id": sample_summary.id,
        "session_id": sample_summary.session_id,
        "target_description": sample_summary.target_description,
        "created_at": sample_summary.created_at,
        "surface_count": sample_summary.surface_count,
        "severity_breakdown": json.dumps(sample_summary.severity_breakdown),
        "focus_areas_covered": json.dumps([f.value for f in sample_summary.focus_areas_covered]),
        "top_attack_vectors": json.dumps(sample_summary.top_attack_vectors),
        "overall_critic_score": sample_summary.overall_critic_score,
        "iteration_count": sample_summary.iteration_count,
    }
    conn.fetchrow.return_value = row
    mem = EpisodicMemory(pool)
    result = await mem.get_by_id(sample_summary.id)
    assert result is not None
    assert result.session_id == sample_summary.session_id
