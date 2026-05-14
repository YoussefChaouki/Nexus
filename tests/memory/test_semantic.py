"""Smoke tests for the read-only SemanticMemory layer."""

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from nexus.memory.semantic import SemanticMemory


def _pool_with_rows(rows: list[dict[str, Any]]) -> Any:
    """Build a mock asyncpg pool that yields ``rows`` from .fetch()."""
    conn = MagicMock()
    conn.fetch = AsyncMock(return_value=rows)
    pool = MagicMock()
    acquire_cm = MagicMock()
    acquire_cm.__aenter__ = AsyncMock(return_value=conn)
    acquire_cm.__aexit__ = AsyncMock(return_value=None)
    pool.acquire = MagicMock(return_value=acquire_cm)
    return pool


def test_store_raises_runtime_error() -> None:
    mem = SemanticMemory(pool=MagicMock())
    with pytest.raises(RuntimeError, match="read-only"):
        mem.store("anything")


async def test_search_patterns_returns_empty_on_db_failure() -> None:
    pool = MagicMock()
    pool.acquire = MagicMock(side_effect=ConnectionError("db down"))
    mem = SemanticMemory(pool=pool)
    result = await mem.search_patterns([0.0] * 1536)
    assert result == []


async def test_search_patterns_maps_rows_to_models() -> None:
    rows = [
        {
            "id": "11111111-1111-1111-1111-111111111111",
            "source_type": "owasp_llm",
            "pattern_id": "LLM01",
            "name": "Prompt Injection",
            "pattern_text": "An attacker manipulates an LLM via crafted inputs.",
            "metadata": "{}",
        }
    ]
    mem = SemanticMemory(pool=_pool_with_rows(rows))
    result = await mem.search_patterns([0.1] * 1536, limit=1)
    assert len(result) == 1
    assert result[0].pattern_id == "LLM01"


async def test_search_patterns_returns_empty_when_no_rows_match() -> None:
    """When the DB returns no matching patterns, the result is empty.

    This is the runtime analogue of "no patterns above similarity
    threshold": pgvector's ``ORDER BY embedding <=> $1`` over an empty
    qualifying set yields zero rows.
    """
    mem = SemanticMemory(pool=_pool_with_rows([]))
    result = await mem.search_patterns([0.5] * 1536, limit=5)
    assert result == []
