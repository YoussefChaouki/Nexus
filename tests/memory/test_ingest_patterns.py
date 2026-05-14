"""Tests for ``scripts/ingest_patterns.py``.

The script is exercised here at the helper level — we do not spin up a
real OpenAI client or a real Postgres. The two paths that matter:
* OWASP/ATLAS source builders shape ``_PatternToIngest`` records
  correctly (right ``source_type`` / ``pattern_id`` / text format).
* ``upsert_patterns`` issues the upsert with a pgvector literal and
  reports ``(inserted, refreshed)`` per the ``xmax = 0`` trick.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Make the ``scripts/`` directory importable as a regular package.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from scripts.ingest_patterns import (  # noqa: E402 — sys.path tweak above
    OWASP_LLM_TOP10_2023,
    _PatternToIngest,
    _vector_literal,
    atlas_patterns,
    owasp_patterns,
    upsert_patterns,
)


def test_owasp_patterns_emits_ten_entries_with_full_text() -> None:
    patterns = owasp_patterns()
    assert len(patterns) == 10
    pattern_ids = [p.pattern_id for p in patterns]
    assert pattern_ids == [f"LLM{i:02d}" for i in range(1, 11)]
    # Every entry must carry the long-form description, not just the
    # title — the spec is explicit about including the detailed text.
    for pattern in patterns:
        assert pattern.source_type == "owasp_llm"
        assert pattern.metadata == {"version": "2023"}
        assert len(pattern.pattern_text) > 100, pattern.pattern_id


def test_owasp_corpus_is_self_consistent() -> None:
    """The hardcoded corpus and the ``owasp_patterns()`` view agree."""
    assert len(OWASP_LLM_TOP10_2023) == 10
    for entry in OWASP_LLM_TOP10_2023:
        assert set(entry) == {"pattern_id", "name", "pattern_text"}


def test_atlas_patterns_returns_empty_when_bundle_missing(tmp_path: Path) -> None:
    missing = tmp_path / "nope" / "ATLAS.json"
    result = atlas_patterns(stix_path=missing)
    assert result == []


def test_atlas_patterns_maps_technique_to_pattern(tmp_path: Path) -> None:
    # SimpleNamespace beats MagicMock here — ``name=`` on MagicMock sets
    # the mock's own ``name`` attribute (used in repr), not the value
    # readers see when they access ``.name``.
    from types import SimpleNamespace

    fake_tech = SimpleNamespace(
        technique_id="AML.T0001",
        name="Search Open Datasets",
        description="Adversaries may search publicly available datasets ...",
        tactic="reconnaissance",
        url="https://atlas.mitre.org/techniques/AML.T0001",
        mitigations=["AML.M0001"],
    )
    bundle = tmp_path / "ATLAS.json"
    bundle.write_text("{}", encoding="utf-8")

    with patch(
        "scripts.ingest_patterns._load_atlas_techniques",
        return_value=[fake_tech],
    ):
        patterns = atlas_patterns(stix_path=bundle)

    assert len(patterns) == 1
    pat = patterns[0]
    assert pat.source_type == "atlas"
    assert pat.pattern_id == "AML.T0001"
    assert pat.name == "Search Open Datasets"
    assert pat.pattern_text.startswith("Search Open Datasets. ")
    assert pat.metadata == {
        "tactic": "reconnaissance",
        "url": "https://atlas.mitre.org/techniques/AML.T0001",
        "mitigations": ["AML.M0001"],
    }


def test_vector_literal_format() -> None:
    literal = _vector_literal([0.0, 1.0, -0.5])
    assert literal == "[0.00000000,1.00000000,-0.50000000]"


def _async_pool_with_fetchrow(rows: list[dict[str, Any]]) -> tuple[Any, AsyncMock]:
    """Build a mock asyncpg pool whose ``fetchrow`` returns ``rows`` in order."""
    conn = MagicMock()
    fetchrow = AsyncMock(side_effect=rows)
    conn.fetchrow = fetchrow
    transaction_cm = MagicMock()
    transaction_cm.__aenter__ = AsyncMock(return_value=None)
    transaction_cm.__aexit__ = AsyncMock(return_value=None)
    conn.transaction = MagicMock(return_value=transaction_cm)

    pool = MagicMock()
    acquire_cm = MagicMock()
    acquire_cm.__aenter__ = AsyncMock(return_value=conn)
    acquire_cm.__aexit__ = AsyncMock(return_value=None)
    pool.acquire = MagicMock(return_value=acquire_cm)
    return pool, fetchrow


async def test_upsert_patterns_counts_inserts_and_refreshes() -> None:
    patterns = [
        _PatternToIngest(
            source_type="owasp_llm",
            pattern_id="LLM01",
            name="Prompt Injection",
            pattern_text="text",
            metadata={},
        ),
        _PatternToIngest(
            source_type="owasp_llm",
            pattern_id="LLM02",
            name="Insecure Output Handling",
            pattern_text="text",
            metadata={},
        ),
    ]
    embeddings = [[0.0] * 3, [0.1] * 3]
    pool, fetchrow = _async_pool_with_fetchrow(
        [
            {"inserted": True},  # LLM01 is new
            {"inserted": False},  # LLM02 already existed
        ],
    )

    inserted, refreshed = await upsert_patterns(pool, patterns, embeddings)

    assert (inserted, refreshed) == (1, 1)
    # Both rows were upserted; their pgvector literals match the input.
    sent_vectors = [call.args[-1] for call in fetchrow.call_args_list]
    assert sent_vectors[0] == "[0.00000000,0.00000000,0.00000000]"
    assert sent_vectors[1] == "[0.10000000,0.10000000,0.10000000]"


async def test_upsert_patterns_rejects_length_mismatch() -> None:
    pool, _ = _async_pool_with_fetchrow([])
    with pytest.raises(ValueError, match="length mismatch"):
        await upsert_patterns(
            pool,
            [
                _PatternToIngest(
                    source_type="atlas",
                    pattern_id="AML.T0001",
                    name="x",
                    pattern_text="y",
                    metadata={},
                ),
            ],
            [],
        )
