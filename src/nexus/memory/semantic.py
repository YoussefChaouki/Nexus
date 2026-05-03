"""Semantic memory backed by pgvector — read-only threat pattern library at runtime."""

import json
from typing import Any

import structlog

from nexus.schemas.models import ThreatPattern

logger = structlog.get_logger(__name__)


class SemanticMemory:
    """Read-only access to the Threat Pattern Library.

    Patterns are ingested once via scripts/ingest_patterns.py (S6.T2).
    Any write attempt at runtime raises RuntimeError.
    """

    def __init__(self, pool: Any) -> None:
        self._pool = pool

    async def search_patterns(
        self,
        embedding: list[float],
        limit: int = 5,
    ) -> list[ThreatPattern]:
        """Retrieve threat patterns ordered by cosine similarity.

        Args:
            embedding: Query vector (dim=1536).
            limit: Maximum number of patterns to return.

        Returns:
            ThreatPattern list ordered by descending similarity.
        """
        try:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT id, source_type, pattern_id, name, pattern_text, metadata
                    FROM threat_patterns
                    WHERE embedding IS NOT NULL
                    ORDER BY embedding <=> $1::vector
                    LIMIT $2
                    """,
                    str(embedding),
                    limit,
                )
        except Exception as exc:  # asyncpg.PostgresError — untyped package
            logger.warning("semantic_search_failed", error=str(exc))
            return []

        return [_row_to_pattern(row) for row in rows]

    def store(self, *_: object, **__: object) -> None:
        """Reject write operations at runtime.

        Raises:
            RuntimeError: Always. Use scripts/ingest_patterns.py instead.
        """
        raise RuntimeError(
            "SemanticMemory is read-only at runtime. "
            "Run scripts/ingest_patterns.py to populate threat patterns."
        )


def _row_to_pattern(row: Any) -> ThreatPattern:
    """Convert an asyncpg Record to a ThreatPattern."""
    return ThreatPattern(
        id=row["id"],
        source_type=row["source_type"],
        pattern_id=row["pattern_id"],
        name=row["name"],
        pattern_text=row["pattern_text"],
        metadata=json.loads(row["metadata"]),
    )
