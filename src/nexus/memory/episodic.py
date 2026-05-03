"""Episodic memory backed by pgvector — stores and retrieves ThreatReportSummary."""

import json
from typing import Any

import structlog

from nexus.exceptions import MemoryLayerError
from nexus.schemas.models import FocusArea, ThreatReportSummary

logger = structlog.get_logger(__name__)

_EMBEDDING_DIM = 1536


class EpisodicMemory:
    """Read-write episodic memory layer for past ThreatReportSummary objects."""

    def __init__(self, pool: Any) -> None:
        self._pool = pool

    async def store(
        self,
        summary: ThreatReportSummary,
        embedding: list[float],
    ) -> None:
        """Persist a ThreatReportSummary with its embedding vector.

        Args:
            summary: Condensed report summary.
            embedding: text-embedding-3-small vector (dim=1536).

        Raises:
            MemoryLayerError: On dimension mismatch or DB write failure.
        """
        if len(embedding) != _EMBEDDING_DIM:
            raise MemoryLayerError(
                f"Embedding dimension mismatch: expected {_EMBEDDING_DIM}, got {len(embedding)}"
            )
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO threat_report_summaries (
                        id, session_id, target_description, created_at,
                        surface_count, severity_breakdown, focus_areas_covered,
                        top_attack_vectors, overall_critic_score, iteration_count,
                        embedding
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::vector)
                    ON CONFLICT (id) DO UPDATE SET
                        embedding = EXCLUDED.embedding,
                        overall_critic_score = EXCLUDED.overall_critic_score
                    """,
                    summary.id,
                    summary.session_id,
                    summary.target_description,
                    summary.created_at,
                    summary.surface_count,
                    json.dumps(summary.severity_breakdown),
                    json.dumps([f.value for f in summary.focus_areas_covered]),
                    json.dumps(summary.top_attack_vectors),
                    summary.overall_critic_score,
                    summary.iteration_count,
                    str(embedding),
                )
        except Exception as exc:  # asyncpg.PostgresError — untyped package
            raise MemoryLayerError(
                f"Failed to store ThreatReportSummary {summary.id}: {exc}"
            ) from exc

    async def search_similar(
        self,
        embedding: list[float],
        threshold: float = 0.85,
        limit: int = 3,
    ) -> list[ThreatReportSummary]:
        """Retrieve summaries with cosine similarity above threshold.

        Args:
            embedding: Query vector (dim=1536).
            threshold: Minimum cosine similarity [0.0, 1.0].
            limit: Maximum number of results.

        Returns:
            ThreatReportSummary list ordered by descending similarity.
        """
        try:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT id, session_id, target_description, created_at,
                           surface_count, severity_breakdown, focus_areas_covered,
                           top_attack_vectors, overall_critic_score, iteration_count
                    FROM threat_report_summaries
                    WHERE embedding IS NOT NULL
                      AND 1 - (embedding <=> $1::vector) >= $2
                    ORDER BY embedding <=> $1::vector
                    LIMIT $3
                    """,
                    str(embedding),
                    threshold,
                    limit,
                )
        except Exception as exc:  # asyncpg.PostgresError — untyped package
            logger.warning("episodic_search_failed", error=str(exc))
            return []

        return [_row_to_summary(row) for row in rows]

    async def get_by_id(self, summary_id: str) -> ThreatReportSummary | None:
        """Retrieve a single ThreatReportSummary by primary key.

        Args:
            summary_id: UUID string identifier.

        Returns:
            ThreatReportSummary if found, None otherwise.
        """
        try:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT id, session_id, target_description, created_at,
                           surface_count, severity_breakdown, focus_areas_covered,
                           top_attack_vectors, overall_critic_score, iteration_count
                    FROM threat_report_summaries
                    WHERE id = $1
                    """,
                    summary_id,
                )
        except Exception as exc:  # asyncpg.PostgresError — untyped package
            logger.warning("episodic_get_failed", error=str(exc))
            return None

        return _row_to_summary(row) if row is not None else None


def _row_to_summary(row: Any) -> ThreatReportSummary:
    """Convert an asyncpg Record to a ThreatReportSummary."""
    return ThreatReportSummary(
        id=row["id"],
        session_id=row["session_id"],
        target_description=row["target_description"],
        created_at=row["created_at"],
        surface_count=row["surface_count"],
        severity_breakdown=json.loads(row["severity_breakdown"]),
        focus_areas_covered=[FocusArea(v) for v in json.loads(row["focus_areas_covered"])],
        top_attack_vectors=json.loads(row["top_attack_vectors"]),
        overall_critic_score=row["overall_critic_score"],
        iteration_count=row["iteration_count"],
    )
