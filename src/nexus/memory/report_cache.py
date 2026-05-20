"""Process-local LRU cache for recently produced ThreatReportSummary objects.

Bridges the streaming → report-viewer flow when pgvector is unreachable or
the writer cannot embed the summary: the writer always pushes the summary
into this cache regardless of episodic-memory status, so ``GET /report/{id}``
can serve a just-completed run even when Postgres / OpenAI embeddings are
down. The cache is process-local and bounded — durable storage remains
pgvector via :class:`~nexus.memory.episodic.EpisodicMemory`.
"""

from __future__ import annotations

from collections import OrderedDict
from threading import Lock

from nexus.schemas.models import ThreatReportSummary

_DEFAULT_MAX_SIZE = 256


class ReportCache:
    """Bounded, thread-safe LRU cache keyed by ``ThreatReportSummary.id``."""

    def __init__(self, max_size: int = _DEFAULT_MAX_SIZE) -> None:
        self._cache: OrderedDict[str, ThreatReportSummary] = OrderedDict()
        self._lock = Lock()
        self._max_size = max_size

    def put(self, summary: ThreatReportSummary) -> None:
        with self._lock:
            self._cache[summary.id] = summary
            self._cache.move_to_end(summary.id)
            while len(self._cache) > self._max_size:
                self._cache.popitem(last=False)

    def get(self, report_id: str) -> ThreatReportSummary | None:
        with self._lock:
            summary = self._cache.get(report_id)
            if summary is not None:
                self._cache.move_to_end(report_id)
            return summary


_default_cache = ReportCache()


def get_report_cache() -> ReportCache:
    """Return the module-level singleton cache."""
    return _default_cache
