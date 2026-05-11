"""Writer agent — assembles the final ThreatReport and persists a summary.

Pipeline:
    1. Validate that the state has a critic report and at least one
       :class:`ThreatSurface` (the schema enforces ``min_length=1``, but
       we surface it as :class:`AgentError` for friendlier graph errors).
    2. Build the :class:`ThreatReport` with computed metadata
       (approximate token count, finding/surface counts).
    3. Derive a :class:`ThreatReportSummary` and persist it to
       :class:`EpisodicMemory` so future runs benefit from the precedent.
       A storage failure is logged but never re-raised — the report is
       still returned.
"""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, cast

import tiktoken

from nexus.agents.base import AgentBase
from nexus.exceptions import AgentError, MemoryLayerError
from nexus.memory.episodic import EpisodicMemory
from nexus.schemas.models import (
    AgentState,
    FindingResult,
    FocusArea,
    ResearchTask,
    Severity,
    SourceType,
    ThreatReport,
    ThreatReportSummary,
    ThreatSurface,
)

EmbedFn = Callable[[str], Awaitable[list[float]]]

_MAX_TOP_VECTORS = 5

# GPT-4o pricing per 1M tokens — input vs. output. Will be replaced by
# Langfuse-reported real token counts in S6.T1.
_GPT4O_INPUT_USD_PER_1M = 5.00
_GPT4O_OUTPUT_USD_PER_1M = 15.00
_INPUT_RATIO = 0.70  # conservative split until Langfuse provides exact counts
_OUTPUT_RATIO = 1.0 - _INPUT_RATIO

_ENCODING_NAME = "cl100k_base"  # matches GPT-4o
_encoding = tiktoken.get_encoding(_ENCODING_NAME)


class WriterAgent(AgentBase):
    """Formats approved threat surfaces into a structured ThreatReport."""

    agent_name = "writer"

    def __init__(
        self,
        episodic_memory: EpisodicMemory | None = None,
        embed_fn: EmbedFn | None = None,
    ) -> None:
        super().__init__()
        self._episodic_memory = episodic_memory
        self._embed_fn = embed_fn

    async def run(self, state: AgentState) -> AgentState:
        """Produce the final ThreatReport and persist a summary.

        Raises:
            AgentError: When ``critic_report`` is missing or the state has
                zero ThreatSurface objects.
        """
        self._log_start(state)
        critic_report = state["critic_report"]
        if critic_report is None:
            raise AgentError("WriterAgent requires a CriticReport in state")
        if not state["threat_surfaces"]:
            raise AgentError("WriterAgent requires at least one ThreatSurface")

        report = ThreatReport(
            target_description=state["target_description"],
            created_at=datetime.now(UTC),
            threat_surfaces=list(state["threat_surfaces"]),
            critic_report=critic_report,
            iteration_count=max(1, state["iteration_count"]),
            metadata=_build_metadata(state),
        )

        summary = _summary_from_report(
            report,
            session_id=state["session_id"],
            plan=list(state["plan"]),
        )
        await self._persist_summary(summary, report.target_description)

        return cast(AgentState, {**state, "threat_report": report})

    async def _persist_summary(
        self,
        summary: ThreatReportSummary,
        target_description: str,
    ) -> None:
        if self._episodic_memory is None or self._embed_fn is None:
            self._logger.warning(
                "episodic_memory_not_configured",
                session_id=summary.session_id,
                detail="skipping summary persistence",
            )
            return
        try:
            embedding = await self._embed_fn(target_description)
            await self._episodic_memory.store(summary, embedding)
        except MemoryLayerError as exc:
            self._logger.warning("episodic_store_failed", error=str(exc))
        except Exception as exc:
            self._logger.warning("episodic_store_unexpected", error=str(exc))


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _build_metadata(state: AgentState) -> dict[str, Any]:
    """Compute a metadata dict with token/cost/latency/source telemetry.

    Token counts ignore per-message overhead; pricing splits 70/30 between
    input and output. Real per-call accounting lands in S6.T1 via Langfuse.
    """
    total_tokens = _count_message_tokens(state["messages"])
    return {
        "total_tokens": total_tokens,
        "estimated_cost_usd": _estimate_cost_usd(total_tokens),
        "latency_seconds": _latency_seconds(state),
        "source_breakdown": _source_breakdown(state["findings"]),
        "iteration_count": state["iteration_count"],
        "finding_count": len(state["findings"]),
        "surface_count": len(state["threat_surfaces"]),
    }


def _count_message_tokens(messages: list[Any]) -> int:
    total = 0
    for msg in messages:
        content = getattr(msg, "content", "")
        if not content:
            continue
        total += len(_encoding.encode(str(content)))
    return total


def _estimate_cost_usd(total_tokens: int) -> float:
    input_tokens = total_tokens * _INPUT_RATIO
    output_tokens = total_tokens * _OUTPUT_RATIO
    cost = (
        input_tokens * _GPT4O_INPUT_USD_PER_1M + output_tokens * _GPT4O_OUTPUT_USD_PER_1M
    ) / 1_000_000
    return round(cost, 6)


def _latency_seconds(state: AgentState) -> float:
    start = state.get("session_start_time", 0.0) or 0.0
    if start <= 0.0:
        return 0.0
    return round(max(0.0, time.time() - start), 4)


def _source_breakdown(findings: list[FindingResult]) -> dict[str, int]:
    counter: Counter[str] = Counter(f.source_type.value for f in findings)
    return {src.value: counter.get(src.value, 0) for src in SourceType}


def _summary_from_report(
    report: ThreatReport,
    *,
    session_id: str,
    plan: list[ResearchTask],
) -> ThreatReportSummary:
    return ThreatReportSummary(
        id=report.id,
        session_id=session_id,
        target_description=report.target_description,
        created_at=report.created_at,
        surface_count=len(report.threat_surfaces),
        severity_breakdown=_severity_breakdown(report.threat_surfaces),
        focus_areas_covered=_focus_areas(plan),
        top_attack_vectors=_top_attack_vectors(report.threat_surfaces, limit=_MAX_TOP_VECTORS),
        overall_critic_score=report.critic_report.overall_score,
        iteration_count=report.iteration_count,
    )


def _severity_breakdown(surfaces: list[ThreatSurface]) -> dict[str, int]:
    counter: Counter[str] = Counter(s.severity.value for s in surfaces)
    return {sev.value: counter.get(sev.value, 0) for sev in Severity}


def _focus_areas(plan: list[ResearchTask]) -> list[FocusArea]:
    seen: list[FocusArea] = []
    for task in plan:
        if task.focus_area not in seen:
            seen.append(task.focus_area)
    return seen


def _top_attack_vectors(surfaces: list[ThreatSurface], limit: int) -> list[str]:
    counter: Counter[str] = Counter()
    for surface in surfaces:
        counter.update(surface.attack_vectors)
    return [vector for vector, _ in counter.most_common(limit)]
