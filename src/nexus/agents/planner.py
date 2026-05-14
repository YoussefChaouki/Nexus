"""Planner agent — decomposes a target description into 4-6 ResearchTask objects.

Pipeline:
    1. Embed ``target_description`` and query :class:`EpisodicMemory` for
       past similar architectures (cosine ≥ 0.85, top 3). When the memory
       layer or the embed function is missing the lookup is silently
       skipped — the Planner still works in isolation.
    2. Build a structured prompt that includes the FocusArea taxonomy,
       priority levels, and (when present) bullets from the episodic
       summaries.
    3. Call the LLM and parse a JSON array of ResearchTask dicts. Any
       parse / validation error is wrapped in :class:`AgentError` so the
       LangGraph node can be retried by the supervising graph.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any, cast

from nexus.agents.base import AgentBase
from nexus.exceptions import AgentError
from nexus.memory.episodic import EpisodicMemory
from nexus.schemas.models import (
    AgentState,
    FocusArea,
    Priority,
    ResearchTask,
    ThreatReportSummary,
)

EmbedFn = Callable[[str], Awaitable[list[float]]]

_MIN_TASKS = 4
_MAX_TASKS = 6
_EPISODIC_THRESHOLD = 0.85
_EPISODIC_LIMIT = 3


class PlannerAgent(AgentBase):
    """Decomposes ``target_description`` into the initial research plan."""

    agent_name = "planner"

    def __init__(
        self,
        llm: Any | None = None,
        episodic_memory: EpisodicMemory | None = None,
        embed_fn: EmbedFn | None = None,
    ) -> None:
        super().__init__()
        self._llm = llm
        self._episodic_memory = episodic_memory
        self._embed_fn = embed_fn
        self.last_prompt: str | None = None  # exposed for tests / debugging

    async def run(self, state: AgentState) -> AgentState:
        """Produce ``state['plan']`` from ``state['target_description']``.

        Raises:
            AgentError: When the LLM call fails, returns unparseable text,
                or yields a task count outside ``[4, 6]``.
        """
        self._log_start(state)
        target = state["target_description"]
        episodic_context = await self._fetch_episodic_context(target)
        tasks = await self._generate_plan(target, episodic_context, state)

        if not (_MIN_TASKS <= len(tasks) <= _MAX_TASKS):
            raise AgentError(
                f"Planner produced {len(tasks)} tasks; expected {_MIN_TASKS}-{_MAX_TASKS}",
            )

        return cast(AgentState, {**state, "plan": tasks})

    # ----- episodic memory --------------------------------------------------

    async def _fetch_episodic_context(
        self,
        target: str,
    ) -> list[ThreatReportSummary]:
        if self._episodic_memory is None or self._embed_fn is None:
            return []
        try:
            embedding = await self._embed_fn(target)
            return await self._episodic_memory.search_similar(
                embedding,
                threshold=_EPISODIC_THRESHOLD,
                limit=_EPISODIC_LIMIT,
            )
        except Exception as exc:
            self._logger.warning("episodic_lookup_failed", error=str(exc))
            return []

    # ----- LLM call ---------------------------------------------------------

    async def _generate_plan(
        self,
        target: str,
        episodic_context: list[ThreatReportSummary],
        state: AgentState,
    ) -> list[ResearchTask]:
        prompt = self._build_prompt(target, episodic_context)
        self.last_prompt = prompt

        llm = self._llm or self._get_llm()
        try:
            response = await llm.ainvoke(
                prompt,
                config=self._invoke_config(
                    state,
                    step="generate_plan",
                    extra_metadata={
                        "episodic_context_count": len(episodic_context),
                    },
                ),
            )
        except Exception as exc:
            raise AgentError(f"Planner LLM call failed: {exc}") from exc

        text = str(getattr(response, "content", response)).strip()
        try:
            payload = _extract_json_array(text)
        except ValueError as exc:
            raise AgentError(f"Planner could not parse LLM JSON: {exc}") from exc

        try:
            return [ResearchTask.model_validate(item) for item in payload]
        except Exception as exc:
            raise AgentError(f"Planner produced an invalid ResearchTask: {exc}") from exc

    def _build_prompt(
        self,
        target: str,
        context: list[ThreatReportSummary],
    ) -> str:
        focus_areas = ", ".join(fa.value for fa in FocusArea)
        priorities = ", ".join(p.value for p in Priority)
        episodic_block = _format_episodic(context)

        return (
            "You are the Planner agent for an AI security threat-modelling pipeline.\n"
            f"Target architecture:\n{target}\n\n"
            f"{episodic_block}"
            f"Decompose the target into {_MIN_TASKS}-{_MAX_TASKS} focused "
            "research tasks.\n"
            f"Each task must use a focus_area from this taxonomy: {focus_areas}.\n"
            f"Each task must declare a priority: {priorities}.\n"
            "Each task must include 1-3 search_queries an MCP-backed agent "
            "will issue against arXiv, NVD, and MITRE ATLAS.\n\n"
            "Return ONLY a JSON array of objects with keys: description, "
            "focus_area, priority, search_queries. Do not wrap in markdown.\n"
            'Example item: {"description": "Investigate prompt-injection '
            'attacks against the RAG retrieval layer.", "focus_area": '
            '"injection", "priority": "high", "search_queries": '
            '["prompt injection RAG"]}'
        )


def _format_episodic(context: list[ThreatReportSummary]) -> str:
    if not context:
        return ""
    bullets = "\n".join(
        f"- session={s.session_id} surfaces={s.surface_count} "
        f"critic_score={s.overall_critic_score:.2f}: "
        f"{s.target_description[:200]}"
        for s in context
    )
    return f"Past similar architectures (avoid blind spots covered there):\n{bullets}\n\n"


def _extract_json_array(text: str) -> list[Any]:
    """Pull a JSON array out of ``text``, tolerating prose and code fences."""
    candidate = text.strip()
    if candidate.startswith("```"):
        lines = [ln for ln in candidate.splitlines() if not ln.strip().startswith("```")]
        candidate = "\n".join(lines)
    start = candidate.find("[")
    end = candidate.rfind("]")
    if start == -1 or end == -1 or end < start:
        raise ValueError("no JSON array found in LLM response")
    parsed = json.loads(candidate[start : end + 1])
    if not isinstance(parsed, list):
        raise ValueError("expected JSON array, got object")
    return parsed
