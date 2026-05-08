"""Analyst agent — synthesises findings into ThreatSurface objects per focus area.

Pipeline:
    1. Group ``state['findings']`` by FocusArea using ``state['plan']``
       (``task_id`` → :class:`ResearchTask` lookup). Findings whose task is
       not in the plan fall back to :class:`FocusArea.OTHER`.
    2. For each non-empty group:
       a. Embed a combined summary of the top findings and query
          :class:`SemanticMemory` for related :class:`ThreatPattern`
          entries (top 5). The lookup is silently skipped when the
          memory layer or embed function is missing.
       b. Build a structured prompt (focus area + findings + patterns)
          and ask the LLM for a single :class:`ThreatSurface` JSON
          object.
       c. Force the real FindingResult objects as ``evidence`` so the
          schema's ``require_evidence`` validator always passes, and
          run :meth:`ThreatSurface.model_validate`.
    3. Replace ``state['threat_surfaces']`` with the new list.

Failures from the LLM (network or parse) are wrapped in
:class:`AgentError` so the supervising graph can retry. Semantic memory
failures only emit a warning — the synthesis still proceeds without
pattern context.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Awaitable, Callable
from typing import Any, cast

from nexus.agents.base import AgentBase
from nexus.exceptions import AgentError
from nexus.memory.semantic import SemanticMemory
from nexus.schemas.models import (
    AgentState,
    FindingResult,
    FocusArea,
    ResearchTask,
    Severity,
    ThreatPattern,
    ThreatSurface,
)

EmbedFn = Callable[[str], Awaitable[list[float]]]

_PATTERN_LIMIT = 5
_TOP_FINDINGS_FOR_EMBED = 5
_FINDING_SUMMARY_CHARS = 300
_PATTERN_TEXT_CHARS = 300


class AnalystAgent(AgentBase):
    """Synthesises FindingResult groups into ThreatSurface entries."""

    agent_name = "analyst"

    def __init__(
        self,
        llm: Any | None = None,
        semantic_memory: SemanticMemory | None = None,
        embed_fn: EmbedFn | None = None,
    ) -> None:
        super().__init__()
        self._llm = llm
        self._semantic_memory = semantic_memory
        self._embed_fn = embed_fn
        self.last_prompts: list[str] = []  # exposed for tests / debugging

    async def run(self, state: AgentState) -> AgentState:
        """Produce ``state['threat_surfaces']`` from the active findings.

        Raises:
            AgentError: When the state is missing findings or a plan, the
                LLM call fails, or the produced ThreatSurface fails
                Pydantic validation.
        """
        self._log_start(state)
        if not state["findings"]:
            raise AgentError("AnalystAgent requires at least one finding in state")
        if not state["plan"]:
            raise AgentError("AnalystAgent requires a non-empty plan in state")

        groups = _group_by_focus_area(state["findings"], state["plan"])
        self.last_prompts = []
        surfaces: list[ThreatSurface] = []
        for focus_area, findings in groups.items():
            patterns = await self._fetch_patterns(findings)
            surface = await self._synthesise(focus_area, findings, patterns)
            surfaces.append(surface)
            self._logger.info(
                "analyst_group_done",
                session_id=state["session_id"],
                focus_area=focus_area.value,
                finding_count=len(findings),
                pattern_count=len(patterns),
                approx_tokens=len(self.last_prompts[-1]) // 4,
            )

        return cast(AgentState, {**state, "threat_surfaces": surfaces})

    # ----- semantic memory --------------------------------------------------

    async def _fetch_patterns(self, findings: list[FindingResult]) -> list[ThreatPattern]:
        if self._semantic_memory is None or self._embed_fn is None:
            return []
        top = sorted(findings, key=lambda f: f.relevance_score, reverse=True)[
            :_TOP_FINDINGS_FOR_EMBED
        ]
        query_text = " | ".join(f.title for f in top) or "ai security"
        try:
            embedding = await self._embed_fn(query_text)
            return await self._semantic_memory.search_patterns(
                embedding,
                limit=_PATTERN_LIMIT,
            )
        except Exception as exc:
            self._logger.warning("semantic_lookup_failed", error=str(exc))
            return []

    # ----- LLM synthesis ----------------------------------------------------

    async def _synthesise(
        self,
        focus_area: FocusArea,
        findings: list[FindingResult],
        patterns: list[ThreatPattern],
    ) -> ThreatSurface:
        prompt = self._build_prompt(focus_area, findings, patterns)
        self.last_prompts.append(prompt)

        llm = self._llm or self._get_llm()
        try:
            response = await llm.ainvoke(prompt)
        except Exception as exc:
            raise AgentError(f"Analyst LLM call failed: {exc}") from exc

        text = str(getattr(response, "content", response)).strip()
        try:
            payload = _extract_json_object(text)
        except ValueError as exc:
            raise AgentError(f"Analyst could not parse LLM JSON: {exc}") from exc

        # The LLM never invents evidence — we attach the real FindingResult
        # objects so the schema's require_evidence validator always passes.
        payload["evidence"] = [f.model_dump() for f in findings]
        try:
            return ThreatSurface.model_validate(payload)
        except Exception as exc:
            raise AgentError(f"Analyst produced an invalid ThreatSurface: {exc}") from exc

    def _build_prompt(
        self,
        focus_area: FocusArea,
        findings: list[FindingResult],
        patterns: list[ThreatPattern],
    ) -> str:
        severities = ", ".join(s.value for s in Severity)
        findings_block = "\n".join(
            f"- [{f.source_type.value}] {f.title} :: {f.summary[:_FINDING_SUMMARY_CHARS]}"
            for f in findings
        )
        if patterns:
            patterns_block = "\n".join(
                f"- [{p.source_type}/{p.pattern_id}] {p.name}: "
                f"{p.pattern_text[:_PATTERN_TEXT_CHARS]}"
                for p in patterns
            )
        else:
            patterns_block = "(no related patterns found in semantic memory)"

        return (
            "You are the Analyst agent for an AI security threat-modelling "
            "pipeline.\n"
            f"Focus area: {focus_area.value}\n\n"
            "Findings collected by the Researcher:\n"
            f"{findings_block}\n\n"
            "Related threat patterns (ATLAS / OWASP LLM Top 10):\n"
            f"{patterns_block}\n\n"
            "Synthesise ONE ThreatSurface that summarises the threat for "
            "this focus area.\n"
            f"Severity must be one of: {severities}.\n"
            "Pick owasp_category from the OWASP LLM Top 10 (e.g. LLM01, "
            "LLM02, LLM06, ...) when applicable; otherwise use null.\n"
            "Return ONLY a JSON object with keys: name, description, "
            "severity, attack_vectors, mitigations, cvss_score (0-10 or "
            "null), owasp_category. Do not include 'evidence' — the agent "
            "attaches it.\n"
            "description must be at least 30 characters; mitigations must "
            "be a non-empty list of strings. Do not wrap in markdown."
        )


# --- helpers ---------------------------------------------------------------


def _group_by_focus_area(
    findings: list[FindingResult],
    plan: list[ResearchTask],
) -> dict[FocusArea, list[FindingResult]]:
    """Group findings by the focus_area of their originating ResearchTask."""
    task_focus = {t.id: t.focus_area for t in plan}
    groups: dict[FocusArea, list[FindingResult]] = defaultdict(list)
    for f in findings:
        focus = task_focus.get(f.task_id, FocusArea.OTHER)
        groups[focus].append(f)
    return dict(groups)


def _extract_json_object(text: str) -> dict[str, Any]:
    """Pull a JSON object out of ``text``, tolerating prose and code fences."""
    candidate = text.strip()
    if candidate.startswith("```"):
        lines = [ln for ln in candidate.splitlines() if not ln.strip().startswith("```")]
        candidate = "\n".join(lines)
    start = candidate.find("{")
    end = candidate.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("no JSON object found in LLM response")
    parsed = json.loads(candidate[start : end + 1])
    if not isinstance(parsed, dict):
        raise ValueError("expected JSON object, got array")
    return parsed
