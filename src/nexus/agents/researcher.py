"""Researcher agent — fans out MCP calls to populate ``state['findings']``.

Per :class:`nexus.schemas.models.ResearchTask`, the agent calls all three
MCP servers (arXiv, NVD, ATLAS) in parallel via :class:`MCPClient`,
parses the JSON responses into :class:`FindingResult` objects, scores
their relevance with a (mockable) LLM call, deduplicates by identifier,
and appends to the cumulative ``state['findings']``. A failure from one
MCP is logged and skipped — the Researcher never aborts because a
single source is unavailable.
"""

from __future__ import annotations

import asyncio
import json
from collections import Counter
from collections.abc import Awaitable, Callable
from typing import Any, cast

from nexus.agents.base import AgentBase
from nexus.exceptions import AgentError, MCPClientError
from nexus.mcp import MCPClient
from nexus.schemas.models import (
    AgentState,
    FindingResult,
    ResearchTask,
    SourceType,
)

ScoringFn = Callable[[ResearchTask, FindingResult], Awaitable[float]]

_SUMMARY_MIN_LEN = 20

# (server_name, tool_name) per source type. Kept in sync with mcp_servers/.
_MCP_TOOLS: dict[SourceType, tuple[str, str]] = {
    SourceType.ARXIV: ("arxiv", "search_papers"),
    SourceType.NVD: ("nvd", "search_cves"),
    SourceType.ATLAS: ("atlas", "search_techniques"),
}


class ResearcherAgent(AgentBase):
    """Executes MCP tool calls for every active ResearchTask."""

    agent_name = "researcher"

    def __init__(
        self,
        mcp_client: MCPClient | None = None,
        scoring_fn: ScoringFn | None = None,
        max_results_per_source: int = 10,
    ) -> None:
        super().__init__()
        self._mcp_client = mcp_client
        self._scoring_fn = scoring_fn or self._default_score
        self._max_results = max_results_per_source

    async def run(self, state: AgentState) -> AgentState:
        """Gather findings for the active task list and append them to state.

        Raises:
            AgentError: When no tasks are available, or the run yields
                zero findings (existing + new).
        """
        self._log_start(state)
        tasks = self._tasks_to_research(state)
        if not tasks:
            raise AgentError("ResearcherAgent: no research tasks to execute")

        client = self._mcp_client or MCPClient()
        owns_client = self._mcp_client is None
        try:
            raw_findings = await self._gather_findings(tasks, client)
        finally:
            if owns_client:
                await client.aclose()

        scored = await self._score_findings(tasks, raw_findings)
        merged = _dedup(list(state["findings"]) + scored)

        if not merged:
            raise AgentError(
                "ResearcherAgent produced zero findings; cannot proceed",
            )

        per_source = Counter(f.source_type.value for f in scored)
        self._logger.info(
            "researcher_done",
            session_id=state["session_id"],
            tasks_researched=len(tasks),
            new_findings=len(scored),
            total_findings=len(merged),
            per_source=dict(per_source),
        )

        return cast(
            AgentState,
            {
                **state,
                "findings": merged,
                "iteration_count": state["iteration_count"] + 1,
            },
        )

    # ----- task selection ---------------------------------------------------

    def _tasks_to_research(self, state: AgentState) -> list[ResearchTask]:
        if state["iteration_count"] == 0:
            return list(state["plan"])
        critic = state["critic_report"]
        if critic is None:
            self._logger.warning("re_research_without_critic_report")
            return []
        return list(critic.re_research_tasks)

    # ----- MCP fan-out ------------------------------------------------------

    async def _gather_findings(
        self,
        tasks: list[ResearchTask],
        client: MCPClient,
    ) -> list[FindingResult]:
        coros = [
            self._call_one(client, task, source_type)
            for task in tasks
            for source_type in _MCP_TOOLS
        ]
        batches = await asyncio.gather(*coros)
        return [finding for batch in batches for finding in batch]

    async def _call_one(
        self,
        client: MCPClient,
        task: ResearchTask,
        source_type: SourceType,
    ) -> list[FindingResult]:
        server, tool = _MCP_TOOLS[source_type]
        query = task.search_queries[0] if task.search_queries else task.description
        kwargs: dict[str, Any] = {"max_results": self._max_results}
        if source_type == SourceType.NVD:
            kwargs["keyword"] = query
        else:
            kwargs["query"] = query

        try:
            raw = await client.call_tool(server, tool, **kwargs)
        except MCPClientError as exc:
            self._logger.warning(
                "mcp_call_failed",
                server=server,
                tool=tool,
                task_id=task.id,
                error=str(exc),
            )
            return []

        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            self._logger.warning(
                "mcp_invalid_json",
                server=server,
                tool=tool,
                task_id=task.id,
                error=str(exc),
            )
            return []

        if not isinstance(parsed, list):
            self._logger.warning(
                "mcp_unexpected_payload",
                server=server,
                tool=tool,
                task_id=task.id,
                payload_type=type(parsed).__name__,
            )
            return []

        return _items_to_findings(task.id, source_type, parsed)

    # ----- scoring ----------------------------------------------------------

    async def _score_findings(
        self,
        tasks: list[ResearchTask],
        findings: list[FindingResult],
    ) -> list[FindingResult]:
        task_by_id = {t.id: t for t in tasks}
        scored: list[FindingResult] = []
        for finding in findings:
            task = task_by_id.get(finding.task_id)
            if task is None:
                scored.append(finding)
                continue
            try:
                score = await self._scoring_fn(task, finding)
            except Exception as exc:
                self._logger.warning(
                    "scoring_failed",
                    task_id=finding.task_id,
                    error=str(exc),
                )
                score = 0.5
            score = max(0.0, min(1.0, float(score)))
            scored.append(finding.model_copy(update={"relevance_score": score}))
        return scored

    async def _default_score(
        self,
        task: ResearchTask,
        finding: FindingResult,
    ) -> float:
        """Brief LLM scoring prompt; returns 0.5 on any failure."""
        try:
            llm = self._get_llm()
        except Exception:
            return 0.5
        prompt = (
            f"On a scale from 0.0 to 1.0, how relevant is this "
            f"{finding.source_type.value} finding to the research task "
            f"'{task.description}'?\n"
            f"Title: {finding.title}\n"
            f"Summary: {finding.summary[:500]}\n"
            f"Reply with only a number between 0.0 and 1.0."
        )
        try:
            response = await llm.ainvoke(prompt)
        except Exception:
            return 0.5
        text = str(getattr(response, "content", response)).strip()
        try:
            return float(text)
        except ValueError:
            return 0.5


# --- helpers ---------------------------------------------------------------


def _dedup(findings: list[FindingResult]) -> list[FindingResult]:
    """Drop later findings that share at least one identifier with an earlier one."""
    seen: set[str] = set()
    out: list[FindingResult] = []
    for f in findings:
        keys = list(f.identifiers) or [f"_uuid:{f.id}"]
        if any(k in seen for k in keys):
            continue
        seen.update(keys)
        out.append(f)
    return out


def _items_to_findings(
    task_id: str,
    source_type: SourceType,
    items: list[Any],
) -> list[FindingResult]:
    out: list[FindingResult] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        finding = _item_to_finding(task_id, source_type, item)
        if finding is not None:
            out.append(finding)
    return out


def _item_to_finding(
    task_id: str,
    source_type: SourceType,
    item: dict[str, Any],
) -> FindingResult | None:
    if source_type == SourceType.ARXIV:
        return _arxiv_finding(task_id, item)
    if source_type == SourceType.NVD:
        return _nvd_finding(task_id, item)
    if source_type == SourceType.ATLAS:
        return _atlas_finding(task_id, item)
    return None


def _arxiv_finding(task_id: str, item: dict[str, Any]) -> FindingResult | None:
    arxiv_id = str(item.get("arxiv_id") or "")
    title = str(item.get("title") or "")
    abstract = str(item.get("abstract") or "")
    if not arxiv_id or len(abstract) < _SUMMARY_MIN_LEN:
        return None
    url_value = item.get("url")
    return FindingResult(
        task_id=task_id,
        source_type=SourceType.ARXIV,
        title=title or arxiv_id,
        summary=abstract,
        relevance_score=0.5,
        url=str(url_value) if isinstance(url_value, str) and url_value else None,
        identifiers=[f"arxiv:{arxiv_id}"],
    )


def _nvd_finding(task_id: str, item: dict[str, Any]) -> FindingResult | None:
    cve_id = str(item.get("cve_id") or "")
    description = str(item.get("description") or "")
    if not cve_id or len(description) < _SUMMARY_MIN_LEN:
        return None
    refs = item.get("references") or []
    first_ref: str | None = None
    if isinstance(refs, list) and refs and isinstance(refs[0], str):
        first_ref = refs[0]
    return FindingResult(
        task_id=task_id,
        source_type=SourceType.NVD,
        title=cve_id,
        summary=description,
        relevance_score=0.5,
        url=first_ref,
        identifiers=[cve_id],
    )


def _atlas_finding(task_id: str, item: dict[str, Any]) -> FindingResult | None:
    technique_id = str(item.get("technique_id") or "")
    name = str(item.get("name") or "")
    description = str(item.get("description") or "")
    if not technique_id or len(description) < _SUMMARY_MIN_LEN:
        return None
    url_value = item.get("url")
    return FindingResult(
        task_id=task_id,
        source_type=SourceType.ATLAS,
        title=name or technique_id,
        summary=description,
        relevance_score=0.5,
        url=str(url_value) if isinstance(url_value, str) and url_value else None,
        identifiers=[f"ATLAS-{technique_id}"],
    )
