"""Fixtures for the integration test suite.

These fakes stand in for the real LLM and MCP transport while still
exercising the actual LangGraph nodes and Pydantic schemas. Three fakes
are provided:

* :class:`_FakeRoutingLLM` — routes a single ``ainvoke`` entry point to
  three different responses (Planner / Analyst / scoring) based on the
  prompt content. The Analyst branch reads the ``Focus area:`` line of
  the prompt so each focus_area group gets a distinct ThreatSurface.

* :class:`ContextAwareMockLLM` — :class:`_FakeRoutingLLM` plus full
  Critic support: a queue of :class:`Recommendation` values drives the
  ``recommendation`` field of each :class:`CriticReport`, while
  ``agent_calls`` records the sequence of nodes that invoked the LLM
  (``planner`` / ``researcher_scoring`` / ``analyst`` / ``critic``).
  Used by the Sprint 5 end-to-end pipeline tests.

* :class:`_FakeMCPClient` — returns canned JSON arrays per
  ``(server_name, query)`` pair. ``error_servers`` makes a server raise
  :class:`MCPClientError` so we can exercise the partial-failure path.
  ``empty_servers`` makes a server return an empty list so we can
  exercise the no-findings error path.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from nexus.exceptions import MCPClientError

# --------------------------------------------------------------------------
# Fake LLM
# --------------------------------------------------------------------------


_PLANNER_TASKS: list[dict[str, Any]] = [
    {
        "description": "Investigate prompt injection against the RAG retrieval layer.",
        "focus_area": "injection",
        "priority": "high",
        "search_queries": ["prompt injection rag"],
    },
    {
        "description": "Investigate data leakage via the pgvector store.",
        "focus_area": "data_leakage",
        "priority": "high",
        "search_queries": ["pgvector data leakage"],
    },
    {
        "description": "Investigate supply chain risks in Python dependencies.",
        "focus_area": "supply_chain",
        "priority": "medium",
        "search_queries": ["python supply chain attack"],
    },
    {
        "description": "Investigate denial of service against the LLM API.",
        "focus_area": "dos",
        "priority": "medium",
        "search_queries": ["llm denial of service"],
    },
    {
        "description": "Investigate model extraction via the OpenAI API.",
        "focus_area": "model_extraction",
        "priority": "low",
        "search_queries": ["model extraction openai"],
    },
]


def _analyst_payload(focus_area: str, severity: str) -> dict[str, Any]:
    return {
        "name": f"{focus_area.replace('_', ' ').title()} threat surface",
        "description": (
            f"Identified {focus_area} threats against the target system "
            "based on collected evidence."
        ),
        "severity": severity,
        "attack_vectors": [f"{focus_area} vector A", f"{focus_area} vector B"],
        "mitigations": [f"mitigate {focus_area}"],
        "cvss_score": 8.1 if severity in ("critical", "high") else 5.0,
        "owasp_category": "LLM01" if focus_area == "injection" else None,
    }


def _extract_focus_area(prompt: str) -> str:
    for line in prompt.splitlines():
        if line.startswith("Focus area:"):
            return line.split(":", 1)[1].strip()
    return "other"


class _FakeResp:
    """Minimal duck-typed substitute for langchain AIMessage."""

    def __init__(self, content: str) -> None:
        self.content = content


class _FakeRoutingLLM:
    """Routes prompts to canned responses based on the calling agent.

    Analyst calls are tracked so the first group is HIGH severity (the
    test assertion requires at least one CRITICAL/HIGH surface). Later
    groups alternate to MEDIUM to keep responses non-trivial.
    """

    def __init__(self) -> None:
        self.analyst_calls = 0
        self.analyst_gate_calls = 0
        self.calls: list[str] = []

    async def ainvoke(self, prompt: str, **_: Any) -> _FakeResp:
        self.calls.append(prompt)
        if "Planner agent" in prompt:
            return _FakeResp(json.dumps(_PLANNER_TASKS))
        if "gate the Analyst" in prompt:
            # S8.T2 relevance gate — always on-topic for the canned fixtures.
            self.analyst_gate_calls += 1
            return _FakeResp("yes - findings match the fixture target")
        if "Analyst agent" in prompt:
            self.analyst_calls += 1
            focus = _extract_focus_area(prompt)
            severity = "high" if self.analyst_calls == 1 else "medium"
            return _FakeResp(json.dumps(_analyst_payload(focus, severity)))
        # Researcher relevance scoring or anything else.
        return _FakeResp("0.7")


# --------------------------------------------------------------------------
# Context-aware mock LLM (Sprint 5 end-to-end)
# --------------------------------------------------------------------------


# Imported lazily to keep this module light when only _FakeRoutingLLM is used.
from nexus.agents.critic import OWASP_LLM_TOP10  # noqa: E402
from nexus.schemas.models import FocusArea, Recommendation  # noqa: E402


class ContextAwareMockLLM(_FakeRoutingLLM):
    """End-to-end mock LLM with critic + scoring routing.

    Extends :class:`_FakeRoutingLLM` with:

    * a :class:`Recommendation` queue that drives each Critic evaluation
      (one element popped per evaluation prompt);
    * structured tracking via ``agent_calls`` so tests can assert which
      pipeline nodes invoked the LLM and in what order;
    * a deterministic researcher-scoring response (``"0.85"``) tagged
      ``researcher_scoring`` in ``agent_calls``;
    * a Critic filter response that marks every OWASP category as
      applicable, so the threshold maths is predictable across tests.

    Args:
        recommendations: Recommendations consumed in order, one per
            Critic evaluation. The default ``[APPROVE]`` is enough for
            the single-iteration test.
    """

    def __init__(self, recommendations: list[Recommendation] | None = None) -> None:
        super().__init__()
        self._recs: list[Recommendation] = list(
            recommendations if recommendations is not None else [Recommendation.APPROVE]
        )
        self.agent_calls: list[str] = []
        self.critic_eval_calls: int = 0
        self.critic_filter_calls: int = 0

    async def ainvoke(self, prompt: str, **kwargs: Any) -> _FakeResp:
        if "senior AI security auditor" in prompt:
            self.critic_eval_calls += 1
            self.agent_calls.append("critic")
            if not self._recs:
                raise RuntimeError(
                    "ContextAwareMockLLM exhausted — enqueue more recommendations "
                    "(at least max_iterations elements)",
                )
            rec = self._recs.pop(0)
            return _FakeResp(_critic_eval_payload(rec, self.critic_eval_calls))
        if "OWASP LLM Top 10 catalogue" in prompt:
            self.critic_filter_calls += 1
            # Mark every category applicable so the score arithmetic in the
            # Critic prompt is fully driven by the queued recommendation.
            return _FakeResp(json.dumps(list(OWASP_LLM_TOP10)))
        if "Planner agent" in prompt:
            self.agent_calls.append("planner")
        elif "gate the Analyst" in prompt or "Analyst agent" in prompt:
            # Both the relevance gate and the synthesis call run inside the
            # Analyst node — tag them identically so transition assertions
            # reflect graph-level node ordering.
            self.agent_calls.append("analyst")
        else:
            # Researcher relevance scoring — single-number response.
            self.agent_calls.append("researcher_scoring")
        return await super().ainvoke(prompt, **kwargs)


def _critic_eval_payload(rec: Recommendation, call_index: int) -> str:
    """Build a JSON CriticReport that satisfies the Pydantic validator.

    The ``call_index`` is woven into the re-research task's search query
    so successive iterations dispatch *new* MCP queries instead of
    hitting the Researcher's dedup cache.
    """
    if rec == Recommendation.RE_RESEARCH:
        body: dict[str, Any] = {
            "overall_score": 0.45,
            "gaps": ["LLM10 not covered"],
            "bias_warnings": [],
            "recommendation": rec.value,
            "re_research_tasks": [
                {
                    "description": "Investigate model extraction attacks against the LLM API.",
                    "focus_area": FocusArea.MODEL_EXTRACTION.value,
                    "priority": "high",
                    "search_queries": [f"model extraction follow-up iter{call_index}"],
                },
            ],
        }
    else:
        body = {
            "overall_score": 0.85,
            "gaps": [],
            "bias_warnings": [],
            "recommendation": rec.value,
            "re_research_tasks": [],
        }
    return json.dumps(body)


# --------------------------------------------------------------------------
# Fake MCP client
# --------------------------------------------------------------------------


def _stable_id(server: str, query: str, idx: int) -> str:
    digest = hashlib.sha1(f"{server}|{query}|{idx}".encode()).hexdigest()[:6]
    return f"{server}-{digest}-{idx}"


def _arxiv_items(query: str) -> list[dict[str, Any]]:
    return [
        {
            "arxiv_id": f"2401.{_stable_id('arxiv', query, i)}",
            "title": f"arXiv paper on {query} #{i}",
            "abstract": (
                f"This paper studies {query} attack vectors and discusses "
                "experimental mitigations evaluated against state-of-the-art "
                "language model deployments."
            ),
            "url": f"https://arxiv.org/abs/2401.{i}",
        }
        for i in range(2)
    ]


def _nvd_items(query: str) -> list[dict[str, Any]]:
    return [
        {
            "cve_id": f"CVE-2024-{_stable_id('nvd', query, 0)[-4:]}",
            "description": (
                f"Vulnerability related to {query} affecting AI inference "
                "stacks; allows information disclosure under specific "
                "configurations."
            ),
            "severity": "HIGH",
            "cvss_score": 7.5,
            "published_date": "2024-03-01",
            "last_modified_date": "2024-03-15",
            "references": [f"https://nvd.nist.gov/vuln/detail/CVE-2024-{i}" for i in range(1)],
        },
    ]


def _atlas_items(query: str) -> list[dict[str, Any]]:
    return [
        {
            "technique_id": f"AML.T{_stable_id('atlas', query, 0)[:4]}",
            "name": f"ATLAS technique for {query}",
            "description": (
                f"MITRE ATLAS technique describing how adversaries leverage "
                f"{query} to compromise machine learning systems in production."
            ),
            "tactic": "ml-attack",
            "url": "https://atlas.mitre.org/techniques/AML.T0001",
        },
    ]


_BUILDERS = {
    "arxiv": _arxiv_items,
    "nvd": _nvd_items,
    "atlas": _atlas_items,
}


class _FakeMCPClient:
    """In-memory MCPClient replacement.

    Args:
        error_servers: Names of servers that should raise
            :class:`MCPClientError` when called.
        empty_servers: Names of servers that should return ``[]``.
    """

    def __init__(
        self,
        *,
        error_servers: set[str] | None = None,
        empty_servers: set[str] | None = None,
    ) -> None:
        self.error_servers = set(error_servers or set())
        self.empty_servers = set(empty_servers or set())
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    async def call_tool(
        self,
        server_name: str,
        tool_name: str,
        **kwargs: Any,
    ) -> str:
        self.calls.append((server_name, tool_name, dict(kwargs)))
        if server_name in self.error_servers:
            raise MCPClientError(f"forced failure for {server_name}.{tool_name}")
        if server_name in self.empty_servers:
            return json.dumps([])
        builder = _BUILDERS.get(server_name)
        if builder is None:
            return json.dumps([])
        query = str(kwargs.get("query") or kwargs.get("keyword") or "default")
        return json.dumps(builder(query))

    async def aclose(self) -> None:
        return None


# --------------------------------------------------------------------------
# Pytest fixtures
# --------------------------------------------------------------------------


@pytest.fixture
def mock_llm() -> _FakeRoutingLLM:
    """Routing fake LLM shared by Planner and Analyst nodes."""
    return _FakeRoutingLLM()


@pytest.fixture
def mock_mcp_client() -> _FakeMCPClient:
    """Default fake MCP client — every server returns canned findings."""
    return _FakeMCPClient()
