"""Fixtures for the partial pipeline integration tests.

These fixtures stand in for the real LLM and MCP transport while still
exercising the actual LangGraph nodes and Pydantic schemas. Two fakes
are provided:

* :class:`_FakeRoutingLLM` — routes a single ``ainvoke`` entry point to
  three different responses (Planner / Analyst / scoring) based on the
  prompt content. The Analyst branch reads the ``Focus area:`` line of
  the prompt so each focus_area group gets a distinct ThreatSurface.

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
        self.calls: list[str] = []

    async def ainvoke(self, prompt: str, **_: Any) -> _FakeResp:
        self.calls.append(prompt)
        if "Planner agent" in prompt:
            return _FakeResp(json.dumps(_PLANNER_TASKS))
        if "Analyst agent" in prompt:
            self.analyst_calls += 1
            focus = _extract_focus_area(prompt)
            severity = "high" if self.analyst_calls == 1 else "medium"
            return _FakeResp(json.dumps(_analyst_payload(focus, severity)))
        # Researcher relevance scoring or anything else.
        return _FakeResp("0.7")


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
