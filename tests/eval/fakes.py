"""Deterministic fakes for offline (``use_real_llm=False``) eval runs.

:class:`EvalMockLLM` drives the *real* LangGraph agents with stable,
architecture-independent responses so the harness — and the CI test that
exercises it — produces reproducible coverage numbers without a live
model. It recognises the same prompt markers the production agents emit
(verified by the Sprint 5 integration suite):

* ``"Planner agent"``            → one ResearchTask per primary FocusArea
* ``"Analyst agent"`` + ``"Focus area:"`` → one ThreatSurface per group
* ``"senior AI security auditor"``       → Critic evaluation (APPROVE)
* ``"OWASP LLM Top 10 catalogue"``       → Critic applicability filter

The Analyst branch maps each FocusArea to its canonical OWASP category
and a human-readable surface name, so the harness measures a realistic —
if optimistic — coverage profile for the offline path.

:func:`baseline_mock_llm` returns a tiny fake for the single-prompt
baseline so the baseline path is testable without an API key.
"""

from __future__ import annotations

import json
from typing import Any

from nexus.schemas.models import FocusArea

# FocusArea → (OWASP code, canonical surface name) used by the mock Analyst.
_FOCUS_TO_SURFACE: dict[FocusArea, tuple[str, str]] = {
    FocusArea.INJECTION: ("LLM01", "Prompt Injection"),
    FocusArea.DATA_LEAKAGE: ("LLM06", "Sensitive Information Disclosure"),
    FocusArea.SUPPLY_CHAIN: ("LLM05", "Supply Chain Vulnerabilities"),
    FocusArea.DENIAL_OF_SERVICE: ("LLM04", "Model Denial of Service"),
    FocusArea.MODEL_EXTRACTION: ("LLM10", "Model Theft"),
    FocusArea.OTHER: ("", "Other Threat Surface"),
}

# Severity assigned per focus area so the offline run is not flat-HIGH.
_FOCUS_TO_SEVERITY: dict[FocusArea, str] = {
    FocusArea.INJECTION: "critical",
    FocusArea.DATA_LEAKAGE: "high",
    FocusArea.SUPPLY_CHAIN: "high",
    FocusArea.DENIAL_OF_SERVICE: "medium",
    FocusArea.MODEL_EXTRACTION: "medium",
    FocusArea.OTHER: "low",
}

_PLANNER_TASKS: list[dict[str, Any]] = [
    {
        "description": "Investigate prompt injection against the retrieval layer.",
        "focus_area": FocusArea.INJECTION.value,
        "priority": "high",
        "search_queries": ["prompt injection"],
    },
    {
        "description": "Audit data leakage and sensitive information disclosure paths.",
        "focus_area": FocusArea.DATA_LEAKAGE.value,
        "priority": "high",
        "search_queries": ["data leakage llm"],
    },
    {
        "description": "Survey supply-chain risks across the ML toolchain.",
        "focus_area": FocusArea.SUPPLY_CHAIN.value,
        "priority": "medium",
        "search_queries": ["ml supply chain"],
    },
    {
        "description": "Map denial-of-service vectors against model serving.",
        "focus_area": FocusArea.DENIAL_OF_SERVICE.value,
        "priority": "medium",
        "search_queries": ["model denial of service"],
    },
    {
        "description": "Catalogue model-extraction and model-theft techniques.",
        "focus_area": FocusArea.MODEL_EXTRACTION.value,
        "priority": "low",
        "search_queries": ["model extraction"],
    },
]


class _FakeResp:
    """Minimal duck-typed substitute for a langchain AIMessage."""

    def __init__(self, content: str) -> None:
        self.content = content


def _focus_from_prompt(prompt: str) -> FocusArea:
    for line in prompt.splitlines():
        if line.startswith("Focus area:"):
            raw = line.split(":", 1)[1].strip()
            try:
                return FocusArea(raw)
            except ValueError:
                return FocusArea.OTHER
    return FocusArea.OTHER


def _analyst_payload(focus: FocusArea) -> dict[str, Any]:
    owasp, name = _FOCUS_TO_SURFACE[focus]
    severity = _FOCUS_TO_SEVERITY[focus]
    return {
        "name": name,
        "description": (
            f"{name} threat surface derived from collected evidence "
            f"targeting the {focus.value} focus area of the system."
        ),
        "severity": severity,
        "attack_vectors": [f"{focus.value} vector A", f"{focus.value} vector B"],
        "mitigations": [f"Mitigate {focus.value} exposure"],
        "cvss_score": 9.1 if severity == "critical" else 6.5,
        "owasp_category": owasp or None,
        "severity_reasoning": (
            f"Severity {severity} assigned for the {focus.value} focus area "
            "based on the offline eval rubric."
        ),
    }


class EvalMockLLM:
    """Deterministic, architecture-independent LLM for offline eval runs."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def ainvoke(self, prompt: str, **_: Any) -> _FakeResp:
        self.calls.append(prompt)
        if "senior AI security auditor" in prompt:
            return _FakeResp(
                json.dumps(
                    {
                        "overall_score": 0.85,
                        "gaps": [],
                        "bias_warnings": [],
                        "recommendation": "approve",
                        "re_research_tasks": [],
                    }
                )
            )
        if "OWASP LLM Top 10 catalogue" in prompt:
            from nexus.agents.critic import OWASP_LLM_TOP10

            return _FakeResp(json.dumps(list(OWASP_LLM_TOP10)))
        if "Planner agent" in prompt:
            return _FakeResp(json.dumps(_PLANNER_TASKS))
        if "Analyst agent" in prompt:
            return _FakeResp(json.dumps(_analyst_payload(_focus_from_prompt(prompt))))
        # Researcher relevance scoring or anything else → high single number.
        return _FakeResp("0.8")


class _BaselineMockLLM:
    """Single-call fake for the offline single-prompt baseline.

    Returns a deliberately partial answer (two OWASP categories, two
    surface names) so the baseline scores below the multi-agent pipeline
    — mirroring the qualitative gap the harness is meant to demonstrate.
    """

    def __init__(self, content: str | None = None) -> None:
        self._content = content or json.dumps(
            {
                "owasp_categories": ["LLM01", "LLM06"],
                "threat_surfaces": ["Prompt Injection", "Data Leakage"],
            }
        )
        self.calls: list[str] = []

    async def ainvoke(self, prompt: str, **_: Any) -> _FakeResp:
        self.calls.append(prompt)
        return _FakeResp(self._content)


def baseline_mock_llm(content: str | None = None) -> _BaselineMockLLM:
    """Return a single-prompt baseline fake (optionally fixed content)."""
    return _BaselineMockLLM(content)
