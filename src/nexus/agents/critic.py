"""Critic agent — evaluates threat surfaces against OWASP LLM Top 10.

Pipeline:
    1. Determine which OWASP LLM Top 10 categories are applicable to the
       current ``target_description`` via a lightweight LLM call. The
       call falls back to "all categories applicable" if the response
       cannot be parsed.
    2. Build a structured prompt that includes the threat-surface
       summary (names, descriptions, ``owasp_category``) and the
       applicable category list, then ask the LLM for a strict JSON
       :class:`CriticReport`.
    3. Parse the response, retry once on validation error, and validate
       the result against the :class:`CriticReport` schema.
    4. Apply guardrails: force ``APPROVE`` when the score crosses 0.6
       *or* the loop has reached ``max_iterations`` — this mirrors the
       behaviour the :class:`ControllableCriticStub` exhibited during
       S5.T1 routing validation.

Both LLM calls are instrumented with the Langfuse callback handler so
the agent contributes the first real traces to the ``nexus/session``
hierarchy.
"""

from __future__ import annotations

import json
from typing import Any, cast

from nexus.agents.base import AgentBase
from nexus.exceptions import AgentError
from nexus.observability.langfuse import get_langfuse_handler
from nexus.schemas.models import (
    AgentState,
    CriticReport,
    FocusArea,
    Recommendation,
    ThreatSurface,
)
from nexus.settings import get_settings

# ---------------------------------------------------------------------------
# OWASP LLM Top 10 (2025 wording)
# ---------------------------------------------------------------------------

OWASP_LLM_TOP10: dict[str, str] = {
    "LLM01": "Prompt Injection — manipulating LLM via crafted inputs",
    "LLM02": "Insecure Output Handling — not validating LLM outputs before use",
    "LLM03": "Training Data Poisoning — corrupting training data to influence behavior",
    "LLM04": "Model Denial of Service — resource-exhausting inputs to degrade availability",
    "LLM05": "Supply Chain Vulnerabilities — compromised components in ML pipeline",
    "LLM06": "Sensitive Information Disclosure — LLM revealing confidential data",
    "LLM07": "Insecure Plugin Design — LLM plugins lacking proper access controls",
    "LLM08": "Excessive Agency — LLM taking high-impact actions beyond intended scope",
    "LLM09": "Overreliance — depending on LLM without adequate oversight",
    "LLM10": "Model Theft — unauthorized extraction of proprietary model",
}

# Maps OWASP category → most relevant FocusArea so re-research tasks emitted
# for a gap pick a focus_area that the Researcher knows how to dispatch.
_OWASP_TO_FOCUS: dict[str, FocusArea] = {
    "LLM01": FocusArea.INJECTION,
    "LLM02": FocusArea.INJECTION,
    "LLM03": FocusArea.SUPPLY_CHAIN,
    "LLM04": FocusArea.DENIAL_OF_SERVICE,
    "LLM05": FocusArea.SUPPLY_CHAIN,
    "LLM06": FocusArea.DATA_LEAKAGE,
    "LLM07": FocusArea.OTHER,
    "LLM08": FocusArea.OTHER,
    "LLM09": FocusArea.OTHER,
    "LLM10": FocusArea.MODEL_EXTRACTION,
}

_APPROVE_THRESHOLD = 0.6


class CriticAgent(AgentBase):
    """Scores OWASP coverage, identifies gaps, and gates the final report."""

    agent_name = "critic"

    def __init__(self, llm: Any | None = None) -> None:
        super().__init__()
        self._llm = llm
        self.last_prompts: list[str] = []  # exposed for tests / debugging

    async def run(self, state: AgentState) -> AgentState:
        """Evaluate threat surfaces and produce a :class:`CriticReport`.

        Raises:
            AgentError: When the LLM call fails or the response cannot
                be validated even after one retry.
        """
        self._log_start(state)
        if not state["threat_surfaces"]:
            raise AgentError("CriticAgent requires at least one threat surface in state")

        callbacks = self._callbacks(state)
        applicable = await self._select_applicable_categories(
            state["target_description"],
            callbacks=callbacks,
            iteration=state["iteration_count"],
        )
        report = await self._evaluate(
            state=state,
            applicable=applicable,
            callbacks=callbacks,
        )
        report = self._apply_guardrails(report, state)
        return cast(AgentState, {**state, "critic_report": report})

    # ----- Langfuse ---------------------------------------------------------

    def _callbacks(self, state: AgentState) -> list[Any]:
        handler = get_langfuse_handler(state["session_id"])
        return [handler] if handler is not None else []

    def _config(self, callbacks: list[Any], iteration: int, step: str) -> dict[str, Any]:
        return {
            "callbacks": callbacks,
            "metadata": {
                "agent": self.agent_name,
                "iteration": iteration,
                "step": step,
            },
        }

    # ----- applicable categories -------------------------------------------

    async def _select_applicable_categories(
        self,
        target: str,
        *,
        callbacks: list[Any],
        iteration: int,
    ) -> list[str]:
        """Filter OWASP_LLM_TOP10 to categories relevant for ``target``.

        The Critic asks the LLM for a JSON list of category IDs. On any
        parse failure we fall back to "all categories apply" — a
        conservative default that keeps the evaluation strict.
        """
        prompt = _filter_prompt(target)
        self.last_prompts.append(prompt)
        llm = self._llm or self._get_llm()
        try:
            response = await llm.ainvoke(
                prompt,
                config=self._config(callbacks, iteration, "filter_categories"),
            )
        except Exception as exc:
            raise AgentError(f"Critic filter LLM call failed: {exc}") from exc

        text = str(getattr(response, "content", response)).strip()
        try:
            payload = _extract_json_array(text)
        except ValueError:
            self._logger.warning(
                "critic_filter_unparseable",
                preview=text[:120],
                fallback="all OWASP categories",
            )
            return list(OWASP_LLM_TOP10.keys())

        keys = [str(item) for item in payload if str(item) in OWASP_LLM_TOP10]
        if not keys:
            self._logger.warning("critic_filter_empty", fallback="all OWASP categories")
            return list(OWASP_LLM_TOP10.keys())
        return keys

    # ----- main evaluation --------------------------------------------------

    async def _evaluate(
        self,
        *,
        state: AgentState,
        applicable: list[str],
        callbacks: list[Any],
    ) -> CriticReport:
        prompt = _eval_prompt(
            target=state["target_description"],
            surfaces=state["threat_surfaces"],
            applicable=applicable,
        )
        self.last_prompts.append(prompt)
        llm = self._llm or self._get_llm()

        text = await self._invoke_eval(llm, prompt, callbacks, state["iteration_count"])
        first_error: str | None = None
        try:
            return _parse_critic_report(text)
        except Exception as exc:  # noqa: BLE001
            first_error = str(exc)
            self._logger.warning(
                "critic_eval_invalid_first_pass",
                error=first_error,
                action="retry_once",
            )

        retry_prompt = _retry_prompt(prompt, text, first_error or "validation failure")
        self.last_prompts.append(retry_prompt)
        retry_text = await self._invoke_eval(
            llm,
            retry_prompt,
            callbacks,
            state["iteration_count"],
        )
        try:
            return _parse_critic_report(retry_text)
        except Exception as exc:
            raise AgentError(f"Critic produced an invalid CriticReport: {exc}") from exc

    async def _invoke_eval(
        self,
        llm: Any,
        prompt: str,
        callbacks: list[Any],
        iteration: int,
    ) -> str:
        try:
            response = await llm.ainvoke(
                prompt,
                config=self._config(callbacks, iteration, "evaluate"),
            )
        except Exception as exc:
            raise AgentError(f"Critic evaluation LLM call failed: {exc}") from exc
        return str(getattr(response, "content", response)).strip()

    # ----- guardrails -------------------------------------------------------

    def _apply_guardrails(self, report: CriticReport, state: AgentState) -> CriticReport:
        """Force APPROVE when the score crosses the threshold or we hit max_iterations."""
        max_iterations = get_settings().max_iterations
        iteration = state["iteration_count"]
        force = report.overall_score >= _APPROVE_THRESHOLD or iteration >= max_iterations
        if force and report.recommendation == Recommendation.RE_RESEARCH:
            self._logger.warning(
                "critic_force_approve",
                score=report.overall_score,
                iteration=iteration,
                max_iterations=max_iterations,
            )
            return report.model_copy(
                update={
                    "recommendation": Recommendation.APPROVE,
                    "re_research_tasks": [],
                },
            )
        return report


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------


def _filter_prompt(target: str) -> str:
    catalogue = "\n".join(f"- {k}: {v}" for k, v in OWASP_LLM_TOP10.items())
    return (
        "You are the Critic agent for an AI security threat-modelling pipeline.\n"
        "Decide which OWASP LLM Top 10 categories are APPLICABLE to the target "
        "architecture below — exclude categories that cannot plausibly affect "
        "this system (e.g. LLM07 if no plugins are mentioned).\n\n"
        f"Target architecture:\n{target}\n\n"
        f"OWASP LLM Top 10 catalogue:\n{catalogue}\n\n"
        'Return ONLY a JSON array of category IDs, e.g. ["LLM01", "LLM04", '
        '"LLM06"]. No prose, no markdown.'
    )


def _surface_summary(surfaces: list[ThreatSurface]) -> str:
    items = []
    for s in surfaces:
        items.append(
            json.dumps(
                {
                    "name": s.name,
                    "description": s.description[:200],
                    "owasp_category": s.owasp_category,
                    "severity": s.severity.value,
                },
            ),
        )
    return "\n".join(items)


def _eval_prompt(
    *,
    target: str,
    surfaces: list[ThreatSurface],
    applicable: list[str],
) -> str:
    applicable_block = "\n".join(f"- {k}: {OWASP_LLM_TOP10[k]}" for k in applicable)
    focus_map = ", ".join(f"{k}→{v.value}" for k, v in _OWASP_TO_FOCUS.items())
    return (
        "You are a senior AI security auditor evaluating completeness of a "
        "threat model.\n\n"
        f"Target architecture:\n{target}\n\n"
        "Threat surfaces produced by the Analyst (JSON, one per line):\n"
        f"{_surface_summary(surfaces)}\n\n"
        "Applicable OWASP LLM Top 10 categories for this target:\n"
        f"{applicable_block}\n\n"
        "Score the model: overall_score = covered_categories / "
        f"{len(applicable)}, where 'covered' means at least one threat "
        "surface explicitly addresses that OWASP category in its "
        "owasp_category field.\n"
        "If overall_score >= 0.6, recommendation MUST be 'approve'.\n"
        "If overall_score < 0.6, recommendation MUST be 're_research' and "
        "you MUST emit one ResearchTask per uncovered applicable category "
        "(at least one task).\n"
        f"Map uncovered OWASP categories to focus_area using: {focus_map}.\n\n"
        "Return ONLY a JSON object matching this schema:\n"
        "{\n"
        '  "overall_score": float in [0,1],\n'
        '  "gaps": [string, ...],\n'
        '  "bias_warnings": [string, ...],\n'
        '  "recommendation": "approve" | "re_research",\n'
        '  "re_research_tasks": [\n'
        "    {\n"
        '      "description": "<min 10 chars>",\n'
        '      "focus_area": "<one of injection|data_leakage|supply_chain|dos'
        '|model_extraction|other>",\n'
        '      "priority": "high"|"medium"|"low",\n'
        '      "search_queries": ["..."]\n'
        "    }\n"
        "  ]\n"
        "}\n"
        "No prose, no markdown."
    )


def _retry_prompt(original: str, bad: str, error: str) -> str:
    return (
        "Your previous response could not be validated as a CriticReport.\n"
        f"Validation error: {error}\n\n"
        "Previous response:\n"
        f"{bad[:1500]}\n\n"
        "Re-emit a STRICTLY valid JSON object that satisfies the schema "
        "described in the original instructions below.\n"
        "Remember: re_research_tasks must be a non-empty list when "
        "recommendation is 're_research'.\n\n"
        "Original instructions:\n"
        f"{original}"
    )


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def _parse_critic_report(text: str) -> CriticReport:
    payload = _extract_json_object(text)
    return CriticReport.model_validate(payload)


def _extract_json_object(text: str) -> dict[str, Any]:
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


def _extract_json_array(text: str) -> list[Any]:
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
