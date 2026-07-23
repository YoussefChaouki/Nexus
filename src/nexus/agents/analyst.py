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
       b. Build a structured prompt (target architecture + focus area +
          top findings + patterns) and ask the LLM for a single
          :class:`ThreatSurface` JSON object.
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
# Caps the findings block in the synthesis prompt — beyond this the extra
# low-relevance items dilute the context without adding signal.
_MAX_FINDINGS_IN_PROMPT = 12

# Severity ordering used by the evidence-quality downgrade.
_SEVERITY_ORDER: list[Severity] = [
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]

# Triggers a one-band downgrade when evidence is thin / weak.
_MIN_EVIDENCE_FOR_FULL_BAND = 2
_MIN_TOP_RELEVANCE_FOR_FULL_BAND = 0.6

# Canonical OWASP LLM Top 10 category per focus area. Used as the
# deterministic fallback when the LLM emits a null owasp_category for a
# surface that plainly maps to one (an unauth DoS on an LLM service IS
# LLM04) — the Critic's coverage score counts owasp_category fields, so
# null surfaces silently freeze the feedback loop. OTHER stays None.
_FOCUS_TO_OWASP: dict[FocusArea, str | None] = {
    FocusArea.INJECTION: "LLM01",
    FocusArea.DATA_LEAKAGE: "LLM06",
    FocusArea.SUPPLY_CHAIN: "LLM05",
    FocusArea.DENIAL_OF_SERVICE: "LLM04",
    FocusArea.MODEL_EXTRACTION: "LLM10",
    FocusArea.OTHER: None,
}


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
        # Focus areas the Critic explicitly demanded via re_research_tasks
        # bypass the relevance gate: skipping a category the Critic just
        # asked to cover guarantees a wasted iteration (observed in prod —
        # data_leakage gated out three passes in a row).
        critic = state["critic_report"]
        demanded: set[FocusArea] = (
            {t.focus_area for t in critic.re_research_tasks} if critic is not None else set()
        )
        self.last_prompts = []
        surfaces: list[ThreatSurface] = []
        for focus_area, findings in groups.items():
            if focus_area in demanded:
                self._logger.info(
                    "analyst_gate_bypassed",
                    session_id=state["session_id"],
                    focus_area=focus_area.value,
                    reason="critic_demanded_re_research",
                )
            elif not await self._group_is_relevant(focus_area, findings, state):
                self._logger.info(
                    "analyst_skipped_off_target",
                    session_id=state["session_id"],
                    focus_area=focus_area.value,
                    finding_count=len(findings),
                    finding_ids=[f.id for f in findings],
                )
                continue
            patterns = await self._fetch_patterns(findings)
            surface = await self._synthesise(focus_area, findings, patterns, state)
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

    # ----- relevance gate ---------------------------------------------------

    async def _group_is_relevant(
        self,
        focus_area: FocusArea,
        findings: list[FindingResult],
        state: AgentState,
    ) -> bool:
        """Ask the LLM whether this finding group is on-topic for the target.

        Returns ``True`` when the LLM answers ``yes`` (or when the call
        fails) — we never let observability hiccups silently drop a
        surface. A ``no`` answer is logged and the surface is skipped.
        """
        prompt = self._build_relevance_prompt(focus_area, findings, state["target_description"])
        llm = self._llm or self._get_llm()
        try:
            response = await llm.ainvoke(
                prompt,
                config=self._invoke_config(
                    state,
                    step="relevance_gate",
                    extra_metadata={
                        "focus_area": focus_area.value,
                        "finding_count": len(findings),
                    },
                ),
            )
        except Exception as exc:
            self._logger.warning(
                "analyst_relevance_gate_failed",
                focus_area=focus_area.value,
                error=str(exc),
            )
            return True

        text = str(getattr(response, "content", response)).strip().lower()
        first_token = text.split()[0] if text else ""
        first_token = first_token.strip(".,:;\"'")
        return not first_token.startswith("no")

    def _build_relevance_prompt(
        self,
        focus_area: FocusArea,
        findings: list[FindingResult],
        target_description: str,
    ) -> str:
        bullets = "\n".join(
            f"- [{f.source_type.value}] {f.title} :: {f.summary[:_FINDING_SUMMARY_CHARS]}"
            for f in findings[:_TOP_FINDINGS_FOR_EMBED]
        )
        return (
            "You gate the Analyst against off-topic synthesis.\n"
            f"Target architecture: {target_description}\n"
            f"Focus area: {focus_area.value}\n\n"
            "Findings collected by the Researcher:\n"
            f"{bullets}\n\n"
            "Could a meaningful threat surface for this focus area on this "
            "target be built from these findings?\n"
            "Answer 'no' ONLY when the findings clearly belong to an "
            "unrelated domain (e.g. mobile-banking malware for a RAG "
            "pipeline). Thin, weak, or generic evidence is NOT a reason to "
            "answer no — severity calibration downgrades weak evidence "
            "downstream. When in doubt, answer yes.\n"
            "Reply on a single line in the form 'yes - <one-sentence why>' "
            "or 'no - <one-sentence why>'."
        )

    # ----- LLM synthesis ----------------------------------------------------

    async def _synthesise(
        self,
        focus_area: FocusArea,
        findings: list[FindingResult],
        patterns: list[ThreatPattern],
        state: AgentState,
    ) -> ThreatSurface:
        prompt = self._build_prompt(
            focus_area,
            findings,
            patterns,
            state["target_description"],
        )
        self.last_prompts.append(prompt)

        llm = self._llm or self._get_llm()
        try:
            response = await llm.ainvoke(
                prompt,
                config=self._invoke_config(
                    state,
                    step="synthesise",
                    extra_metadata={
                        "focus_area": focus_area.value,
                        "finding_count": len(findings),
                        "pattern_count": len(patterns),
                    },
                ),
            )
        except Exception as exc:
            raise AgentError(f"Analyst LLM call failed: {exc}") from exc

        text = str(getattr(response, "content", response)).strip()
        try:
            payload = _extract_json_object(text)
        except ValueError as exc:
            raise AgentError(f"Analyst could not parse LLM JSON: {exc}") from exc

        # Severity rubric prompt uses uppercase bands for readability; LLMs
        # mimic that casing and emit "HIGH" instead of the enum value "high".
        if isinstance(payload.get("severity"), str):
            payload["severity"] = payload["severity"].strip().lower()

        # The LLM never invents evidence — we attach the real FindingResult
        # objects (strongest first) so the schema's require_evidence
        # validator always passes and report readers see the best citations
        # at the top.
        ranked = sorted(findings, key=lambda f: f.relevance_score, reverse=True)
        payload["evidence"] = [f.model_dump() for f in ranked]

        # Deterministic OWASP fallback — GPT-4o reads infra-style threats
        # (SQL injection, endpoint flooding) as outside the OWASP *LLM*
        # taxonomy and returns null, which the Critic's coverage score
        # then can't credit.
        if not payload.get("owasp_category"):
            default_owasp = _FOCUS_TO_OWASP.get(focus_area)
            if default_owasp is not None:
                payload["owasp_category"] = default_owasp
                self._logger.info(
                    "analyst_owasp_defaulted",
                    session_id=state["session_id"],
                    focus_area=focus_area.value,
                    owasp_category=default_owasp,
                )

        downgraded = _maybe_downgrade(payload, findings)
        if downgraded is not None:
            self._logger.info(
                "analyst_severity_downgraded",
                session_id=state["session_id"],
                focus_area=focus_area.value,
                original=str(payload.get("severity")),
                downgraded=downgraded.value,
                evidence_count=len(findings),
                top_relevance=max((f.relevance_score for f in findings), default=0.0),
            )
            payload["severity"] = downgraded.value

        try:
            return ThreatSurface.model_validate(payload)
        except Exception as exc:
            raise AgentError(f"Analyst produced an invalid ThreatSurface: {exc}") from exc

    def _build_prompt(
        self,
        focus_area: FocusArea,
        findings: list[FindingResult],
        patterns: list[ThreatPattern],
        target_description: str,
    ) -> str:
        severities = ", ".join(s.value for s in Severity)
        # Strongest evidence first; cap so weak tail findings don't dilute
        # the synthesis context.
        top_findings = sorted(findings, key=lambda f: f.relevance_score, reverse=True)[
            :_MAX_FINDINGS_IN_PROMPT
        ]
        findings_block = "\n".join(
            f"- [{f.source_type.value}] {f.title} :: {f.summary[:_FINDING_SUMMARY_CHARS]}"
            for f in top_findings
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
            f"Target architecture under analysis:\n{target_description}\n\n"
            f"Focus area: {focus_area.value}\n\n"
            "Findings collected by the Researcher (strongest first):\n"
            f"{findings_block}\n\n"
            "Related threat patterns (ATLAS / OWASP LLM Top 10):\n"
            f"{patterns_block}\n\n"
            f"{_SEVERITY_RUBRIC}\n\n"
            f"{_FEW_SHOT_EXAMPLES}\n\n"
            "Now synthesise ONE ThreatSurface that summarises the threat for "
            "this focus area AGAINST THE TARGET ARCHITECTURE ABOVE.\n"
            "Ground the description, attack_vectors and mitigations in the "
            "target's actual components and trust boundaries (auth model, "
            "ingestion paths, exposed services) — not in generic advice.\n"
            f"Severity must be one of: {severities}. Calibrate it against the "
            "rubric above using the target's trust boundaries — do NOT "
            "default to HIGH. If the evidence does not demonstrate impact at "
            "a band for THIS target, pick the lower one.\n"
            "Pick owasp_category from the OWASP LLM Top 10 (e.g. LLM01, "
            "LLM02, LLM06, ...). Judge the threat IN THE CONTEXT of the LLM "
            "service: an unauthenticated DoS on an LLM API is LLM04, data "
            "exfiltration through the LLM context is LLM06. Default mapping "
            "by focus area when nothing more specific applies: "
            "injection→LLM01, data_leakage→LLM06, dos→LLM04, "
            "supply_chain→LLM05, model_extraction→LLM10. "
            f"{_other_owasp_hint(focus_area)}"
            "Use null only when no LLM-specific category fits at all.\n"
            "Return ONLY a JSON object with keys: name, description, "
            "severity, severity_reasoning, attack_vectors, mitigations, "
            "cvss_score (0-10 or null), owasp_category. "
            "severity_reasoning must be a one-sentence justification using "
            "the rubric language (e.g. 'untrusted user upload reaches "
            "embedding pipeline without sanitization → CRITICAL data exfil'). "
            "Do not include 'evidence' — the agent attaches it.\n"
            "description must be at least 30 characters; mitigations must "
            "be a non-empty list of strings. Do not wrap in markdown."
        )


# --- prompt blocks ---------------------------------------------------------


_SEVERITY_RUBRIC = """\
Severity rubric (CVSS bands + business-impact framing):
- CRITICAL → Remote code execution, full data exfiltration, or authentication
  bypass on the trust boundary. CVSS ≥ 9.0. Pick this when an untrusted input
  reaches a privileged sink with no mitigation in the target description.
- HIGH → Privilege escalation, partial data leak, or denial of service at
  scale. CVSS 7.0–8.9. Pick this when impact is significant but bounded
  (e.g. requires authenticated user, single-tenant blast radius).
- MEDIUM → Degraded availability, non-secret information leak, or
  misconfiguration that requires another flaw to be exploited. CVSS 4.0–6.9.
- LOW → Reconnaissance, minor misconfig, defense-in-depth issue with no
  direct exploit path. CVSS < 4.0.

When in doubt, prefer the LOWER band. A flat HIGH distribution is a failure
mode of this agent — the rubric exists to spread severity meaningfully."""


_FEW_SHOT_EXAMPLES = """\
Examples (these are templates, NOT outputs to copy verbatim):

Example 1 — CRITICAL
  Target: "Public RAG API, no authentication, user upload to embedding store"
  Reasoning: untrusted user uploads reach the vector DB and downstream LLM
  context with no auth gate → an attacker can poison embeddings AND exfil
  other tenants' data through crafted prompts → CRITICAL data exfil + auth
  bypass on the trust boundary.

Example 2 — HIGH
  Target: "Authenticated chatbot with tool calling, OpenAI moderation
  enabled, no per-tool sandbox"
  Reasoning: prompt injection can pivot through the tool layer to leak
  per-user data, but the attacker needs a valid account first → bounded
  blast radius, privilege escalation within tenant → HIGH.

Example 3 — MEDIUM
  Target: "Internal-only summarisation service behind SSO, logs scrubbed
  before storage"
  Reasoning: prompt-injection still possible but no untrusted upload path,
  data exfil capped at one user's own prompts, no privileged tools wired →
  MEDIUM degraded confidentiality at most."""


# --- helpers ---------------------------------------------------------------


def _other_owasp_hint(focus_area: FocusArea) -> str:
    """Category guidance for focus areas that collapse multiple OWASP codes.

    LLM02/07/08/09 all map to FocusArea.OTHER — without an explicit label
    from the LLM these surfaces stay null and the Critic's coverage score
    can never credit them, freezing the feedback loop below threshold.

    LLM03 (training data poisoning) and LLM05 (supply chain vulnerabilities)
    both map to FocusArea.SUPPLY_CHAIN, but the default-mapping sentence in
    the prompt only ever mentions LLM05 — biasing the LLM toward LLM05 even
    when the finding is specifically about poisoned training data.
    """
    if focus_area is FocusArea.OTHER:
        return (
            "For this 'other' focus area, choose the BEST-FITTING of: LLM02 "
            "(insecure output handling), LLM07 (insecure plugin design), LLM08 "
            "(excessive agency — autonomous tools, no human approval), LLM09 "
            "(overreliance). "
        )
    if focus_area is FocusArea.SUPPLY_CHAIN:
        return (
            "For this 'supply_chain' focus area, use LLM03 (training data "
            "poisoning) instead of the LLM05 default when the finding is "
            "about corrupted/poisoned training or fine-tuning data rather "
            "than a compromised dependency, artifact, or pipeline component. "
        )
    return ""


def _maybe_downgrade(
    payload: dict[str, Any],
    findings: list[FindingResult],
) -> Severity | None:
    """Return a downgraded :class:`Severity` when evidence quality is thin.

    Triggers when fewer than :data:`_MIN_EVIDENCE_FOR_FULL_BAND` findings
    back the surface, or the highest relevance score sits below
    :data:`_MIN_TOP_RELEVANCE_FOR_FULL_BAND`. Returns ``None`` when no
    downgrade applies or the LLM emitted an unparseable severity.
    """
    raw = payload.get("severity")
    if not isinstance(raw, str):
        return None
    try:
        current = Severity(raw.lower())
    except ValueError:
        return None

    top_relevance = max((f.relevance_score for f in findings), default=0.0)
    thin_evidence = len(findings) < _MIN_EVIDENCE_FOR_FULL_BAND
    weak_relevance = top_relevance < _MIN_TOP_RELEVANCE_FOR_FULL_BAND
    if not (thin_evidence or weak_relevance):
        return None

    return _downgrade_severity(current)


def _downgrade_severity(severity: Severity) -> Severity:
    """Drop ``severity`` by one band. LOW is a fixed point."""
    try:
        idx = _SEVERITY_ORDER.index(severity)
    except ValueError:
        return severity
    return _SEVERITY_ORDER[max(0, idx - 1)]


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
