# A real run, traced node by node

This isn't a hypothetical example — it's the actual SSE event log and final
report from one live GPT-4o run, captured on 2026-07-24. Picked deliberately
because it exercises the Critic → Researcher feedback loop, the piece of the
design a single-prompt baseline can't replicate.

## Input

```bash
curl -N -G "localhost:8000/analyze/stream" \
  --data-urlencode "target_description=FastAPI backend serving pgvector RAG over internal HR documents, OpenAI GPT-4o, SSO-authenticated internal users only"
```

## Timeline

Every row below is a real `AgentEvent` from the SSE stream, with the wall-clock
offset from pipeline start:

| t | agent | event | plan | findings | surfaces | critic |
|---|-------|-------|------|----------|----------|--------|
| 0.0s | pipeline | started | — | — | — | — |
| 6.6s | planner | node_completed | 6 tasks | 0 | 0 | — |
| 26.7s | researcher | node_completed | 6 | **7** | 0 | — |
| 35.6s | analyst | node_completed | 6 | 7 | **2** | — |
| 40.2s | critic | node_completed | 6 | 7 | 2 | **0.4 → re_research** |
| 58.0s | researcher (pass 2) | node_completed | **9** | **9** | 2 | 0.4 |
| 76.2s | analyst (pass 2) | node_completed | 9 | 9 | **3** | 0.4 |
| 80.1s | critic (pass 2) | node_completed | 9 | 9 | 3 | **0.6 → approve** |
| 80.8s | writer | node_completed | 9 | 9 | 3 | 0.6 (final) |

Total: **80.8s, 2 passes.**

## What happened at each step

**Planner** — decomposed the target into 6 `ResearchTask`, one per candidate
`FocusArea`. It also checks episodic memory for similar past architectures
(cosine similarity > 0.85); none matched closely enough here, so no prior
context was injected.

**Researcher (pass 1)** — fanned the 6 tasks' search queries out to arXiv and
NVD in parallel (ATLAS returned nothing — see the [known limitation](../README.md#evidence-sources-and-memory)).
7 `FindingResult` survived the relevance gate (`researcher_min_relevance=0.5`,
`researcher_min_context_relevance=0.35` — the two-stage filter that rejects
off-topic findings like the historical M-Banking-CVE-on-a-RAG-pipeline
incident).

**Analyst (pass 1)** — grouped the 7 findings by focus area and synthesized
**2** `ThreatSurface`, each grounded in the target's actual trust boundary
(`SSO-authenticated`, `internal`) per the severity rubric.

**Critic (pass 1)** — recomputed OWASP coverage *in code* (not by asking the
LLM to do arithmetic): 2 of 5 applicable categories covered → **0.4**, below
the 0.6 approval threshold → `recommendation: re_research`, with
`re_research_tasks` targeting the uncovered categories specifically.

**Researcher (pass 2)** — researches *only* the Critic's `re_research_tasks`,
not the original plan again. Plan grows to 9 tasks total (6 + 3 new),
findings to 9 — cumulative across passes, never replaced.

**Analyst (pass 2)** — the Critic-demanded focus areas bypass the relevance
gate by design (a production fix from Sprint 10: a category the Critic just
asked for must never get silently gated out, or the loop burns iterations for
nothing). Surface count climbs to **3**.

**Critic (pass 2)** — coverage climbs to **0.6** → `recommendation: approve`.

**Writer** — assembles the final `ThreatReport` and persists a
`ThreatReportSummary` (not the full report — see below) into episodic memory.

## The final report

```json
{
  "surface_count": 3,
  "severity_breakdown": { "critical": 0, "high": 2, "medium": 0, "low": 1 },
  "focus_areas_covered": ["injection", "data_leakage", "supply_chain", "dos", "model_extraction", "other"],
  "top_attack_vectors": [
    "Authenticated users can exploit the Starlette vulnerability by uploading excessively large files without filename restrictions, leading to resource exhaustion.",
    "Authenticated users can trigger memory exhaustion by exploiting the vulnerable version of Starlette used in FastAPI, causing service disruption.",
    "Exploitation of SSO integration vulnerabilities to inject unauthorized data or manipulate sessions.",
    "Potential SQL injection through improperly sanitized inputs in the SSO authentication process.",
    "Authenticated users can exploit the stored XSS by injecting malicious scripts into LLM responses, which are then rendered by the MdRenderer.vue component, potentially leaking sensitive HR data."
  ],
  "overall_critic_score": 0.6,
  "iteration_count": 2
}
```

Two things worth noting on real (not cherry-picked) output:

- **Severity isn't flat** — 2 HIGH, 1 LOW, for a service that's SSO-gated and
  internal-only. The Analyst recognized bounded blast radius on at least one
  surface instead of defaulting everything to HIGH, which is exactly the
  behavior [ADR-0007's severity rubric](adr/0007-severity-calibration.md)
  targets. Compare this to a public no-auth target, which reliably comes back
  CRITICAL/HIGH-heavy (see the README's evaluation section).
- **Attack vectors are specific to this target** — a named library
  (Starlette) and a named integration point (SSO session handling, an
  LLM-rendered markdown component), not generic "sanitize your inputs"
  boilerplate.

## What a finding's evidence actually looks like

`ThreatReportSummary` (above, what's persisted) intentionally drops
per-surface evidence — only the live `ThreatReport` returned by `POST
/analyze` carries it, by design (episodic memory stores summaries, not full
reports). Here's one real `ThreatSurface.evidence` entry from a separate
run (`ml_pipeline` architecture), showing the citation format:

```json
{
  "name": "Denial of Service via CI/CD Pipeline Misconfiguration",
  "severity": "high",
  "owasp_category": "LLM04",
  "evidence": [
    {
      "source_type": "arxiv",
      "title": "Ambush from All Sides: Understanding Security Threats in Open-Source Software CI/CD Pipelines",
      "identifiers": ["arxiv:2401.17606v1"],
      "relevance_score": 0.9
    }
  ]
}
```

That `arxiv:2401.17606v1` is a real paper fetched from the arXiv API at
analysis time — the LLM never invents a citation; the Researcher's MCP call
either returns a real identifier or the finding doesn't exist.

## Reproducing this

```bash
docker compose up -d
curl -N -G "localhost:8000/analyze/stream" \
  --data-urlencode "target_description=<your architecture description>"
```

Expect variance run-to-run: GPT-4o isn't perfectly deterministic even at
`temperature=0`, so pass count, exact surface count, and wording will differ
between runs on the same input. The *mechanics* traced above (deterministic
coverage scoring, cumulative findings, gate bypass for Critic-demanded
categories) do not.
