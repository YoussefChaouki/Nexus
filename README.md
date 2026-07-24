# NEXUS — Multi-agent AI Vulnerability Intelligence

[![CI](https://github.com/YoussefChaouki/Nexus/actions/workflows/ci.yml/badge.svg)](https://github.com/YoussefChaouki/Nexus/actions/workflows/ci.yml)
![Coverage](https://img.shields.io/badge/coverage-92%25-brightgreen)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![LangGraph](https://img.shields.io/badge/orchestration-LangGraph-1c3c3c)
![License: MIT](https://img.shields.io/badge/license-MIT-yellow)

Describe an AI deployment in plain English — NEXUS returns a structured
**ThreatReport**: attack surfaces with calibrated severity, CVE references,
arXiv papers, MITRE ATLAS techniques, OWASP LLM Top 10 mapping, and
mitigations. Five specialized agents research, synthesize, and *criticize*
the analysis in a feedback loop until coverage crosses an objective,
deterministically-computed threshold.

![Demo](docs/demo.gif)
*(demo GIF coming — run `make dev` + the Next.js frontend for the live version)*

---

## Why multi-agent?

A single "you are a security expert" prompt produces plausible-sounding but
shallow threat models: no evidence, flat severity, and whatever OWASP
categories the model happens to remember. NEXUS splits the job across five
LangGraph nodes sharing one typed `AgentState`, with a bounded feedback loop
between Critic and Researcher:

```mermaid
flowchart TD
    T["target_description"] --> P["Planner<br/>4-6 ResearchTask, grounded in<br/>similar past runs (episodic memory)"]
    P --> R["Researcher<br/>fans out to MCP servers"]
    R --> A["Analyst<br/>synthesizes ThreatSurfaces,<br/>rubric-calibrated severity"]
    A --> C{"Critic<br/>OWASP coverage ≥ 0.6?"}
    C -- "no · iteration < 3<br/>re_research_tasks for the gaps" --> R
    C -- "yes · or max_iterations hit" --> W["Writer<br/>assembles ThreatReport"]
    W --> TR(["ThreatReport"])
```

Every finding cites a real identifier (`CVE-…`, `arxiv:…`, `AML.T…`) fetched
at analysis time — the LLM never invents evidence. The Critic recomputes its
coverage score deterministically from the surfaces' OWASP categories, so the
feedback loop is driven by arithmetic, not by a model grading its own homework.

See [docs/WALKTHROUGH.md](docs/WALKTHROUGH.md) for a real run traced
node-by-node, including a re-research pass triggered by a low coverage score.

### Evidence sources and memory

```mermaid
flowchart LR
    subgraph mcp["MCP servers (stdio subprocesses)"]
        ARX["arXiv<br/>search_papers"]
        NVD["NVD<br/>search_cves"]
        ATL["MITRE ATLAS*<br/>search_techniques"]
        CA["Code Analysis<br/>analyze_dependencies<br/>detect_patterns<br/>extract_attack_surface"]
    end
    subgraph memory["Memory"]
        WM[("Redis<br/>working / checkpointer")]
        EP[("pgvector<br/>episodic: past ThreatReportSummary")]
        SM[("pgvector<br/>semantic: ATLAS/OWASP patterns<br/>(read-only)")]
    end
    Researcher --> ARX
    Researcher --> NVD
    Researcher --> ATL
    Planner -. "similarity search" .-> EP
    Analyst -. "pattern lookup" .-> SM
    Writer -. "persists summary" .-> EP
```

\* MITRE dropped the STIX 2.1 JSON feed this server was built against in
favor of a YAML format — `search_techniques` currently returns no results
until `stix_loader.py` is ported to it (degrades gracefully, doesn't crash
the run). `Code Analysis` is registered and independently testable but not
yet wired into the Researcher's automatic fan-out — call it directly via
its MCP tools for now.

## Evaluation — NEXUS vs a single prompt

Measured by `scripts/compare_baseline.py` against live GPT-4o on the 5-target
benchmark in `tests/eval/architectures.py` (same extractors and metrics for
both strategies — full table in [docs/EVAL_RESULTS.md](docs/EVAL_RESULTS.md)):

| Metric | NEXUS | Single-prompt baseline |
|--------|-------|------------------------|
| Expected threat-surface coverage (mean) | **80.0%** | 26.7% |
| OWASP LLM Top 10 category coverage (mean) | 80.0% | 93.3%* |
| Evidence citations (CVE / arXiv / ATLAS ids) | every surface | none |
| P50 ThreatReport generation time | ~75 s (1-2 passes) | ~3 s |
| Test coverage (CI, mocked LLM) | 92% | — |

\* Naming OWASP codes is free — the baseline is literally asked to list
them. Producing the named, evidence-backed threat surfaces behind those
codes is the actual deliverable, and that is where the multi-agent
pipeline wins by **+53 points**. The feedback loop demonstrably works:
on 3 of the 5 targets the Critic's deterministic coverage score climbed
between passes (0.40→0.80, 0.50→0.83, 0.20→0.60) before approving.

Severity calibration is validated in both directions on real runs: a public
no-auth RAG service yields critical/high surfaces, while a locked-down
internal service (SSO, private VPC, trusted users) yields medium-only — the
distribution tracks the target's actual trust boundaries instead of
defaulting to HIGH.

## Architecture

- **Agents** (`src/nexus/agents/`) — five async LangGraph nodes sharing a
  typed `AgentState`; state is never mutated, every node returns a new dict.
  The Critic→Researcher feedback loop is bounded by `max_iterations=3` with
  a force-approve guardrail.
- **Memory** (`src/nexus/memory/`) — three layers: Redis checkpointing
  (working), pgvector episodic store of past report summaries (the Planner
  retrieves similar architectures), and a read-only pgvector semantic library
  of ATLAS/OWASP patterns ingested by `scripts/ingest_patterns.py`.
- **MCP servers** (`mcp_servers/`) — four standalone stdio processes (arXiv,
  NVD, MITRE ATLAS, Code Analysis) speaking the Model Context Protocol, each
  with its own `pyproject.toml`, rate limiting/retries where relevant, and
  typed Pydantic envelopes. The Researcher fans out to the first three;
  Code Analysis is available but not yet in that automatic loop.
- **Observability** — every LLM call carries a Langfuse callback with a
  shared metadata vocabulary (`agent`, `iteration`, `step`, `session_id`);
  structured logs (`structlog`) expose per-pass coverage breakdowns.
- **API + frontend** — FastAPI with SSE streaming (`/analyze/stream`) feeding
  a Next.js 14 terminal-style UI: live agent pipeline rail, severity
  spectrum, critic coverage gauge.

## Quick start

```bash
git clone https://github.com/YoussefChaouki/Nexus.git && cd Nexus
cp .env.example .env          # set OPENAI_API_KEY (Langfuse keys optional)
docker compose up -d          # postgres (pgvector) + redis + api on :8000

curl -X POST localhost:8000/analyze \
  -H 'Content-Type: application/json' \
  -d '{"target_description": "FastAPI + pgvector RAG, OpenAI API, no auth, user uploads, public internet"}'
```

For the UI: `cd frontend && npm install && npm run dev` → http://localhost:3000.

Local development: `make dev` (API with reload), `make ci` (ruff + mypy
--strict + pytest, mocked LLM), `make test-all` (includes integration suite).

## Project structure

```
src/nexus/
├── agents/          planner · researcher · analyst · critic · writer
├── graph/           LangGraph StateGraph, routing, SSE streaming
├── memory/          working (Redis) · episodic & semantic (pgvector)
├── mcp/             stdio client + tool registry
├── observability/   Langfuse handler factory
├── schemas/         Pydantic models — single source of truth
└── api/             FastAPI app
mcp_servers/         arxiv/ · nvd/ · atlas/ · code_analysis/   (standalone MCP processes)
frontend/            Next.js 14 terminal UI
tests/eval/          benchmark harness + baseline comparison
docs/adr/            architecture decision records
```

## Design decisions

Key choices are documented as ADRs in [`docs/adr/`](docs/adr/), notably:
[severity calibration rubric](docs/adr/0007-severity-calibration.md),
[two-stage relevance filtering](docs/adr/0008-relevance-filtering.md), and
[deterministic critic scoring + target grounding](docs/adr/0009-deterministic-critic-and-target-grounding.md).

## What's next

NEXUS is the research stage of a three-project AI-security arc:

1. **NEXUS** *(this repo)* — threat intelligence: what can go wrong, with evidence.
2. **ThreatRAG** — knowledge graph linking surfaces, techniques and mitigations across reports.
3. **RedTeamForge** — execution: turning surfaces into reproducible red-team scenarios.

## License

[MIT](LICENSE)
