# NEXUS Evaluation Results

_Generated 2026-06-11T23:38:42+00:00 — mode: live LLM._

Multi-agent NEXUS vs. a single-prompt baseline across 5 benchmark architectures. Coverage = fraction of the expected OWASP LLM Top 10 categories / threat surfaces found.

| Architecture | NEXUS OWASP% | Baseline OWASP% | Δ OWASP | NEXUS Surface% | Baseline Surface% | Δ Surface |
|---|---|---|---|---|---|---|
| `rag_basic` | 100.0% | 100.0% |  +0.0 | 100.0% |   0.0% | +100.0 |
| `rag_enterprise` |  66.7% |  66.7% |  +0.0 |  66.7% |   0.0% | +66.7 |
| `autonomous_agent` |  66.7% | 100.0% | -33.3 | 100.0% |   0.0% | +100.0 |
| `llm_api_service` | 100.0% | 100.0% |  +0.0 | 100.0% |  66.7% | +33.3 |
| `ml_pipeline` |  66.7% | 100.0% | -33.3 |  33.3% |  66.7% | -33.3 |

## Aggregate

| Metric | NEXUS | Baseline | Delta |
|---|---|---|---|
| Mean OWASP coverage |  80.0% |  93.3% | -13.3 |
| Mean surface coverage |  80.0% |  26.7% | +53.3 |
