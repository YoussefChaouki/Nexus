# NEXUS — Product Requirements Document

**Version:** 1.0 | **Statut:** Approved | **Owner:** Portfolio ML Engineer

---

## Vision

NEXUS produit automatiquement des threat models structurés pour des systèmes AI. Donné une description en langage naturel d'une architecture AI, NEXUS orchestre 5 agents spécialisés pour rechercher les vecteurs d'attaque, synthétiser les preuves, valider la complétude, et livrer un `ThreatReport` actionnable.

**Positionnement portfolio :** NEXUS démontre la maîtrise de multi-agent orchestration, persistent memory, MCP, et LLM observability — les keywords exacts ciblant Anthropic / OpenAI / DeepMind / NVIDIA Security.

---

## Use Case — AI Vulnerability Intelligence

### Scénario principal
Un ML Engineer veut évaluer la posture de sécurité de son système AI avant déploiement.
Il décrit l'architecture en langage naturel. NEXUS produit un rapport complet en < 60 secondes.

### Input
```
target_description: str
  Exemple: "FastAPI backend avec pgvector pour un pipeline RAG, frontend Streamlit,
            déployé sur AWS ECS, utilise l'API OpenAI GPT-4, pas d'authentification,
            documents d'entreprise ingérés via upload utilisateur."
```

### Output — ThreatReport
```json
{
  "id": "uuid",
  "target_description": "...",
  "threat_surfaces": [
    {
      "name": "Indirect Prompt Injection via Retrieved Documents",
      "severity": "critical",
      "attack_vectors": ["ATLAS-T0054", "OWASP-LLM01"],
      "evidence": [
        {"source_type": "arxiv", "title": "Indirect Prompt Injection...", "identifiers": ["arxiv:2302.12173"]},
        {"source_type": "nvd", "identifiers": ["CVE-2024-5184"]}
      ],
      "mitigations": ["Input sanitization on retrieved chunks", "Output validation layer"]
    }
  ],
  "critic_report": {
    "overall_score": 0.82,
    "gaps": ["Model extraction attacks not covered", "Membership inference not assessed"],
    "recommendation": "approve"
  },
  "iteration_count": 2,
  "metadata": {"total_tokens": 18420, "estimated_cost_usd": 0.11, "latency_seconds": 47}
}
```

---

## Exigences fonctionnelles

### FR-1 — Pipeline agent
- Planner DOIT décomposer toute description en 4-6 `ResearchTask` couvrant des `FocusArea` distincts
- Researcher DOIT interroger au moins 2 des 3 MCP servers par tâche (async parallel)
- Analyst DOIT produire au moins 1 `ThreatSurface` par cycle de recherche complété
- Critic DOIT évaluer contre OWASP LLM Top 10 ET MITRE ATLAS tactics list
- Writer DOIT produire un `ThreatReport` JSON valide conforme au schéma Pydantic

### FR-2 — Boucle de feedback
- Quand `CriticReport.recommendation == "re_research"` : retrigger Researcher avec `re_research_tasks`
- Maximum 3 itérations imposées dans la state machine (`max_iterations=3`)
- `ThreatReport` final inclut `iteration_count` et `gaps` de toutes les itérations du Critic
- Condition d'arrêt forcée : après 3 itérations, Writer est toujours déclenché

### FR-3 — Memory layer
- **Working (Redis)** : persiste l'état LangGraph entre appels LLM dans la session (TTL=3600s)
- **Episodic (pgvector)** : stocke `ThreatReportSummary`, récupérable par similarité d'architecture
  - Planner consulte l'épisodique au démarrage (si score cosinus > 0.85 : contexte optionnel)
  - Writer persiste le résumé en fin de pipeline
- **Semantic (pgvector)** : Threat Pattern Library — ATLAS techniques + OWASP LLM Top 10
  - Ingestion one-time via `scripts/ingest_patterns.py`
  - Analyst interroge par similarité pour augmenter la synthèse
  - Read-only au runtime

### FR-4 — MCP servers
- **arXiv MCP** : `search_papers(query, max_results)`, `get_paper_abstract(arxiv_id)`, `get_full_text(arxiv_id)`
- **NVD MCP** : `search_cves(keyword, severity?, max_results)`, `get_cve_detail(cve_id)`, `search_by_product(cpe)`
- **MITRE ATLAS MCP** : `search_techniques(query)`, `get_technique_detail(id)`, `search_by_tactic(tactic)`
- Chaque server a ses propres tests, sa propre gestion de rate limit, son propre `pyproject.toml`

### FR-5 — Observabilité
- Tous les appels LLM tracés dans Langfuse avec : agent, iteration, token_count, latency
- Cost tracking par `ThreatReport` (total_tokens, estimated_cost_usd)
- Trace multi-hop visible depuis le dashboard Langfuse pour une session complète

### FR-6 — API
- `POST /analyze` : `{target_description, session_id?}` → `ThreatReport` (synchrone)
- `GET /analyze/stream` : SSE stream d'`AgentEvent` (agent actif, findings en temps réel)
- `GET /report/{report_id}` : récupère un `ThreatReport` stocké

### FR-7 — Frontend
- Zone de saisie de la description cible (textarea + bouton Analyze)
- Live feed des agents (SSE) : agent actif, nombre de findings, durée
- ThreatReport viewer : surfaces expandables, badges de sévérité, citations de preuves
- Lien vers la trace Langfuse associée

---

## Exigences non-fonctionnelles

| NFR | Cible |
|-----|-------|
| Latence P50 (1 itération, 3-4 tasks) | < 60s |
| Latence P95 (3 itérations) | < 180s |
| pytest coverage | ≥ 80% |
| mypy --strict | 0 erreur |
| ruff check | 0 erreur |
| CI pass rate | 100% sur main |

---

## Métriques de succès (README-visible)

| Métrique | Cible | Méthode de mesure |
|----------|-------|-------------------|
| Coverage OWASP LLM Top 10 (5 architectures test) | ≥ 70% | eval harness (`tests/eval/`) |
| Delta surface coverage : NEXUS vs single-prompt | ≥ +30% | eval harness comparatif |
| Temps moyen ThreatReport (P50) | < 60s | Langfuse metrics |
| Gaps identifiés par le Critic (moyenne) | ≥ 2 | eval harness |
| pytest coverage | ≥ 80% | CI badge |

---

## Hors périmètre

- ❌ Construction de knowledge graph (→ ThreatRAG)
- ❌ Exécution d'attaques ou génération d'exploits (→ RedTeamForge)
- ❌ Flux de vulnérabilités temps réel (CVE feeds live)
- ❌ Systèmes non-AI (applications web génériques, mobile, etc.)
- ❌ Authentification utilisateur dans le frontend (demo uniquement)
- ❌ Multi-tenant (une instance = un utilisateur)

---

## Dépendances externes

| Service | Usage | Fallback |
|---------|-------|---------|
| OpenAI API | LLM calls (GPT-4o) + embeddings | Config Anthropic Claude |
| arXiv API | Recherche papers (gratuit) | Cache local |
| NVD REST API v2 | CVE data (gratuit, clé optionnelle) | Rate limit dégradé |
| MITRE ATLAS | Dataset STIX local (téléchargé à setup) | Bundle inclus dans repo |
| Langfuse Cloud | Observabilité (plan gratuit suffit) | Langfuse self-hosted |
