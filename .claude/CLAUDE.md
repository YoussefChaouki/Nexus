# NEXUS — Claude Code CLI Context

## Projet
NEXUS est un système multi-agent de production qui produit des **ThreatReport** structurés pour des déploiements AI.
Input : description d'une architecture AI (ex: "FastAPI + pgvector RAG, OpenAI API, pas d'auth").
Output : `ThreatReport` JSON avec attack surfaces, CVE references, papers arxiv, ATLAS techniques, mitigations.

**Contexte portfolio :** ML Engineer targeting Anthropic / OpenAI / DeepMind / NVIDIA.
NEXUS est le projet "Research" dans l'arc AI Security : NEXUS (research) → ThreatRAG (graph) → RedTeamForge (exec).

---

## Stack technique exacte

| Composant | Technologie | Contrainte |
|-----------|-------------|------------|
| Python | 3.11+ | strict typing partout |
| Orchestration | LangGraph ≥ 0.2 (StateGraph) | pas de Chain langchain |
| LLM | `langchain-openai` ChatOpenAI | modèle via Settings |
| Validation | Pydantic v2 ≥ 2.5 | v1 interdit |
| MCP protocol | `mcp` Python SDK | servers en stdio |
| Working memory | `redis.asyncio` Redis 7+ | LangGraph checkpointer |
| Vector store | `asyncpg` + `pgvector` | pas de SQLAlchemy |
| Embeddings | `text-embedding-3-small` (1536 dims) | — |
| Observabilité | Langfuse 2.x | tous les LLM calls |
| API | FastAPI + uvicorn | async partout |
| Logging | `structlog` | pas de print() |
| Linting | `ruff` (line-length=100) | — |
| Types | `mypy --strict` | zéro `Any` non justifié |
| Tests | `pytest` + `pytest-asyncio` | mocks LLM obligatoires |
| CI | GitHub Actions | lint + types + test |
| Containers | Docker Compose | postgres, redis, app, mcps |

---

## Standards de code — NON-NÉGOCIABLES

```
✓ Tout le code I/O est async/await — zéro appel bloquant
✓ mypy --strict doit passer sans erreur
✓ ruff check . doit passer (line-length=100, isort enforced)
✓ pytest coverage ≥ 80% — LLM calls mockés dans tous les tests
✓ Pydantic v2 pour tous les modèles (model_validator, field_validator)
✓ Conventional commits : feat: fix: test: docs: refactor: chore:
✓ structlog pour tout logging — jamais print()
✓ Exceptions typées dans nexus/exceptions.py — jamais raise Exception()
✓ Docstrings Google style sur toutes les fonctions publiques
✓ Env vars via pydantic-settings Settings — jamais os.environ directement
```

---

## Architecture du pipeline

```
target_description (str)
        ↓
  ┌─────────────┐
  │   Planner   │  → ResearchTask[] (4-6 tâches, une par focus_area)
  └──────┬──────┘
         ↓
  ┌─────────────┐  ←──────────────────────────────────┐
  │ Researcher  │  → FindingResult[] (MCP queries)     │ re_research_tasks
  └──────┬──────┘                                      │
         ↓                                             │
  ┌─────────────┐                                      │
  │   Analyst   │  → ThreatSurface[] (synthesis)       │
  └──────┬──────┘                                      │
         ↓                                             │
  ┌─────────────┐  recommendation==re_research (max 3) ┘
  │   Critic    │
  └──────┬──────┘  recommendation==approve
         ↓
  ┌─────────────┐
  │   Writer    │  → ThreatReport (final)
  └─────────────┘
```

---

## Schémas Pydantic — Source de vérité unique

> **Toujours importer depuis `src/nexus/schemas/models.py`. Ne jamais redéfinir.**
> Schémas complets dans `docs/DATA_MODELS.md` (chargé automatiquement ci-dessous).

@../docs/DATA_MODELS.md

---

## Structure des fichiers

```
nexus/
├── .claude/
│   └── CLAUDE.md                    ← CE FICHIER
├── docs/
│   ├── DATA_MODELS.md               ← Pydantic schemas (chargé automatiquement)
│   ├── ARCHITECTURE.md
│   ├── PRD.md
│   ├── SPRINTS.md
│   └── adr/
├── src/nexus/
│   ├── schemas/models.py             ← Pydantic (source de vérité)
│   ├── graph/
│   │   ├── state.py                  ← AgentState TypedDict
│   │   ├── edges.py                  ← fonctions de routing
│   │   └── graph.py                  ← StateGraph construction
│   ├── agents/
│   │   ├── base.py                   ← BaseAgent, helpers communs
│   │   ├── planner.py
│   │   ├── researcher.py
│   │   ├── analyst.py
│   │   ├── critic.py
│   │   └── writer.py
│   ├── memory/
│   │   ├── working.py                ← Redis checkpointer
│   │   ├── episodic.py               ← pgvector ThreatReportSummary
│   │   └── semantic.py               ← pgvector Threat Pattern Library
│   ├── mcp/
│   │   ├── client.py                 ← ClientSession wrapper
│   │   └── tool_registry.py          ← mapping tool_name → MCP server
│   ├── observability/langfuse.py     ← CallbackHandler factory
│   ├── exceptions.py                 ← toutes les exceptions typées
│   ├── settings.py                   ← pydantic-settings Settings
│   └── api/main.py                   ← FastAPI app
├── mcp_servers/
│   ├── arxiv/server.py
│   ├── nvd/server.py
│   └── atlas/server.py
├── tests/
│   ├── conftest.py                   ← fixtures: mock_llm, mock_redis, mock_pgvector
│   ├── agents/                       ← test_{planner,researcher,analyst,critic,writer}.py
│   ├── memory/
│   ├── mcp/
│   └── integration/                  ← marqués @pytest.mark.integration
├── scripts/
│   └── ingest_patterns.py            ← ingestion ATLAS + OWASP → semantic memory
├── frontend/                         ← Next.js 14 (process séparé)
├── docker-compose.yml
├── pyproject.toml
├── .env.example
└── Makefile                          ← make ci, make dev, make test, make lint
```

---

## Conventions LangGraph

- `AgentState` défini dans `src/nexus/graph/state.py` — TypedDict, jamais dataclass
- Signature de chaque agent : `async def agent_name(state: AgentState) -> AgentState`
- **Ne jamais muter state** — toujours retourner un nouveau dict avec champs modifiés
- Fonctions de routing dans `edges.py`, retournent des `Literal[node_name]`
- Feedback loop : `max_iterations=3` géré dans `edges.py` via `iteration_count`
- Graph compilé avec `checkpointer=RedisSaver(...)` (working memory)
- `iteration_count` incrémenté par Researcher au début de chaque cycle

## Conventions MCP servers

- Chaque server = process Python standalone via `mcp.server.stdio`
- Tools = fonctions async décorées `@server.tool()`
- Return type : modèle Pydantic sérialisé JSON (jamais de dict nu)
- Error handling : `{"error": str, "error_type": str}` — jamais lever d'exception dans les handlers
- Chaque server a son propre `pyproject.toml` et tests dans `mcp_servers/{name}/tests/`
- Connection depuis agents via `mcp.client.ClientSession` (stdio transport)

## Conventions Memory

- Redis : `redis.asyncio.Redis`, factory dans `nexus.memory.working.get_redis_client()`
- pgvector : pool `asyncpg`, embeddings `text-embedding-3-small` (1536 dims)
- Mémoire épisodique stocke `ThreatReportSummary` (pas le rapport complet)
- Mémoire sémantique est **read-only** au runtime — write uniquement dans `scripts/`
- Key pattern Redis : `nexus:session:{session_id}:checkpoint`

## Conventions Tests

- Tous les appels LLM mockés via fixture `mock_llm` dans `conftest.py`
- `mock_llm` retourne des objets Pydantic typés correspondant au format attendu
- `@pytest.mark.asyncio` sur tous les tests async
- Tests intégration dans `tests/integration/` — exclus du run par défaut
- Coverage : `pytest --cov=src/nexus --cov-fail-under=80`
- `pytest -m "not integration"` pour le run rapide (CI)

## Observabilité Langfuse

- Handler créé via `nexus.observability.langfuse.get_langfuse_handler(session_id)`
- Passé à chaque appel LLM : `llm.invoke(..., config={"callbacks": [handler]})`
- Hiérarchie des traces : `nexus/session/{id}` → `nexus/{agent}/{iteration}` → LLM calls
- Ne jamais loguer de données sensibles (API keys, données perso) dans Langfuse

## Variables d'environnement (pydantic-settings)

```python
class Settings(BaseSettings):
    openai_api_key: SecretStr
    anthropic_api_key: SecretStr | None = None
    langfuse_public_key: SecretStr
    langfuse_secret_key: SecretStr
    langfuse_host: str = "https://cloud.langfuse.com"
    redis_url: str = "redis://localhost:6379"
    postgres_dsn: PostgresDsn = "postgresql+asyncpg://nexus:nexus@localhost:5432/nexus"
    nvd_api_key: SecretStr | None = None   # 5 req/s sans clé, 50 req/s avec
    llm_model: str = "gpt-4o"
    embedding_model: str = "text-embedding-3-small"
    max_iterations: int = 3
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")
```

---

## Git Workflow — NON-NÉGOCIABLE

### Format des branches
`{type}/s{sprint}-t{task}-{slug}` — ex : `feat/s1-t1-scaffold`, `test/s4-t2-pipeline-int`

| Type | Quand |
|------|-------|
| `feat/` | nouvelle fonctionnalité |
| `fix/` | correction de bug |
| `test/` | ajout/amélioration de tests uniquement |
| `refactor/` | refactoring sans changement fonctionnel |
| `docs/` | documentation uniquement |
| `chore/` | config, tooling, CI |

### Format des commits
Conventional Commits strict : `{type}: {description courte impérative}`
- Max 72 caractères, tout en minuscules
- Ex : `feat: add langgraph state machine skeleton`
- Ex : `test: cover feedback loop termination cases`

### git add — toujours par fichiers explicites
```bash
# ✓ Correct
git add src/nexus/schemas/ tests/schemas/test_models.py

# ✗ Interdit
git add .
git add -A
```

### ⛔ RÈGLES ABSOLUES
```
✗ JAMAIS ajouter Co-Authored-By Claude — les commits t'appartiennent uniquement
✗ JAMAIS git add . ni git add -A — risque d'inclure .env, caches, fichiers générés
✗ JAMAIS committer directement sur main
✗ Une branche par tâche sprint — merge sur main uniquement après make ci vert
```

---

## ⛔ DO NOT

```
✗ Ne pas utiliser de Chain langchain — utiliser des nœuds LangGraph
✗ Ne pas stocker ThreatReport complet en mémoire épisodique — ThreatReportSummary seulement
✗ Ne pas appeler l'API NVD sans rate limiting (5 req/s max sans clé API)
✗ Ne pas hardcoder les noms de modèles — utiliser Settings.llm_model
✗ Ne pas construire de knowledge graph dans NEXUS — c'est le rôle de ThreatRAG
✗ Ne pas utiliser de clients Redis/Postgres synchrones
✗ Ne pas sauter l'instrumentation Langfuse sur un appel LLM
✗ Ne pas importer de langchain_community sauf absolue nécessité
✗ Ne pas utiliser TypedDict pour les modèles de données — Pydantic v2 seulement
✗ Ne pas lancer de vraies API (OpenAI, NVD, arXiv) dans les tests unitaires
```
