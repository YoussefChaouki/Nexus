# NEXUS — Architecture Document

**Version:** 1.0 | **Dernière mise à jour:** Phase 0

---

## Vue d'ensemble du système

NEXUS est une application Python 3.11+ async composée de plusieurs processus :

```
┌─────────────────────────────────────────────────┐
│  nexus app (FastAPI + LangGraph)                │
│  ├── POST /analyze                              │
│  └── GET /analyze/stream (SSE)                 │
└──────────────────┬──────────────────────────────┘
                   │ stdio
       ┌───────────┼───────────┐
       ↓           ↓           ↓
  MCP arXiv    MCP NVD    MCP ATLAS
  (process)   (process)  (process)
       
       ┌───────────┬───────────┐
       ↓           ↓           ↓
    Redis       pgvector    Langfuse
  (working)   (episodic    (external
              +semantic)     SaaS)
```

---

## State Machine LangGraph

### AgentState (TypedDict)
```python
class AgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    target_description: str
    session_id: str
    plan: list[ResearchTask]          # rempli par Planner
    findings: list[FindingResult]     # rempli par Researcher (cumulatif)
    threat_surfaces: list[ThreatSurface]  # rempli par Analyst
    critic_report: CriticReport | None    # rempli par Critic
    threat_report: ThreatReport | None    # rempli par Writer
    iteration_count: int              # incrémenté par Researcher
    should_continue: bool             # routing flag posé par Critic
```

### Graphe
```python
graph = StateGraph(AgentState)
graph.add_node("planner",    planner_node)
graph.add_node("researcher", researcher_node)
graph.add_node("analyst",    analyst_node)
graph.add_node("critic",     critic_node)
graph.add_node("writer",     writer_node)

graph.set_entry_point("planner")
graph.add_edge("planner",    "researcher")
graph.add_edge("researcher", "analyst")
graph.add_edge("analyst",    "critic")
graph.add_conditional_edges(
    "critic",
    route_after_critic,         # → "researcher" | "writer"
    {"researcher": "researcher", "writer": "writer"}
)
graph.add_edge("writer", END)

compiled = graph.compile(checkpointer=RedisSaver(redis_client))
```

### Routing (edges.py)
```python
def route_after_critic(state: AgentState) -> Literal["researcher", "writer"]:
    if (
        state["critic_report"].recommendation == Recommendation.RE_RESEARCH
        and state["iteration_count"] < settings.max_iterations
    ):
        return "researcher"
    return "writer"
```

---

## Agents

### Planner (`src/nexus/agents/planner.py`)
**Responsabilité :** Décomposer `target_description` en `ResearchTask[]` (4-6 tâches).

**Prompt strategy :**
- System : taxonomie des FocusArea + exemples par type d'architecture AI
- User : `target_description`
- Output format : JSON structuré → validé en `list[ResearchTask]`

**Mémoire :** Consulte EpisodicMemory (similarité cosinus > 0.85) pour récupérer le contexte d'architectures similaires analysées précédemment. Optionnel — n'affecte pas le flow si absent.

**Métrique :** 4-6 tasks, au moins 3 FocusArea distincts couverts.

---

### Researcher (`src/nexus/agents/researcher.py`)
**Responsabilité :** Exécuter les `ResearchTask[]` en interrogeant les 3 MCP servers en parallèle.

**Flow :**
```
pour chaque ResearchTask:
  asyncio.gather(
    arxiv_mcp.search_papers(task.search_queries),
    nvd_mcp.search_cves(task.search_queries),
    atlas_mcp.search_techniques(task.search_queries),
  )
  → FindingResult[] (dedupliqués, scorés par pertinence)
```

**Gestion de la boucle :** Incrémente `state["iteration_count"]` à chaque appel.
Sur les itérations suivantes (re_research), interroge uniquement les sources pertinentes aux `re_research_tasks` du Critic.

**Rate limiting :**
- arXiv : 3 req/s, délai 0.33s entre calls
- NVD : 5 req/s sans clé, 50 req/s avec `NVD_API_KEY`
- ATLAS : pas de rate limit (local)

---

### Analyst (`src/nexus/agents/analyst.py`)
**Responsabilité :** Synthétiser `FindingResult[]` en `ThreatSurface[]`.

**Flow :**
1. Grouper les findings par `focus_area`
2. Pour chaque groupe : interroger SemanticMemory (patterns ATLAS/OWASP similaires)
3. LLM synthesis : contexte findings + patterns → ThreatSurface structurée
4. Assigner severity (CRITICAL/HIGH/MEDIUM/LOW) et owasp_category

**Augmentation sémantique :** Les patterns de la Threat Pattern Library sont injectés dans le prompt comme contexte de référence. Cela améliore la qualité des mitigations et la précision des `attack_vectors`.

---

### Critic (`src/nexus/agents/critic.py`)
**Responsabilité :** Évaluer la complétude de `ThreatSurface[]` et décider approve vs re_research.

**Checklist d'évaluation :**
- OWASP LLM Top 10 (2025) : 10 catégories
- MITRE ATLAS tactics : 14 tactics (les plus pertinentes pour le target)
- Coverage score : nb de catégories couvertes / nb de catégories applicables

**Logique de décision :**
```
if overall_score >= 0.6 OR iteration_count >= max_iterations:
    recommendation = APPROVE
else:
    recommendation = RE_RESEARCH
    re_research_tasks = [tasks pour les gaps identifiés]
```

**Output :** `CriticReport` avec `gaps[]` explicites (nommés, pas juste un score).

---

### Writer (`src/nexus/agents/writer.py`)
**Responsabilité :** Assembler le `ThreatReport` final et le persister.

**Flow :**
1. Assembler tous les champs du `ThreatReport` depuis l'`AgentState`
2. Calculer metadata (token counts depuis Langfuse callbacks, latence)
3. Valider le modèle Pydantic (lève si invalide)
4. Persister `ThreatReportSummary` dans EpisodicMemory
5. Retourner l'état mis à jour avec `threat_report`

---

## MCP Servers

### Architecture commune
```python
# Pattern standard pour chaque server
from mcp.server import Server
from mcp.server.stdio import stdio_server

server = Server("nexus-{name}-mcp")

@server.tool()
async def tool_name(param: str) -> str:
    """Description du tool."""
    result = await fetch_data(param)
    return result.model_dump_json()  # toujours Pydantic → JSON

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())
```

### arXiv MCP (`mcp_servers/arxiv/server.py`)
| Tool | Params | Source |
|------|--------|--------|
| `search_papers` | `query: str, max_results: int = 10` | arxiv.org API |
| `get_paper_abstract` | `arxiv_id: str` | arxiv.org API |
| `get_full_text` | `arxiv_id: str` | arXiv S2ORC ou abstract fallback |

Rate limit : 3 req/s. Retry avec exponential backoff sur 429.

### NVD MCP (`mcp_servers/nvd/server.py`)
| Tool | Params | Source |
|------|--------|--------|
| `search_cves` | `keyword: str, severity: str \| None, max_results: int = 20` | nvd.nist.gov REST API v2 |
| `get_cve_detail` | `cve_id: str` | nvd.nist.gov REST API v2 |
| `search_by_product` | `cpe_name: str` | nvd.nist.gov REST API v2 |

Rate limit : 5/s sans clé, 50/s avec `NVD_API_KEY`. Toujours utiliser `Retry-After` header.

### MITRE ATLAS MCP (`mcp_servers/atlas/server.py`)
| Tool | Params | Source |
|------|--------|--------|
| `search_techniques` | `query: str, max_results: int = 10` | pgvector similarity search |
| `get_technique_detail` | `technique_id: str` | STIX bundle local |
| `search_by_tactic` | `tactic_name: str` | STIX bundle local |

Dataset : `data/atlas/ATLAS.json` (STIX 2.1, téléchargé à setup).
Embeddings pre-computed sur `technique.description` au démarrage du server.

### Code Analysis MCP (`mcp_servers/code_analysis/server.py`) — stretch goal S9.T3, complété
| Tool | Params | Source |
|------|--------|--------|
| `analyze_dependencies` | `requirements_content: str` | requirements.txt / pyproject.toml → nvd.nist.gov REST API v2 |
| `detect_patterns` | `code_content: str, language: str = "python"` | subprocess `semgrep --config=auto` |
| `extract_attack_surface` | `config_content: str, config_type: str` | docker-compose / kubernetes / openapi (YAML/JSON) / terraform (regex heuristics) |

Package self-contenu (pas d'import croisé avec `mcp_servers/nvd` — client NVD
minimal dupliqué volontairement, même convention que les 3 autres servers).
`semgrep` est un binaire externe (pas une dépendance Python) — voir
`mcp_servers/code_analysis/README.md` pour le setup.

---

## Memory Layer

### Working Memory (Redis)
```
Purpose:   LangGraph session state
Key:       nexus:session:{session_id}:checkpoint
TTL:       3600s
Library:   redis.asyncio + langgraph.checkpoint.redis.RedisSaver
```

### Episodic Memory (pgvector)
```sql
CREATE TABLE threat_report_summaries (
    id UUID PRIMARY KEY,
    session_id TEXT NOT NULL,
    target_description TEXT NOT NULL,
    target_embedding vector(1536) NOT NULL,  -- text-embedding-3-small
    summary_json JSONB NOT NULL,             -- ThreatReportSummary
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX ON threat_report_summaries USING ivfflat (target_embedding vector_cosine_ops);
```

### Semantic Memory (pgvector)
```sql
CREATE TABLE threat_patterns (
    id UUID PRIMARY KEY,
    source_type TEXT NOT NULL,   -- 'atlas' | 'owasp_llm'
    pattern_id TEXT NOT NULL,    -- ATLAS-T0054 | OWASP-LLM01
    pattern_text TEXT NOT NULL,
    embedding vector(1536) NOT NULL,
    metadata JSONB DEFAULT '{}'
);
CREATE INDEX ON threat_patterns USING ivfflat (embedding vector_cosine_ops);
```
Ingestion : `scripts/ingest_patterns.py` (one-shot, idempotent via upsert).
Contenu : 149 ATLAS techniques + 10 OWASP LLM Top 10 (2023) + 10 OWASP LLM Top 10 (2025).

---

## API FastAPI

```python
# POST /analyze — synchrone
@app.post("/analyze", response_model=ThreatReport)
async def analyze(request: AnalyzeRequest) -> ThreatReport:
    session_id = request.session_id or str(uuid4())
    result = await run_nexus_pipeline(request.target_description, session_id)
    return result

# GET /analyze/stream — SSE
@app.get("/analyze/stream")
async def analyze_stream(target_description: str, session_id: str | None = None):
    async def event_generator():
        async for event in stream_nexus_pipeline(target_description, session_id):
            yield f"data: {event.model_dump_json()}\n\n"
    return StreamingResponse(event_generator(), media_type="text/event-stream")

# GET /report/{id}
@app.get("/report/{report_id}", response_model=ThreatReport)
async def get_report(report_id: str) -> ThreatReport:
    ...
```

---

## Infrastructure Docker Compose

```yaml
version: "3.9"
services:
  postgres:
    image: pgvector/pgvector:pg16
    environment:
      POSTGRES_DB: nexus
      POSTGRES_USER: nexus
      POSTGRES_PASSWORD: nexus
    volumes: [postgres_data:/var/lib/postgresql/data]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U nexus"]
      interval: 5s

  redis:
    image: redis:7-alpine
    volumes: [redis_data:/data]
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]

  app:
    build: .
    depends_on:
      postgres: {condition: service_healthy}
      redis: {condition: service_healthy}
    env_file: .env
    ports: ["8000:8000"]
    volumes: ["./data:/app/data"]

  mcp_arxiv:
    build: ./mcp_servers/arxiv
    stdin_open: true

  mcp_nvd:
    build: ./mcp_servers/nvd
    env_file: .env

  mcp_atlas:
    build: ./mcp_servers/atlas
    volumes: ["./data/atlas:/app/data"]

volumes:
  postgres_data:
  redis_data:
```

---

## CI/CD GitHub Actions

```yaml
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: ruff check . && ruff format --check .

  typecheck:
    runs-on: ubuntu-latest
    steps:
      - run: mypy src/ --strict

  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: pgvector/pgvector:pg16
      redis:
        image: redis:7-alpine
    steps:
      - run: pytest tests/ -m "not integration" --cov=src/nexus --cov-fail-under=80 --cov-report=xml
      - uses: codecov/codecov-action@v3

  integration:
    if: github.event_name == 'workflow_dispatch'
    # Manuel uniquement — nécessite les vraies API keys
```

---

## Decisions de conception clés

Voir `docs/adr/` pour le détail :
- ADR-001 : Choix du cas d'usage (AI Vulnerability Intelligence)
- ADR-002 : Architecture 5 agents avec boucle de feedback
- ADR-003 : Memory layer 3 niveaux (Redis + pgvector × 2)
- ADR-004 : MCP servers custom (arXiv + NVD + MITRE ATLAS)
