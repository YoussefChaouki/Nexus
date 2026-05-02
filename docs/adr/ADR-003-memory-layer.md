# ADR-003 — Memory layer 3 niveaux (Redis + pgvector × 2)

**Date :** Phase 0 | **Statut :** Accepted

## Décision

3 types de mémoire, chacun avec une fonction testable et distincte. La mémoire "procédurale" (patterns de tool-use) est abandonnée — trop complexe pour le délai, trop peu de valeur demo.

| Type | Technologie | Purpose | Agent(s) |
|------|-------------|---------|----------|
| Working | Redis + LangGraph RedisSaver | Persistance state LangGraph dans la session | Tous (via checkpointer) |
| Episodic | pgvector | Historique ThreatReport, récupérable par similarité d'architecture | Planner (read), Writer (write) |
| Semantic | pgvector | Threat Pattern Library — ATLAS + OWASP LLM Top 10 statique | Analyst (read) |

## Redis vs in-memory pour Working

Redis est justifié (pas juste un dict) parce que :
- Survit au redémarrage du process (recovery)
- Shared entre instances (scalabilité future)
- LangGraph a un RedisSaver natif
- Talking point en entretien : "j'ai implémenté un checkpointer distribué"

## Mem0 vs custom

Mem0 est rejeté. "J'ai architecturé un memory layer à 3 niveaux" est une réponse d'entretien. "J'ai utilisé Mem0" ne l'est pas. Le custom donne du contrôle, de la transparence, et des talking points.

## Mémoire épisodique : ThreatReportSummary, pas ThreatReport complet

Stocker le rapport complet créerait un vecteur de 1536 dims pour un JSON de potentiellement 50KB. La similarité cosinus sur le `target_description` embedé est suffisante pour la retrieval. Le Writer persiste le résumé condensé seulement.

## Mémoire sémantique : read-only au runtime

La Threat Pattern Library ne change pas entre les rapports. L'ingestion est un script one-shot idempotent. Cela évite toute complexité de synchronisation et garantit la cohérence des résultats.
