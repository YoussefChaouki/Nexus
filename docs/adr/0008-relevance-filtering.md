# ADR-0008 — Two-stage relevance filtering (Researcher + Analyst gate)

**Date :** 2026-05-23 | **Statut :** Accepted | **Sprint :** S8.T2

## Contexte

Le portfolio review du sprint S7 a exposé un cas où l'Analyst synthétisait une ThreatSurface *"Exploitation of vulnerabilities in payment and financial systems like M-Banking"* sur une cible RAG/pgvector (l'incident M-Banking). Le Researcher remontait un CVE générique mobile-banking, l'Analyst le gardait, le rapport finissait par mentionner une menace qui n'a rien à voir avec la cible.

Cause racine :

1. **Aucun filtre Researcher** : le Researcher scorait la pertinence par LLM mais ne droppait jamais — toutes les findings passaient à l'Analyst.
2. **Confiance aveugle de l'Analyst** : l'Analyst supposait que toute finding routée vers son focus_area était pertinente, sans validation sémantique vis-à-vis du `target_description`.

## Décision

Filtre à deux étages, conservateur par défaut.

### Étage 1 — Researcher (deux seuils)

Dans `src/nexus/agents/researcher.py`, ajout d'un `_filter_findings` exécuté juste après `_score_findings` :

| Seuil | Source | Default | Réglable via |
|-------|--------|---------|--------------|
| `relevance_score` (LLM 0–1) | scoring_fn (LLM brief) | 0.5 | `Settings.researcher_min_relevance` |
| `context_relevance` (cosine sim) | `embed(target) · embed(title+summary)` | 0.35 | `Settings.researcher_min_context_relevance` |

Le second seuil ne tire que si un `embed_fn` est injecté. En production le constructeur du graph fournit `get_openai_embed_fn()`, en tests on injecte un stub.

Chaque drop est loggué via structlog avec `reason=low_score` ou `reason=off_target`, le `task_id`, et les identifiers — observable dans Langfuse.

**Comportement défensif** :

- Embedding du target échoue → on skip *seulement* l'étage 2 (les findings score-passantes restent).
- Embedding d'une finding échoue → on garde la finding (jamais d'abort sur observabilité).
- Aucune finding score-passante → on skip l'étage 2 immédiatement.

### Étage 2 — Analyst (gate LLM yes/no)

Avant chaque appel `_synthesise`, l'Analyst pose une question binaire au LLM via un nouveau `_group_is_relevant` :

```
Target architecture: <target_description>
Focus area: <focus_area>
Findings: <top-5 bullets>
Are these findings actually relevant ...? Reply 'yes - <why>' or 'no - <why>'.
```

Réponse parsée sur le premier mot (`no` → skip + log `analyst_skipped_off_target` avec le focus_area et les finding_ids). Toute autre réponse (`yes`, `maybe`, parse error, LLM down) → on garde le groupe.

**Pourquoi un appel LLM séparé plutôt qu'un check intégré au prompt de synthèse :**

- Séparation des préoccupations : le gate est binaire et bon-marché (~50 tokens out vs ~500 pour la synthèse).
- Observabilité : un span Langfuse dédié (`step=relevance_gate`) rend les rejets traçables.
- Robustesse : un gate défaillant ne corrompt pas le payload JSON de la synthèse — il fail-open, point.

**Pourquoi fail-open** : un gate fail-closed (skip si LLM down) ferait disparaître des surfaces légitimes lors des pannes OpenAI. Les drops Researcher sont déjà conservateurs ; ce 2e étage est une ceinture-bretelle, pas un gatekeeper critique.

## Conséquences

**Positives :**

- L'incident M-Banking-sur-RAG ne devrait plus passer : étage 1 le drop sur cosine (sujet financier vs RAG technique), ou étage 2 le drop sur le verdict LLM.
- Les seuils sont réglables — un futur Researcher plus précis pourra les remonter sans modifier le code.
- Les drops sont auditables (structlog + Langfuse).

**Négatives / à surveiller :**

- Coût LLM : +N appels gate par run (N = nombre de focus_areas avec findings, généralement 4–6). Token usage marginal vs synthèse, mais à monitorer.
- False-negatives possibles : une finding ATLAS générique sur prompt-injection peut avoir un cosine bas contre une cible "FastAPI Streamlit pgvector" parce que les embeddings comparent les détails techniques plutôt que les concepts. Mitigation : seuils conservateurs (0.35), réajustables si on observe trop de drops légitimes.
- Tests existants `test_scoring_fn_is_applied_to_each_finding` ajusté : score 0.42 → 0.72 pour ne pas tomber sous le nouveau seuil 0.5.

## Validation

- 49 tests `tests/agents/test_{researcher,analyst}.py` verts, dont :
  - drop findings sous min_relevance,
  - réglage par `Settings.researcher_min_relevance` (monkeypatch),
  - drop findings off-topic par cosine orthogonal (regression M-Banking-on-RAG),
  - keep findings on-topic par cosine aligné,
  - embed failure ne droppe jamais,
  - gate analyst skip sur "no",
  - gate analyst keep sur "yes",
  - gate failure fall-open,
  - one gate call par focus group.
- 209/209 tests non-integration verts globalement, pas de régression.
- Critère de succès complet (≥ 9/10 paires off-topic rejetées) nécessite l'eval harness S9.T1 ; non bloquant pour ce sprint.

## Voir aussi

- ADR-0007 (calibration de sévérité) — sprint S8.T1.
- S9.T1 (eval harness 20-target) — validera quantitativement le ≥ 9/10 sur paires off-topic curated.
