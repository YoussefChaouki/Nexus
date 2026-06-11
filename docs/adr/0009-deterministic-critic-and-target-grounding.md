# ADR-0009 — Scoring Critic déterministe + synthèse ancrée sur la cible

**Date :** 2026-06-10 | **Statut :** Accepted | **Sprint :** S10

## Contexte

Une passe d'audit backend complète (post S9.T1) a identifié quatre défauts systémiques qui
dégradaient la qualité des `ThreatReport` indépendamment de la qualité du modèle :

1. **L'Analyst ne voyait jamais `target_description`.** Le prompt de synthèse contenait la
   rubrique de sévérité S8.T1 ("untrusted input reaches a privileged sink in the target
   description") mais pas la description de la cible elle-même. Le LLM ne pouvait ni calibrer
   la sévérité contre les vraies trust boundaries, ni produire des mitigations spécifiques —
   d'où des surfaces génériques.
2. **Le Researcher n'utilisait que `search_queries[0]`.** Le Planner génère 1-3 requêtes par
   tâche ; tout ce qui suivait la première était silencieusement jeté. Couverture de recherche
   amputée d'un facteur potentiel de 3.
3. **`overall_score` était calculé par le LLM.** Le prompt du Critic définit pourtant le score
   comme un ratio exact (`covered / applicable`) — confier une division à un LLM alors que ce
   score pilote la boucle de re-recherche est une source d'instabilité documentée.
4. **Latence séquentielle.** Scoring de pertinence et embeddings de contexte étaient awaités
   un par un (jusqu'à ~180 appels LLM/embeddings en série par itération).

## Décision

### 1. Synthèse Analyst ancrée sur la cible

`_build_prompt` reçoit désormais `target_description` et exige que description,
attack_vectors et mitigations soient ancrés dans les composants réels de la cible. Les
findings sont triés par `relevance_score` décroissant et plafonnés à 12 dans le prompt
(`_MAX_FINDINGS_IN_PROMPT`) ; l'`evidence` attachée est triée du plus fort au plus faible.

### 2. Fan-out complet des requêtes du Researcher

Chaque tâche fan-out sur **toutes** ses `search_queries` (plafonnées à 3 par
`_MAX_QUERIES_PER_TASK`) × 3 MCP servers. Le dedup garde désormais la copie au meilleur
`relevance_score` au lieu de la première arrivée. Le parsing du score LLM tolère la prose
(`"Score: 0.85"`) via regex au lieu de retomber silencieusement sur 0.5.

### 3. Couverture OWASP calculée en code dans le Critic

Après validation du `CriticReport` LLM, le Critic recalcule :

```
covered  = codes OWASP normalisés (regex) des owasp_category des surfaces ∩ applicable
coverage = len(covered) / len(applicable)   → remplace overall_score
```

- Divergence LLM/calcul > 0.05 → log `critic_score_overridden` (télémétrie de biais).
- Chaque catégorie applicable non couverte est ajoutée aux `gaps` (sans doublon).
- Sur RE_RESEARCH, chaque catégorie non couverte dont le focus_area mappé
  (`_OWASP_TO_FOCUS`) n'est adressé par aucune tâche reçoit une `ResearchTask` synthétisée
  (priorité HIGH, requête dérivée du titre OWASP) — l'itération suivante attaque *tous* les
  gaps, pas seulement ceux que le LLM a pensé à émettre.

**Le LLM garde la propriété qualitative** de `recommendation` et `bias_warnings` : on ne force
pas RE_RESEARCH quand le LLM approuve avec un score bas (jugement qualitatif respecté,
guardrails inchangés : APPROVE forcé à coverage ≥ 0.6 ou `max_iterations`).

### 4. Concurrence bornée + hygiène config

- Scoring et embeddings par finding via `asyncio.gather` sous `Semaphore(8)`.
- `route_after_critic` lit `Settings.max_iterations` (le hardcode `_MAX_ITERATIONS = 3`
  violait la convention CLAUDE.md).
- Nouveau `Settings.llm_temperature` (défaut 0.0) appliqué dans `AgentBase._get_llm()` —
  tous les agents parsent du JSON strict, le sampling par défaut ne faisait qu'ajouter des
  retries de validation.

## Conséquences

- Le score qui pilote la boucle de feedback est exact et reproductible ; les rapports
  documentent les gaps réels même sur APPROVE.
- La couverture de recherche reflète enfin le plan complet du Planner.
- Latence Researcher : ~N appels séquentiels → ⌈N/8⌉ vagues parallèles.
- Coût : le fan-out multi-requêtes augmente les appels MCP (gratuits/locaux) et le nombre de
  findings à scorer — borné par le dedup et les seuils de pertinence S8.T2.
- Risque accepté : la correspondance gap→tâche par focus_area est grossière (LLM07/08/09
  partagent OTHER) ; une tâche par focus_area suffit au dispatch du Researcher.
