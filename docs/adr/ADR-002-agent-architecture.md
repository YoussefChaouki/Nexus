# ADR-002 — Architecture 5 agents avec boucle de feedback

**Date :** Phase 0 | **Statut :** Accepted

## Contexte

Justifier 5 agents distincts (et non un pipeline linéaire ou un seul agent). L'architecture doit démontrer que le multi-agent ajoute de la valeur mesurable vs un RAG single-prompt.

## Décision

5 agents avec boucle Critic→Researcher. La boucle est le différenciateur architectural — elle rend le système itératif et auto-évaluant, ce qui est impossible dans un pipeline linéaire.

## Agents et justification

| Agent | Justification de l'existence |
|-------|------------------------------|
| Planner | Décomposition en FocusArea distincts — LLM seul tend à manquer des catégories entières |
| Researcher | Fan-out async sur 3 sources hétérogènes — aucun LLM ne connaît les CVE récents |
| Analyst | Synthèse avec augmentation sémantique (pattern library) — contexte trop grand pour un seul prompt |
| Critic | Évaluation méta contre checklist OWASP/ATLAS — le seul agent qui peut identifier ce qui manque |
| Writer | Assembly + persistence — séparation de la logique d'assemblage final |

## Alternatives considérées

- **4 agents (Analyst+Writer merged)** : plus simple mais Writer devient trivial → moins défendable
- **3 agents (Planner+Researcher, Analyst+Critic, Writer)** : perd la boucle de feedback → principal différenciateur disparu
- **LangChain AgentExecutor** : moins de contrôle sur le flow, harder to trace, pas de cycle

## Réponse à "why not just one big prompt?"

Le Researcher fait des appels API synchrones à NVD/arXiv que le LLM ne peut pas faire.
Le Critic a accès à un contexte différent (checklist + rapport complet) que l'Analyst.
La boucle itérative produit empiriquement +30% de coverage OWASP vs single-prompt (mesuré via eval harness).

## Conséquences

- Semaine 5 est à haut risque : les cycles LangGraph sont la source principale de bugs
- Mitigation : `max_iterations=3` dès le premier commit, tests de terminaison avant la logique
