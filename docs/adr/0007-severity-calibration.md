# ADR-0007 — Analyst severity calibration

**Date :** 2026-05-22 | **Statut :** Accepted | **Sprint :** S8.T1

## Contexte

Les premiers runs end-to-end après S7.T3 ont produit une distribution de sévérité plate : 6/6 ThreatSurface notées `HIGH`, zéro `CRITICAL`/`MEDIUM`/`LOW`. Cible d'évaluation : *"FastAPI backend with pgvector for a RAG pipeline, Streamlit frontend on AWS ECS, OpenAI GPT-4, no authentication, enterprise documents ingested via user upload"*. Avec `no authentication` + `user upload`, au moins une surface devrait être `CRITICAL` (RCE non-auth, prompt injection avec exfil). Le modèle s'aligne sur un défaut HIGH safe-by-default — comportement classique des LLMs sans rubrique d'ancrage.

## Décision

Deux changements appliqués à l'agent Analyst :

### 1. Rubric CVSS + business-impact dans le prompt

Le prompt inclut désormais une rubrique explicite qui ancre chaque bande à un type d'impact + une plage CVSS :

| Bande | Impact | CVSS |
|-------|--------|------|
| CRITICAL | RCE / exfil totale / bypass d'auth sur la trust boundary | ≥ 9.0 |
| HIGH | Escalade de privilèges / fuite partielle / DoS à l'échelle | 7.0–8.9 |
| MEDIUM | Disponibilité dégradée / fuite info non-secrète / mauvaise configuration chaînable | 4.0–6.9 |
| LOW | Reconnaissance / misconfig mineure / defense-in-depth | < 4.0 |

Le prompt instruit explicitement "*When in doubt, prefer the LOWER band*" et nomme la distribution plate HIGH comme un mode de défaillance à éviter.

### 2. Few-shot examples (CRITICAL / HIGH / MEDIUM)

3 templates de raisonnement injectés dans le prompt, chacun avec la chaîne **"untrusted X reaches Y without Z → band"**. Les exemples ne sont pas des outputs à copier verbatim, ils enseignent la *structure du raisonnement*.

### 3. Stockage du `severity_reasoning`

Un nouveau champ optionnel `severity_reasoning: str | None` est ajouté à `ThreatSurface`. Le LLM doit l'émettre, et il est conservé dans le ThreatReport final.

**Alternative considérée :** drop du champ avant validation. Rejeté car :

- la justification est un signal d'audit précieux pour le Critic (S5.T2) et pour la relecture des rapports.
- ajouter un champ optionnel ne casse aucune compatibilité descendante (les anciens reports en mémoire épisodique restent valides).
- l'overhead JSON est négligeable.

### 4. Heuristique evidence-quality (downgrade d'une bande)

Avant validation Pydantic, l'Analyst applique :

```
if len(evidence) < 2 OR max(evidence.relevance_score) < 0.6:
    severity = downgrade_one_band(severity)
```

LOW est un point fixe. Le downgrade émet un log structlog `analyst_severity_downgraded` avec l'original, la nouvelle bande, le nombre de findings et le top relevance — observable dans Langfuse.

**Pourquoi cette règle :** la qualité de preuve plafonne l'affirmation. Avec un seul finding faible, on ne peut pas raisonnablement affirmer CRITICAL — c'est de l'overclaiming.

**Pourquoi un downgrade plutôt qu'une re-research :** le Critic possède déjà le mécanisme de re-research (max 3 itérations). Doubler ce mécanisme à l'étage Analyst dégraderait le throughput sans gain. Le downgrade est un correctif local conservateur.

## Conséquences

**Positives :**

- distribution de sévérité non plate (critère de succès : ≥ 3 bandes distinctes sur 20 cibles benchmark, à valider via S9.T1).
- traçabilité : chaque bande accompagnée d'une justification one-liner.
- robustesse : un Researcher faible (peu de findings ou findings de basse qualité) ne produit plus mécaniquement des `HIGH`.

**Négatives / à surveiller :**

- false-negatives possibles : une menace réellement CRITICAL avec un seul finding très pertinent (score 0.9) sera downgradée en HIGH. Mitigation : le Critic peut demander une re-research pour augmenter la couverture.
- la suite de tests historique a dû être ajustée (`test_analyst_owasp_category_propagates` utilise désormais 2 findings).

## Validation

- 24 tests unitaires verts (`tests/agents/test_analyst.py`), dont :
  - parametrized round-trip sur les 4 bandes,
  - downgrade thin evidence (`len < 2`),
  - downgrade weak relevance (`max < 0.6`),
  - point fixe LOW,
  - prompt contient rubric + 3 exemples + `severity_reasoning`,
  - régression S7 : distribution non plate sur la cible RAG-no-auth.
- 199/199 tests non-integration verts globalement (pas de régression).
