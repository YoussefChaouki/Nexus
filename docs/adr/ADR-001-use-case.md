# ADR-001 — Choix du cas d'usage : AI Vulnerability Intelligence

**Date :** Phase 0  
**Statut :** Accepted  
**Décideurs :** Portfolio owner

---

## Contexte

NEXUS est un système multi-agent portfolio. Le cas d'usage doit démontrer la valeur du multi-agent (pas juste un RAG amélioré), être différenciant pour les cibles (Anthropic, OpenAI, DeepMind, NVIDIA Security), et s'intégrer dans l'arc AI Security du portfolio.

## Décision

NEXUS implémente **AI Vulnerability Intelligence** : donné une description d'architecture AI, NEXUS produit automatiquement un ThreatReport structuré avec attack surfaces, CVEs, papers académiques, et mitigations.

## Options considérées

| Option | Verdict | Raison principale du rejet |
|--------|---------|---------------------------|
| ML Research Synthesis (arxiv papers) | Rejeté | Perplexity/Elicit font ça. Zéro différenciation AI Security. |
| AI Incident Analysis (AIAAIC) | Rejeté | Dataset trop pauvre pour démos riches |
| AI Vulnerability Intelligence | Retenu | — |
| Code Review générique | Rejeté | Overlap avec RedTeamForge, domaine trop large |

## Conséquences

**Positives :**
- Arc narratif cohérent : NEXUS (research) → ThreatRAG (map) → RedTeamForge (exec)
- Agents ont des rôles distincts et défendables : Planner décompose en FocusArea, Researcher ground les données factuelles, Critic évalue contre checklist OWASP/ATLAS
- MCP servers uniques dans les portfolios ML : arXiv + NVD + MITRE ATLAS
- Demo story tangible : "Je donne CITADEL à NEXUS → il identifie 7 attack surfaces avec CVE references"

**Négatives :**
- Qualité des résultats dépend des données (NVD, arxiv) — risque de hallucination sur les identifiants
- Contre-mesure : ground tout dans des API calls, jamais de free recall LLM sur les CVE IDs

## Artefact de sortie

`ThreatReport` JSON structuré avec : `threat_surfaces[]`, `evidence[]`, `critic_report` (avec `gaps[]` explicites), `metadata` (tokens, coût, latence).
La définition de l'artefact précède l'architecture des agents — c'est la décision structurante.
