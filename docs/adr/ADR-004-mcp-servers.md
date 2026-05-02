# ADR-004 — MCP Servers custom : arXiv + NVD + MITRE ATLAS

**Date :** Phase 0 | **Statut :** Accepted

## Décision

3 MCP servers custom, sélectionnés pour maximiser la valeur perçue en entretien et l'utilité réelle pour le cas d'usage. Web scraping MCP générique rejeté.

## Servers retenus

| Server | Justification | Unicité portfolio |
|--------|---------------|-------------------|
| arXiv | Recherche académique en temps réel — aucun LLM n'a les papers récents | Rare dans les portfolios ML |
| NVD/CVE | Données CVE factuelles — grounding obligatoire (zéro hallucination tolérée) | Montre la maîtrise des APIs de sécurité |
| MITRE ATLAS | Référentiel AI-specific unique — connecte directement à ThreatRAG | Démontre la connaissance du domaine AI Security |

## Servers rejetés

| Server | Raison du rejet |
|--------|-----------------|
| Web scraping générique | Tool natif LangGraph suffisant, zéro valeur ajoutée, fait par tout le monde |
| MITRE ATT&CK générique | Trop généraliste — ATLAS est l'équivalent AI-specific, plus pertinent |
| Exploit DB | Overlap avec RedTeamForge, hors scope NEXUS |
| Code Analysis (AST/semgrep) | Sprint 8 stretch only — valeur réelle mais pas critique |

## Architecture des MCP servers

Chaque server est un processus Python standalone (stdio transport). Cette approche est :
- Plus robuste (crash isolation)
- Scalable (plusieurs workers possibles)
- Conforme au MCP standard
- Démontrable séparément en entretien

## Connexion depuis les agents

Via `mcp.client.ClientSession` (stdio). Le `MCPClient` wrapper dans `src/nexus/mcp/client.py` gère le connection pooling et la gestion d'erreurs standardisée (retourne `MCPError` JSON, jamais d'exception non catchée).
