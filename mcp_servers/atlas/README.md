# nexus-mcp-atlas

MITRE ATLAS MCP server. Exposes 3 stdio tools backed by a local STIX 2.1
bundle and an in-memory cosine-similarity index over OpenAI
`text-embedding-3-small` vectors.

## Tools

- `search_techniques(query, max_results=10)` — semantic search over technique
  name + description + tactic.
- `get_technique_detail(technique_id)` — exact lookup by ATLAS id (e.g.
  `AML.T0051`).
- `search_by_tactic(tactic_name)` — case-insensitive filter by ATLAS
  kill-chain phase.

## Setup

The server reads the ATLAS STIX bundle from `ATLAS_STIX_PATH` (defaults to
`<repo>/data/atlas/ATLAS.json`). Download it once before launching:

```bash
mkdir -p data/atlas
curl -L -o data/atlas/ATLAS.json \
  https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.json
```

`OPENAI_API_KEY` must be set so the embedding index can be built at
startup. Tests inject a deterministic embed function and never hit the
OpenAI API.

## Run

```bash
python mcp_servers/atlas/server.py
```
