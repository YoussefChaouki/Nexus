-- Semantic memory: Threat Pattern Library ingested from ATLAS and OWASP LLM Top 10.
-- Read-only at runtime; populated via scripts/ingest_patterns.py.
CREATE TABLE IF NOT EXISTS threat_patterns (
    id           TEXT PRIMARY KEY,
    source_type  TEXT NOT NULL,
    pattern_id   TEXT NOT NULL UNIQUE,
    name         TEXT NOT NULL,
    pattern_text TEXT NOT NULL,
    metadata     JSONB NOT NULL DEFAULT '{}',
    embedding    VECTOR(1536)
);

-- IVFFlat index for approximate nearest-neighbour cosine search.
CREATE INDEX IF NOT EXISTS threat_patterns_embedding_idx
    ON threat_patterns
    USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100);

CREATE INDEX IF NOT EXISTS threat_patterns_source_type_idx
    ON threat_patterns (source_type);
