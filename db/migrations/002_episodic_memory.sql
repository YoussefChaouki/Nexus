-- Episodic memory: condensed ThreatReport summaries with vector embeddings.
-- One row per pipeline session; used by Planner to recall similar past analyses.
CREATE TABLE IF NOT EXISTS threat_report_summaries (
    id                  TEXT        PRIMARY KEY,
    session_id          TEXT        NOT NULL,
    target_description  TEXT        NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    surface_count       INTEGER     NOT NULL CHECK (surface_count >= 0),
    severity_breakdown  JSONB       NOT NULL DEFAULT '{}',
    focus_areas_covered JSONB       NOT NULL DEFAULT '[]',
    top_attack_vectors  JSONB       NOT NULL DEFAULT '[]',
    overall_critic_score FLOAT      NOT NULL CHECK (overall_critic_score BETWEEN 0 AND 1),
    iteration_count     INTEGER     NOT NULL CHECK (iteration_count >= 1),
    embedding           VECTOR(1536)
);

-- IVFFlat index for approximate nearest-neighbour cosine search.
-- lists=100 is appropriate for tables up to ~1 million rows.
CREATE INDEX IF NOT EXISTS threat_report_summaries_embedding_idx
    ON threat_report_summaries
    USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100);

CREATE INDEX IF NOT EXISTS threat_report_summaries_session_idx
    ON threat_report_summaries (session_id);
