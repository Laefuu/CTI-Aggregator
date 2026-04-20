-- ─────────────────────────────────────────────────────────────
-- CTI Aggregator — PostgreSQL initial schema
-- Runs automatically on first container start
-- For subsequent changes: use Alembic migrations
-- ─────────────────────────────────────────────────────────────

-- ── Extensions ───────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS vector;

-- ── STIX objects ─────────────────────────────────────────────
CREATE TABLE stix_objects (
    id          UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    stix_id     TEXT        UNIQUE NOT NULL,
    stix_type   TEXT        NOT NULL CHECK (stix_type IN (
                                'indicator',
                                'threat-actor',
                                'attack-pattern',
                                'relationship',
                                'report'
                            )),
    stix_data   JSONB       NOT NULL,
    confidence  SMALLINT    NOT NULL DEFAULT 0 CHECK (confidence BETWEEN 0 AND 100),
    tlp_level   TEXT        NOT NULL DEFAULT 'WHITE' CHECK (tlp_level IN ('WHITE', 'GREEN')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    modified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_merged   BOOLEAN     NOT NULL DEFAULT FALSE,
    -- When is_merged=true, points to the canonical object this was merged into
    merged_into TEXT        REFERENCES stix_objects(stix_id) ON DELETE SET NULL
);

COMMENT ON TABLE stix_objects IS 'Canonical STIX 2.1 objects. One row per unique entity after deduplication.';
COMMENT ON COLUMN stix_objects.confidence IS '0-100 score: reliability (35) + freshness (25) + corroboration (20) + llm_quality (20). Detail in stix_data.x_cti_confidence_detail';
COMMENT ON COLUMN stix_objects.is_merged IS 'True if this object was identified as a duplicate and absorbed into merged_into';

-- ── Object provenance ─────────────────────────────────────────
-- Tracks every source that contributed to an object (N sources → 1 canonical object)
CREATE TABLE object_sources (
    id               UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    stix_object_id   UUID        NOT NULL REFERENCES stix_objects(id) ON DELETE CASCADE,
    source_url       TEXT        NOT NULL,
    source_type      TEXT        NOT NULL,
    raw_content      TEXT,                   -- Original text chunk that produced this object
    ingested_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    llm_model        TEXT,
    llm_duration_ms  INTEGER,
    confidence_score REAL
);

COMMENT ON TABLE object_sources IS 'Every source that contributed to a STIX object. Multiple rows per object after merges.';

-- ── Vector embeddings ─────────────────────────────────────────
-- BGE-M3 embeddings (1024 dims) used for semantic deduplication
CREATE TABLE stix_embeddings (
    stix_object_id UUID        PRIMARY KEY REFERENCES stix_objects(id) ON DELETE CASCADE,
    embedding      VECTOR(1024) NOT NULL
);

COMMENT ON TABLE stix_embeddings IS 'BGE-M3 embeddings for threat-actor and attack-pattern objects. Used for semantic deduplication.';

-- ── Configured sources ────────────────────────────────────────
CREATE TABLE sources (
    id            UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    name          TEXT        NOT NULL,
    type          TEXT        NOT NULL CHECK (type IN (
                                  'rss', 'html', 'pdf_url', 'pdf_upload', 'misp', 'taxii'
                              )),
    url           TEXT,
    -- Encrypted credentials and connector-specific options
    config        JSONB       NOT NULL DEFAULT '{}',
    frequency_min INTEGER     NOT NULL DEFAULT 60 CHECK (frequency_min >= 5),
    enabled       BOOLEAN     NOT NULL DEFAULT TRUE,
    -- Affects confidence scoring: trusted=40pts, known=20pts, unknown=0pts
    category      TEXT        NOT NULL DEFAULT 'unknown' CHECK (category IN ('trusted', 'known', 'unknown')),
    tlp_level     TEXT        NOT NULL DEFAULT 'WHITE' CHECK (tlp_level IN ('WHITE', 'GREEN')),
    last_run_at   TIMESTAMPTZ,
    last_status   TEXT        CHECK (last_status IN ('ok', 'error', 'running')),
    last_error    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON COLUMN sources.config IS 'Connector-specific config. Credentials stored encrypted at application level.';
COMMENT ON COLUMN sources.category IS 'trusted=CERTs/tier-1 vendors, known=recognised blogs, unknown=unvetted';

-- ── Surveillance perimeters ───────────────────────────────────
CREATE TABLE perimeters (
    id          UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        TEXT        NOT NULL,
    description TEXT,
    -- List of IoC values to watch (IPs, domains, hashes...)
    ioc_values  TEXT[]      NOT NULL DEFAULT '{}',
    -- Sector keywords for future matching
    sectors     TEXT[]      NOT NULL DEFAULT '{}',
    enabled     BOOLEAN     NOT NULL DEFAULT TRUE,
    -- Optional webhook URL for alert notifications
    webhook_url TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Alerts ────────────────────────────────────────────────────
CREATE TABLE alerts (
    id             UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    perimeter_id   UUID        NOT NULL REFERENCES perimeters(id) ON DELETE CASCADE,
    stix_object_id UUID        NOT NULL REFERENCES stix_objects(id) ON DELETE CASCADE,
    source_url     TEXT,
    triggered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status         TEXT        NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'acked', 'false_positive')),
    notified       BOOLEAN     NOT NULL DEFAULT FALSE,
    notified_at    TIMESTAMPTZ,
    acked_by       TEXT,       -- User who acknowledged
    acked_at       TIMESTAMPTZ
);

-- ── Pipeline metrics ──────────────────────────────────────────
-- Replaces Prometheus — metrics stored directly in PostgreSQL
CREATE TABLE pipeline_metrics (
    id          BIGSERIAL   PRIMARY KEY,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    module      TEXT        NOT NULL,
    metric      TEXT        NOT NULL,
    value       DOUBLE PRECISION NOT NULL,
    labels      JSONB       NOT NULL DEFAULT '{}'
);

COMMENT ON TABLE pipeline_metrics IS 'Pipeline observability. Replaces external Prometheus. Purged with same 60-day policy.';

-- ── Users ─────────────────────────────────────────────────────
CREATE TABLE users (
    id           UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    email        TEXT        UNIQUE NOT NULL,
    password_hash TEXT       NOT NULL,
    is_active    BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login   TIMESTAMPTZ
);

-- ── Indexes ───────────────────────────────────────────────────

-- stix_objects
CREATE INDEX idx_stix_type        ON stix_objects(stix_type);
CREATE INDEX idx_stix_confidence  ON stix_objects(confidence DESC);
CREATE INDEX idx_stix_created     ON stix_objects(created_at DESC);
CREATE INDEX idx_stix_tlp         ON stix_objects(tlp_level);
CREATE INDEX idx_stix_not_merged  ON stix_objects(stix_type) WHERE is_merged = FALSE;
-- GIN index for full-text search on JSONB
CREATE INDEX idx_stix_gin         ON stix_objects USING GIN(stix_data);

-- object_sources
CREATE INDEX idx_obj_src_object   ON object_sources(stix_object_id);
CREATE INDEX idx_obj_src_ingested ON object_sources(ingested_at DESC);
CREATE INDEX idx_obj_src_url      ON object_sources(source_url);

-- alerts
CREATE INDEX idx_alerts_new       ON alerts(triggered_at DESC) WHERE status = 'new';
CREATE INDEX idx_alerts_perimeter ON alerts(perimeter_id, triggered_at DESC);

-- pipeline_metrics
CREATE INDEX idx_metrics_module   ON pipeline_metrics(module, recorded_at DESC);
CREATE INDEX idx_metrics_metric   ON pipeline_metrics(metric, recorded_at DESC);

-- Vector similarity index (IVFFlat — requires data to be present before building)
-- Created post-data-load in a separate migration once embeddings exist
-- CREATE INDEX idx_embed_cosine ON stix_embeddings
--     USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);

-- ── Triggers ──────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION update_modified_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.modified_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_stix_modified
    BEFORE UPDATE ON stix_objects
    FOR EACH ROW EXECUTE FUNCTION update_modified_at();

CREATE TRIGGER trg_sources_updated
    BEFORE UPDATE ON sources
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_perimeters_updated
    BEFORE UPDATE ON perimeters
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
