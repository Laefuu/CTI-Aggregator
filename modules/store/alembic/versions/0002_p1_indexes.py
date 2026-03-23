"""Add P1 indexes: pipeline_metrics TTL, object_sources source_id, stix_objects GIN

Revision ID: 0002
Revises: 0001
Create Date: 2026-03-14
"""
from __future__ import annotations

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # ── pipeline_metrics ─────────────────────────────────────
    # Composite index for dashboard queries (module + time window)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_metrics_module_metric_time
            ON pipeline_metrics (module, metric, recorded_at DESC);
    """)

    # ── object_sources ────────────────────────────────────────
    # Index to count distinct sources per object (used for corroboration score)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_obj_src_url_object
            ON object_sources (source_url, stix_object_id);
    """)

    # ── stix_objects ──────────────────────────────────────────
    # Partial index for non-merged objects sorted by confidence
    # Speeds up API queries: GET /indicators?sort=confidence
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_stix_active_confidence
            ON stix_objects (confidence DESC, created_at DESC)
            WHERE is_merged = FALSE;
    """)

    # ── Automatic cleanup function for pipeline_metrics ───────
    # Purge entries older than 60 days (matches retention policy)
    # This function is called manually or via pg_cron in production
    op.execute("""
        CREATE OR REPLACE FUNCTION purge_old_metrics()
        RETURNS INTEGER AS $$
        DECLARE
            deleted INTEGER;
        BEGIN
            DELETE FROM pipeline_metrics
            WHERE recorded_at < NOW() - INTERVAL '60 days';
            GET DIAGNOSTICS deleted = ROW_COUNT;
            RETURN deleted;
        END;
        $$ LANGUAGE plpgsql;
    """)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_metrics_module_metric_time;")
    op.execute("DROP INDEX IF EXISTS idx_obj_src_url_object;")
    op.execute("DROP INDEX IF EXISTS idx_stix_active_confidence;")
    op.execute("DROP FUNCTION IF EXISTS purge_old_metrics();")
