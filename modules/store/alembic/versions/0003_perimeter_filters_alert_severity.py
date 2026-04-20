"""Add extended perimeter filters and alert severity

New columns on perimeters:
  - geo_countries     TEXT[]  — targeted/origin countries
  - software_products TEXT[]  — software/products to monitor
  - ip_ranges         TEXT[]  — client IP ranges to watch
  - severity          TEXT    — default severity for alerts from this perimeter

New column on alerts:
  - severity          TEXT    — actual severity of the triggered alert

Revision ID: 0003
Revises: 0002
Create Date: 2026-03-31
"""
from __future__ import annotations

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # ── perimeters — extended filter columns ──────────────────
    op.execute("""
        ALTER TABLE perimeters
            ADD COLUMN IF NOT EXISTS geo_countries     TEXT[]  NOT NULL DEFAULT '{}',
            ADD COLUMN IF NOT EXISTS software_products TEXT[]  NOT NULL DEFAULT '{}',
            ADD COLUMN IF NOT EXISTS ip_ranges         TEXT[]  NOT NULL DEFAULT '{}',
            ADD COLUMN IF NOT EXISTS severity          TEXT    NOT NULL DEFAULT 'medium'
                CONSTRAINT perimeters_severity_check
                CHECK (severity IN ('low', 'medium', 'high', 'critical'));
    """)

    # ── alerts — severity column ──────────────────────────────
    op.execute("""
        ALTER TABLE alerts
            ADD COLUMN IF NOT EXISTS severity TEXT NOT NULL DEFAULT 'medium'
                CONSTRAINT alerts_severity_check
                CHECK (severity IN ('low', 'medium', 'high', 'critical'));
    """)

    # Index: fetch new/high-priority alerts efficiently
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_alerts_severity
            ON alerts (
                (CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high'     THEN 2
                    WHEN 'medium'   THEN 3
                    WHEN 'low'      THEN 4
                END),
                triggered_at DESC
            )
            WHERE status = 'new';
    """)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_alerts_severity;")
    op.execute("ALTER TABLE alerts DROP COLUMN IF EXISTS severity;")
    op.execute("""
        ALTER TABLE perimeters
            DROP COLUMN IF EXISTS severity,
            DROP COLUMN IF EXISTS ip_ranges,
            DROP COLUMN IF EXISTS software_products,
            DROP COLUMN IF EXISTS geo_countries;
    """)
