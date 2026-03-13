"""Create ivfflat index on stix_embeddings

The IVFFlat index requires data to be present before building —
it cannot be created on an empty table (lists parameter needs training data).
Run this migration AFTER the first batch of embeddings has been inserted
(typically at the end of Phase 1).

Revision ID: 0001
Revises:
Create Date: 2026-03-13
"""
from __future__ import annotations

from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # Only create the index if there are enough embeddings to train on.
    # IVFFlat with lists=100 requires at least ~3000 rows for good accuracy.
    # This migration is a no-op if run too early — re-run after data is loaded.
    op.execute("""
        DO $$
        DECLARE
            row_count INTEGER;
        BEGIN
            SELECT COUNT(*) INTO row_count FROM stix_embeddings;
            IF row_count >= 100 THEN
                CREATE INDEX IF NOT EXISTS idx_embed_cosine
                    ON stix_embeddings
                    USING ivfflat (embedding vector_cosine_ops)
                    WITH (lists = 100);
                RAISE NOTICE 'ivfflat index created on % rows', row_count;
            ELSE
                RAISE NOTICE 'Skipping ivfflat index: only % rows (need >= 100)', row_count;
            END IF;
        END $$;
    """)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_embed_cosine;")
