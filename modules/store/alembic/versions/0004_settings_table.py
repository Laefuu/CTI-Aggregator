"""Create settings key/value table

Used to store configurable settings (e.g. LLM system prompt)
that can be edited at runtime via the API.

Revision ID: 0004
Revises: 0003
Create Date: 2026-04-13
"""
from __future__ import annotations

from alembic import op

revision: str = "0004"
down_revision: str = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS settings")
