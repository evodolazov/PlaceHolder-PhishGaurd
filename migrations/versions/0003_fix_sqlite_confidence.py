"""Compatibility revision for the prior SQLite confidence migration

Revision ID: 0003_fix_sqlite_confidence
Revises: 0002_nullable_confidence
"""


revision = "0003_fix_sqlite_confidence"
down_revision = "0002_nullable_confidence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The portable 0002 revision performs the confidence nullability change.
    # This no-op preserves compatibility with databases stamped by the
    # earlier migration chain and does not rebuild tables.
    pass


def downgrade() -> None:
    pass
