"""Allow uncalibrated heuristic confidence to remain null

Revision ID: 0002_nullable_confidence
Revises: 0001_initial
"""

from alembic import op
import sqlalchemy as sa


revision = "0002_nullable_confidence"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("analyses") as batch_op:
        batch_op.alter_column("confidence", existing_type=sa.Float(), nullable=True)
    with op.batch_alter_table("email_analyses") as batch_op:
        batch_op.alter_column("confidence", existing_type=sa.Float(), nullable=True)


def downgrade() -> None:
    """Restore NOT NULL only after all persisted NULL confidence values are resolved.

    The application legitimately stores NULL confidence when no calibrated model
    provides a value. This downgrade does not invent replacement scores; it will
    fail if such rows remain, so inspect and address them before downgrading.
    """
    with op.batch_alter_table("analyses") as batch_op:
        batch_op.alter_column("confidence", existing_type=sa.Float(), nullable=False)
    with op.batch_alter_table("email_analyses") as batch_op:
        batch_op.alter_column("confidence", existing_type=sa.Float(), nullable=False)
