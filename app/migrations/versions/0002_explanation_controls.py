"""Add persistent explanation cache and request reservations."""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "explanation_cache",
        sa.Column("cache_key", sa.String(64), primary_key=True),
        sa.Column("guidance", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "explanation_attempts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("day", sa.String(10), nullable=False),
        sa.Column("slot", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("window", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("day", "slot", name="uq_explanation_daily_slot"),
        sa.UniqueConstraint("user_id", "window", name="uq_explanation_user_window"),
    )
    op.create_index("ix_explanation_attempts_user_id", "explanation_attempts", ["user_id"])


def downgrade() -> None:
    op.drop_table("explanation_attempts")
    op.drop_table("explanation_cache")
