"""Initial PhishGuard schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-11-23
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

_preexisting_schema = False


def upgrade() -> None:
    global _preexisting_schema
    bind = op.get_bind()
    inspector = inspect(bind)
    existing = set(inspector.get_table_names())
    _preexisting_schema = bool(existing.intersection({"urls", "analyses", "emails", "email_analyses"}))

    if "urls" not in existing:
        op.create_table(
            "urls",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("raw_url", sa.String(), nullable=False),
            sa.Column("normalized_url", sa.String(), nullable=False),
            sa.Column("scheme", sa.String(), nullable=False),
            sa.Column("hostname", sa.String(), nullable=False),
            sa.Column("registrable_domain", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        )
        op.create_index("ix_urls_raw_url", "urls", ["raw_url"], unique=True)
        op.create_index("ix_urls_scheme", "urls", ["scheme"])
        op.create_index("ix_urls_hostname", "urls", ["hostname"])
        op.create_index("ix_urls_registrable_domain", "urls", ["registrable_domain"])

    if "analyses" not in existing:
        op.create_table(
            "analyses",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("url_id", sa.Integer(), sa.ForeignKey("urls.id"), nullable=False),
            sa.Column("classification", sa.String(), nullable=False),
            sa.Column("risk_score", sa.Integer(), nullable=False),
            sa.Column("confidence", sa.Float(), nullable=True),
            sa.Column("features", sa.JSON(), nullable=False),
            sa.Column("evidence", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        )
        op.create_index("ix_analyses_url_id", "analyses", ["url_id"])
        op.create_index("ix_analyses_classification", "analyses", ["classification"])

    if "emails" not in existing:
        op.create_table(
            "emails",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("from_address", sa.String(), nullable=False),
            sa.Column("reply_to", sa.String(), nullable=True),
            sa.Column("subject", sa.String(), nullable=False),
            sa.Column("body_text", sa.String(), nullable=False),
            sa.Column("body_html", sa.String(), nullable=False),
            sa.Column("headers", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        )
        op.create_index("ix_emails_from_address", "emails", ["from_address"])

    if "email_analyses" not in existing:
        op.create_table(
            "email_analyses",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("email_id", sa.Integer(), sa.ForeignKey("emails.id"), nullable=False),
            sa.Column("classification", sa.String(), nullable=False),
            sa.Column("risk_score", sa.Integer(), nullable=False),
            sa.Column("confidence", sa.Float(), nullable=True),
            sa.Column("features", sa.JSON(), nullable=False),
            sa.Column("evidence", sa.JSON(), nullable=False),
            sa.Column("urls", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        )
        op.create_index("ix_email_analyses_email_id", "email_analyses", ["email_id"])
        op.create_index("ix_email_analyses_classification", "email_analyses", ["classification"])


def downgrade() -> None:
    if _preexisting_schema:
        return
    op.drop_table("email_analyses")
    op.drop_table("emails")
    op.drop_table("analyses")
    op.drop_table("urls")
