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

_REQUIRED_COLUMNS = {
    "urls": {"id", "raw_url", "normalized_url", "scheme", "hostname", "registrable_domain", "created_at"},
    "analyses": {"id", "url_id", "classification", "risk_score", "confidence", "features", "evidence", "created_at"},
    "emails": {"id", "from_address", "reply_to", "subject", "body_text", "body_html", "headers", "created_at"},
    "email_analyses": {"id", "email_id", "classification", "risk_score", "confidence", "features", "evidence", "urls", "created_at"},
}
_REQUIRED_NOT_NULL_COLUMNS = {
    "urls": {"raw_url", "normalized_url", "scheme", "hostname", "registrable_domain", "created_at"},
    "analyses": {"url_id", "classification", "risk_score", "features", "evidence", "created_at"},
    "emails": {"from_address", "subject", "body_text", "body_html", "headers", "created_at"},
    "email_analyses": {"email_id", "classification", "risk_score", "features", "evidence", "urls", "created_at"},
}
_REQUIRED_PRIMARY_KEYS = {
    "urls": ["id"],
    "analyses": ["id"],
    "emails": ["id"],
    "email_analyses": ["id"],
}
_REQUIRED_FOREIGN_KEYS = {
    "analyses": [(["url_id"], "urls", ["id"])],
    "email_analyses": [(["email_id"], "emails", ["id"])],
}
_REQUIRED_INDEXES = {
    "urls": [
        ("ix_urls_raw_url", ["raw_url"], True),
        ("ix_urls_scheme", ["scheme"], False),
        ("ix_urls_hostname", ["hostname"], False),
        ("ix_urls_registrable_domain", ["registrable_domain"], False),
    ],
    "analyses": [
        ("ix_analyses_url_id", ["url_id"], False),
        ("ix_analyses_classification", ["classification"], False),
    ],
    "emails": [("ix_emails_from_address", ["from_address"], False)],
    "email_analyses": [
        ("ix_email_analyses_email_id", ["email_id"], False),
        ("ix_email_analyses_classification", ["classification"], False),
    ],
}


def _validate_existing_tables(bind, existing: set[str]) -> None:
    inspector = inspect(bind)
    for table_name in _REQUIRED_COLUMNS.keys() & existing:
        columns = inspector.get_columns(table_name)
        actual_columns = {column["name"] for column in columns}
        missing = sorted(_REQUIRED_COLUMNS[table_name] - actual_columns)
        if missing:
            raise RuntimeError(
                f"Cannot safely upgrade legacy table '{table_name}': "
                f"missing required columns: {', '.join(missing)}"
            )

        nullable = {
            column["name"]
            for column in columns
            if column["name"] in _REQUIRED_NOT_NULL_COLUMNS[table_name] and column["nullable"]
        }
        if nullable:
            raise RuntimeError(
                f"Cannot safely upgrade legacy table '{table_name}': "
                f"columns must be NOT NULL: {', '.join(sorted(nullable))}. "
                "Correct the schema and data before retrying."
            )

        primary_key = inspector.get_pk_constraint(table_name).get("constrained_columns") or []
        if primary_key != _REQUIRED_PRIMARY_KEYS[table_name]:
            raise RuntimeError(
                f"Cannot safely upgrade legacy table '{table_name}': "
                f"expected primary key on {', '.join(_REQUIRED_PRIMARY_KEYS[table_name])}. "
                "The migration will not rebuild the table; correct the schema without "
                "discarding data before retrying."
            )

        actual_foreign_keys = {
            (
                tuple(foreign_key.get("constrained_columns") or []),
                foreign_key.get("referred_table"),
                tuple(foreign_key.get("referred_columns") or []),
            )
            for foreign_key in inspector.get_foreign_keys(table_name)
        }
        for local_columns, referred_table, referred_columns in _REQUIRED_FOREIGN_KEYS.get(table_name, []):
            expected = (tuple(local_columns), referred_table, tuple(referred_columns))
            if expected not in actual_foreign_keys:
                raise RuntimeError(
                    f"Cannot safely upgrade legacy table '{table_name}': "
                    f"missing foreign key from {', '.join(local_columns)} to "
                    f"{referred_table}({', '.join(referred_columns)}). "
                    "The migration will not rebuild the table; verify existing references "
                    "and correct the schema without discarding data before retrying."
                )


def _has_required_index(bind, table_name: str, columns: list[str], unique: bool) -> bool:
    inspector = inspect(bind)
    for index in inspector.get_indexes(table_name):
        if index.get("column_names") == columns and bool(index.get("unique")) == unique:
            return True
    if unique:
        return any(
            constraint.get("column_names") == columns
            for constraint in inspector.get_unique_constraints(table_name)
        )
    return False


def _has_unique_index_or_constraint(bind, table_name: str, columns: list[str]) -> bool:
    inspector = inspect(bind)
    if any(
        index.get("column_names") == columns and index.get("unique")
        for index in inspector.get_indexes(table_name)
    ):
        return True
    return any(
        constraint.get("column_names") == columns
        for constraint in inspector.get_unique_constraints(table_name)
    )


def _ensure_required_indexes(bind) -> None:
    for table_name, indexes in _REQUIRED_INDEXES.items():
        existing_indexes = {index.get("name"): index for index in inspect(bind).get_indexes(table_name)}
        for index_name, columns, unique in indexes:
            if not unique and _has_unique_index_or_constraint(bind, table_name, columns):
                raise RuntimeError(
                    f"Cannot safely upgrade table '{table_name}': expected a non-unique "
                    f"index on ({', '.join(columns)}), but a unique index or constraint "
                    "exists on those columns. The migration will not remove it; resolve "
                    "the schema incompatibility without discarding data before retrying."
                )
            if _has_required_index(bind, table_name, columns, unique):
                continue
            conflicting_index = existing_indexes.get(index_name)
            if conflicting_index is not None:
                existing_uniqueness = "unique" if conflicting_index.get("unique") else "non-unique"
                required_uniqueness = "unique" if unique else "non-unique"
                raise RuntimeError(
                    f"Cannot safely upgrade table '{table_name}': index '{index_name}' "
                    f"exists on {conflicting_index.get('column_names')} and is "
                    f"{existing_uniqueness}; expected {required_uniqueness} on {columns}. "
                    "Resolve the index name conflict before retrying."
                )
            if unique:
                table = sa.Table(table_name, sa.MetaData(), autoload_with=bind)
                column = table.c[columns[0]]
                duplicate = bind.execute(
                    sa.select(column)
                    .group_by(column)
                    .having(sa.func.count() > 1)
                    .limit(1)
                ).first()
                if duplicate is not None:
                    raise RuntimeError(
                        f"Cannot safely create unique index '{index_name}' on "
                        f"{table_name}({', '.join(columns)}): duplicate existing values "
                        "were found. Resolve duplicates without deleting user data, then retry."
                    )
            op.create_index(index_name, table_name, columns, unique=unique)
            existing_indexes[index_name] = {
                "name": index_name,
                "column_names": columns,
                "unique": unique,
            }


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    existing = set(inspector.get_table_names())
    _validate_existing_tables(bind, existing)

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
    _ensure_required_indexes(bind)


def downgrade() -> None:
    # Downgrading is intentionally conservative: legacy databases may be
    # adopted by this revision, and revision 0001 cannot prove table ownership.
    # Dropping tables here could destroy an existing PhishGuard database.
    return
