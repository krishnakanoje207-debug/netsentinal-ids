"""Schema tests, compiled against the PostgreSQL dialect.

No server needed: SQLAlchemy can render the DDL for a dialect it is not connected
to, which is enough to pin the columns, constraints and indexes the M2 design
specifies. Testing the schema against SQLite instead would prove nothing, because
SQLite has neither JSONB nor INET.
"""

from __future__ import annotations

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateIndex, CreateTable

from netsentinel_api.db.models import (
    Alert,
    Approval,
    AuditLog,
    Base,
    Detection,
    MLModel,
    ModelMode,
    User,
)

DIALECT = postgresql.dialect()

#: Every table in M2 section 3.2.
EXPECTED_TABLES = {
    "roles", "users", "assets", "sensors", "vulnerabilities", "ml_models",
    "detections", "incidents", "alerts", "iocs", "alert_iocs",
    "response_actions", "approvals", "copilot_summaries", "audit_log",
}


def ddl(model) -> str:
    return str(CreateTable(model.__table__).compile(dialect=DIALECT))


def index_ddl(model) -> list[str]:
    return [str(CreateIndex(ix).compile(dialect=DIALECT)) for ix in model.__table__.indexes]


def test_every_designed_table_exists():
    assert set(Base.metadata.tables) == EXPECTED_TABLES


def test_whole_schema_compiles_for_postgres():
    for table in Base.metadata.tables.values():
        assert str(CreateTable(table).compile(dialect=DIALECT))


def test_postgres_specific_types_are_used():
    # The design specifies JSONB for variable-shape data and INET for addresses;
    # falling back to TEXT would lose indexing and validation.
    assert "JSONB" in ddl(Detection)
    assert "INET" in ddl(Alert)


# --- the three schema-level invariants -------------------------------------

def test_no_detection_without_an_explanation():
    """M2 composes a Detection with exactly one Explanation."""
    statement = ddl(Detection)
    assert "shap_values JSONB NOT NULL" in statement
    assert "model_scores JSONB NOT NULL" in statement


def test_an_action_can_have_only_one_approval():
    """1:1, so an action cannot collect approvals until one says yes."""
    column = Approval.__table__.c.action_id
    assert column.unique is True
    assert "UNIQUE" in ddl(Approval)


def test_executed_action_must_carry_a_timestamp():
    statement = str(
        CreateTable(Base.metadata.tables["response_actions"]).compile(dialect=DIALECT)
    )
    assert "ck_executed_has_timestamp" in statement
    # Assert the logic, not just the name: a constraint that compiles to something
    # always true would pass a name check while enforcing nothing.
    assert "status <> 'executed' OR executed_at IS NOT NULL" in statement


# --- guards on scored data -------------------------------------------------

def test_enum_columns_carry_a_check_constraint():
    """Without create_constraint=True an Enum renders a bare VARCHAR.

    SQLAlchemy stopped defaulting that to True in 1.4, so the value domain would
    be enforced nowhere and any string would be storable.
    """
    statement = str(
        CreateTable(Base.metadata.tables["response_actions"]).compile(dialect=DIALECT)
    )
    assert "CHECK (status IN ('pending_approval', 'approved', 'rejected'" in statement
    assert "CHECK (action_type IN ('block_ip'" in statement

    alerts = ddl(Alert)
    assert "CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical'))" in alerts


def test_risk_score_is_bounded():
    assert "ck_risk_score_range" in ddl(Detection)


def test_onnx_hash_length_is_enforced():
    # A truncated hash silently stops identifying the artefact it names.
    assert "ck_onnx_sha256_length" in ddl(MLModel)


def test_model_defaults_to_shadow_mode():
    assert MLModel.__table__.c.mode.default.arg is ModelMode.shadow


def test_model_version_is_unique_per_name():
    assert "uq_model_name_version" in ddl(MLModel)


# --- indexes named in M2 section 3.2 ---------------------------------------

def test_alert_indexes_match_the_design():
    statements = " ".join(index_ddl(Alert))
    assert "ix_alerts_created_at" in statements
    assert "DESC" in statements, "the dashboard lists newest first"
    assert "ix_alerts_status_severity" in statements
    assert "ix_alerts_src_ip" in statements


def test_detection_and_audit_indexes_exist():
    assert any("ix_detections_flow_id" in s for s in index_ddl(Detection))
    assert any("ix_audit_log_ts" in s for s in index_ddl(AuditLog))


def test_ioc_value_is_indexed_and_unique_per_type():
    iocs = Base.metadata.tables["iocs"]
    statements = [str(CreateIndex(ix).compile(dialect=DIALECT)) for ix in iocs.indexes]
    assert any("ix_iocs_value" in s for s in statements)
    assert "uq_ioc_value_type" in str(CreateTable(iocs).compile(dialect=DIALECT))


# --- referential rules ----------------------------------------------------

def test_audit_rows_outlive_the_user_they_name():
    """Deleting an account must not erase the audit trail."""
    fk = next(iter(AuditLog.__table__.c.user_id.foreign_keys))
    assert fk.ondelete == "SET NULL"
    assert AuditLog.__table__.c.user_id.nullable is True


def test_alert_ioc_links_are_cleaned_up_with_their_parents():
    link = Base.metadata.tables["alert_iocs"]
    for column in ("alert_id", "ioc_id"):
        fk = next(iter(link.c[column].foreign_keys))
        assert fk.ondelete == "CASCADE"


def test_alert_may_exist_without_a_detection():
    # Suricata and Wazuh alerts have no ML detection behind them.
    assert Alert.__table__.c.detection_id.nullable is True


def test_credentials_are_never_stored_in_the_clear():
    columns = set(User.__table__.c.keys())
    assert "password_hash" in columns
    assert "password" not in columns


@pytest.mark.parametrize(
    "table,column",
    [("users", "username"), ("users", "email"), ("roles", "name")],
)
def test_identity_columns_are_unique(table, column):
    assert Base.metadata.tables[table].c[column].unique is True
