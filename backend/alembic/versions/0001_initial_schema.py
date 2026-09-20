"""initial schema

The fifteen tables of M2 section 3.2, generated from
``netsentinel_api.db.models.Base.metadata`` rather than transcribed, so the
migration and the models cannot disagree on a column.

Tables are created in foreign-key dependency order and dropped in reverse.

Revision ID: 0001
Revises:
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import Text  # JSONB(astext_type=Text()) is rendered by Alembic
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('assets',
    sa.Column('asset_id', sa.Integer(), nullable=False),
    sa.Column('hostname', sa.String(length=255), nullable=False),
    sa.Column('ip_address', postgresql.INET(), nullable=False),
    sa.Column('os', sa.String(length=100), nullable=True),
    sa.Column('criticality', sa.Enum('low', 'medium', 'high', name='criticality', native_enum=False, create_constraint=True), nullable=False),
    sa.PrimaryKeyConstraint('asset_id')
    )
    op.create_table('iocs',
    sa.Column('ioc_id', sa.Integer(), nullable=False),
    sa.Column('value', sa.String(length=500), nullable=False),
    sa.Column('type', sa.Enum('ip', 'domain', 'url', 'sha256', 'ja4', name='ioc_type', native_enum=False, create_constraint=True), nullable=False),
    sa.Column('misp_event_id', sa.Integer(), nullable=True),
    sa.Column('threat_level', sa.Integer(), nullable=True),
    sa.PrimaryKeyConstraint('ioc_id'),
    sa.UniqueConstraint('value', 'type', name='uq_ioc_value_type')
    )
    op.create_index('ix_iocs_value', 'iocs', ['value'], unique=False)
    op.create_table('ml_models',
    sa.Column('model_id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('tier', sa.Enum('A', 'B', 'C', 'D', name='model_tier', native_enum=False, create_constraint=True), nullable=False),
    sa.Column('version', sa.String(length=30), nullable=False),
    sa.Column('onnx_sha256', sa.String(length=64), nullable=False),
    sa.Column('threshold', sa.Float(), nullable=False),
    sa.Column('mode', sa.Enum('shadow', 'active', 'retired', name='model_mode', native_enum=False, create_constraint=True), nullable=False),
    sa.Column('pr_auc', sa.Float(), nullable=True),
    sa.Column('deployed_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint('char_length(onnx_sha256) = 64', name='ck_onnx_sha256_length'),
    sa.PrimaryKeyConstraint('model_id'),
    sa.UniqueConstraint('name', 'version', name='uq_model_name_version')
    )
    op.create_table('roles',
    sa.Column('role_id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=50), nullable=False),
    sa.Column('permissions', postgresql.JSONB(astext_type=Text()), nullable=False),
    sa.PrimaryKeyConstraint('role_id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('sensors',
    sa.Column('sensor_id', sa.Integer(), nullable=False),
    sa.Column('type', sa.Enum('suricata', 'zeek', 'early_flow', 'wazuh_agent', 'openvas', name='sensor_type', native_enum=False, create_constraint=True), nullable=False),
    sa.Column('host_asset_id', sa.Integer(), nullable=False),
    sa.Column('status', sa.Enum('online', 'offline', 'degraded', name='sensor_status', native_enum=False, create_constraint=True), nullable=False),
    sa.Column('last_seen', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['host_asset_id'], ['assets.asset_id'], ),
    sa.PrimaryKeyConstraint('sensor_id')
    )
    op.create_table('users',
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=50), nullable=False),
    sa.Column('email', sa.String(length=255), nullable=False),
    sa.Column('password_hash', sa.String(length=255), nullable=False),
    sa.Column('role_id', sa.Integer(), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['role_id'], ['roles.role_id'], ),
    sa.PrimaryKeyConstraint('user_id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('username')
    )
    op.create_table('vulnerabilities',
    sa.Column('vuln_id', sa.Integer(), nullable=False),
    sa.Column('asset_id', sa.Integer(), nullable=False),
    sa.Column('cve_id', sa.String(length=30), nullable=False),
    sa.Column('cvss', sa.Float(), nullable=True),
    sa.Column('detected_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint('cvss IS NULL OR (cvss >= 0 AND cvss <= 10)', name='ck_cvss_range'),
    sa.ForeignKeyConstraint(['asset_id'], ['assets.asset_id'], ),
    sa.PrimaryKeyConstraint('vuln_id')
    )
    op.create_table('audit_log',
    sa.Column('log_id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('action', sa.String(length=100), nullable=False),
    sa.Column('entity', sa.String(length=100), nullable=False),
    sa.Column('details', postgresql.JSONB(astext_type=Text()), nullable=False),
    sa.Column('ts', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.user_id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('log_id')
    )
    op.create_index('ix_audit_log_ts', 'audit_log', ['ts'], unique=False)
    op.create_table('detections',
    sa.Column('detection_id', sa.Integer(), nullable=False),
    sa.Column('flow_id', sa.String(length=120), nullable=False),
    sa.Column('sensor_id', sa.Integer(), nullable=False),
    sa.Column('model_id', sa.Integer(), nullable=False),
    sa.Column('risk_score', sa.Float(), nullable=False),
    sa.Column('model_scores', postgresql.JSONB(astext_type=Text()), nullable=False),
    sa.Column('shap_values', postgresql.JSONB(astext_type=Text()), nullable=False),
    sa.Column('shadow', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint('risk_score >= 0 AND risk_score <= 1', name='ck_risk_score_range'),
    sa.ForeignKeyConstraint(['model_id'], ['ml_models.model_id'], ),
    sa.ForeignKeyConstraint(['sensor_id'], ['sensors.sensor_id'], ),
    sa.PrimaryKeyConstraint('detection_id')
    )
    op.create_index('ix_detections_flow_id', 'detections', ['flow_id'], unique=False)
    op.create_table('incidents',
    sa.Column('incident_id', sa.Integer(), nullable=False),
    sa.Column('iris_case_id', sa.Integer(), nullable=True),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('status', sa.Enum('open', 'contained', 'closed', name='incident_status', native_enum=False, create_constraint=True), nullable=False),
    sa.Column('owner_id', sa.Integer(), nullable=True),
    sa.Column('opened_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['owner_id'], ['users.user_id'], ),
    sa.PrimaryKeyConstraint('incident_id')
    )
    op.create_table('alerts',
    sa.Column('alert_id', sa.Integer(), nullable=False),
    sa.Column('detection_id', sa.Integer(), nullable=True),
    sa.Column('asset_id', sa.Integer(), nullable=True),
    sa.Column('incident_id', sa.Integer(), nullable=True),
    sa.Column('source', sa.String(length=50), nullable=False),
    sa.Column('severity', sa.Enum('info', 'low', 'medium', 'high', 'critical', name='severity', native_enum=False, create_constraint=True), nullable=False),
    sa.Column('status', sa.Enum('new', 'triaging', 'escalated', 'closed_true_positive', 'closed_false_positive', name='alert_status', native_enum=False, create_constraint=True), nullable=False),
    sa.Column('src_ip', postgresql.INET(), nullable=True),
    sa.Column('dst_ip', postgresql.INET(), nullable=True),
    sa.Column('mitre_technique', sa.String(length=20), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['asset_id'], ['assets.asset_id'], ),
    sa.ForeignKeyConstraint(['detection_id'], ['detections.detection_id'], ),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.incident_id'], ),
    sa.PrimaryKeyConstraint('alert_id')
    )
    op.create_index('ix_alerts_created_at', 'alerts', [sa.literal_column('created_at DESC')], unique=False)
    op.create_index('ix_alerts_src_ip', 'alerts', ['src_ip'], unique=False)
    op.create_index('ix_alerts_status_severity', 'alerts', ['status', 'severity'], unique=False)
    op.create_table('alert_iocs',
    sa.Column('alert_id', sa.Integer(), nullable=False),
    sa.Column('ioc_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['alert_id'], ['alerts.alert_id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['ioc_id'], ['iocs.ioc_id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('alert_id', 'ioc_id')
    )
    op.create_table('copilot_summaries',
    sa.Column('summary_id', sa.Integer(), nullable=False),
    sa.Column('alert_id', sa.Integer(), nullable=False),
    sa.Column('summary_json', postgresql.JSONB(astext_type=Text()), nullable=False),
    sa.Column('llm_model', sa.String(length=100), nullable=False),
    sa.Column('schema_valid', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['alert_id'], ['alerts.alert_id'], ),
    sa.PrimaryKeyConstraint('summary_id')
    )
    op.create_table('response_actions',
    sa.Column('action_id', sa.Integer(), nullable=False),
    sa.Column('alert_id', sa.Integer(), nullable=False),
    sa.Column('action_type', sa.Enum('block_ip', 'isolate_host', 'kill_process', 'disable_account', name='action_type', native_enum=False, create_constraint=True), nullable=False),
    sa.Column('target', sa.String(length=255), nullable=False),
    sa.Column('status', sa.Enum('pending_approval', 'approved', 'rejected', 'executed', 'rolled_back', 'failed', name='action_status', native_enum=False, create_constraint=True), nullable=False),
    sa.Column('executed_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("status <> 'executed' OR executed_at IS NOT NULL", name='ck_executed_has_timestamp'),
    sa.ForeignKeyConstraint(['alert_id'], ['alerts.alert_id'], ),
    sa.PrimaryKeyConstraint('action_id')
    )
    op.create_index('ix_response_actions_alert_id', 'response_actions', ['alert_id'], unique=False)
    op.create_table('approvals',
    sa.Column('approval_id', sa.Integer(), nullable=False),
    sa.Column('action_id', sa.Integer(), nullable=False),
    sa.Column('approver_id', sa.Integer(), nullable=False),
    sa.Column('decision', sa.Enum('approved', 'rejected', name='approval_decision', native_enum=False, create_constraint=True), nullable=False),
    sa.Column('comment', sa.Text(), nullable=True),
    sa.Column('decided_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['action_id'], ['response_actions.action_id'], ),
    sa.ForeignKeyConstraint(['approver_id'], ['users.user_id'], ),
    sa.PrimaryKeyConstraint('approval_id'),
    sa.UniqueConstraint('action_id')
    )


def downgrade() -> None:
    op.drop_table('approvals')
    op.drop_index('ix_response_actions_alert_id', table_name='response_actions')
    op.drop_table('response_actions')
    op.drop_table('copilot_summaries')
    op.drop_table('alert_iocs')
    op.drop_index('ix_alerts_created_at', table_name='alerts')
    op.drop_index('ix_alerts_src_ip', table_name='alerts')
    op.drop_index('ix_alerts_status_severity', table_name='alerts')
    op.drop_table('alerts')
    op.drop_table('incidents')
    op.drop_index('ix_detections_flow_id', table_name='detections')
    op.drop_table('detections')
    op.drop_index('ix_audit_log_ts', table_name='audit_log')
    op.drop_table('audit_log')
    op.drop_table('vulnerabilities')
    op.drop_table('users')
    op.drop_table('sensors')
    op.drop_table('roles')
    op.drop_table('ml_models')
    op.drop_index('ix_iocs_value', table_name='iocs')
    op.drop_table('iocs')
    op.drop_table('assets')
