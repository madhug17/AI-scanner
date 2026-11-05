"""initial schema

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-11-04 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '001_initial_schema'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'scan_jobs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('repository_url', sa.String(length=512), nullable=False),
        sa.Column('repository_owner', sa.String(length=128), nullable=False),
        sa.Column('repository_name', sa.String(length=128), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('scan_version', sa.String(length=32), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scan_jobs_repository_url'), 'scan_jobs', ['repository_url'], unique=False)
    op.create_index(op.f('ix_scan_jobs_status'), 'scan_jobs', ['status'], unique=False)

    op.create_table(
        'findings',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('scan_id', sa.String(length=36), nullable=False),
        sa.Column('rule_id', sa.String(length=64), nullable=False),
        sa.Column('title', sa.String(length=256), nullable=False),
        sa.Column('category', sa.String(length=64), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('impact', sa.Text(), nullable=False),
        sa.Column('recommendation', sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(['scan_id'], ['scan_jobs.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_findings_scan_id'), 'findings', ['scan_id'], unique=False)
    op.create_index(op.f('ix_findings_rule_id'), 'findings', ['rule_id'], unique=False)

    op.create_table(
        'evidence',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('finding_id', sa.String(length=36), nullable=False),
        sa.Column('file_path', sa.String(length=512), nullable=False),
        sa.Column('line_start', sa.Integer(), nullable=False),
        sa.Column('line_end', sa.Integer(), nullable=False),
        sa.Column('code_snippet', sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_evidence_finding_id'), 'evidence', ['finding_id'], unique=False)

    op.create_table(
        'scan_summaries',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('scan_id', sa.String(length=36), nullable=False),
        sa.Column('risk_score', sa.Float(), nullable=False),
        sa.Column('risk_category', sa.String(length=32), nullable=False),
        sa.Column('critical_count', sa.Integer(), nullable=False),
        sa.Column('high_count', sa.Integer(), nullable=False),
        sa.Column('medium_count', sa.Integer(), nullable=False),
        sa.Column('low_count', sa.Integer(), nullable=False),
        sa.Column('info_count', sa.Integer(), nullable=False),
        sa.Column('scan_complete', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['scan_id'], ['scan_jobs.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('scan_id')
    )


def downgrade() -> None:
    op.drop_table('scan_summaries')
    op.drop_table('evidence')
    op.drop_table('findings')
    op.drop_table('scan_jobs')

