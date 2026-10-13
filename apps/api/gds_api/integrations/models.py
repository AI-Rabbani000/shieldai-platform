"""GDS OS IDE/CI-CD Integration — Models."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, Text, func
from sqlalchemy import Boolean, DateTime, Integer
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from gds_api.models import Base


class CIPipeline(Base):
    __tablename__ = "ci_pipelines"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    name: Mapped[str] = mapped_column(String(200))
    platform: Mapped[str] = mapped_column(String(100))  # github_actions, gitlab_ci, jenkins, circleci, azure_pipelines
    repo_name: Mapped[str] = mapped_column(String(200))
    repo_url: Mapped[str | None] = mapped_column(String(500), default=None)
    branch: Mapped[str] = mapped_column(String(200), default="main")
    has_sast: Mapped[bool] = mapped_column(Boolean, default=False)
    has_sca: Mapped[bool] = mapped_column(Boolean, default=False)
    has_secret_scan: Mapped[bool] = mapped_column(Boolean, default=False)
    has_container_scan: Mapped[bool] = mapped_column(Boolean, default=False)
    has_iac_scan: Mapped[bool] = mapped_column(Boolean, default=False)
    has_dast: Mapped[bool] = mapped_column(Boolean, default=False)
    has_sbom: Mapped[bool] = mapped_column(Boolean, default=False)
    has_signing: Mapped[bool] = mapped_column(Boolean, default=False)
    has_policy_gate: Mapped[bool] = mapped_column(Boolean, default=False)
    security_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    last_run: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    last_run_status: Mapped[str | None] = mapped_column(String(50), default=None)
    config: Mapped[dict] = mapped_column(JSONB, default=dict)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())


class CIGateResult(Base):
    __tablename__ = "ci_gate_results"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    pipeline_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("ci_pipelines.id"))
    run_id: Mapped[str] = mapped_column(String(200))
    commit_sha: Mapped[str] = mapped_column(String(40))
    branch: Mapped[str] = mapped_column(String(200))
    gate_type: Mapped[str] = mapped_column(String(100))  # sast, sca, secret, container, iac, dast, policy
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    gate_decision: Mapped[str] = mapped_column(String(50))  # pass, fail, warn, block
    block_reason: Mapped[str | None] = mapped_column(Text, default=None)
    findings_detail: Mapped[list] = mapped_column(JSONB, default=list)
    scan_duration_seconds: Mapped[int] = mapped_column(Integer, default=0)
    triggered_by: Mapped[str] = mapped_column(String(200), default="ci_system")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class PipelineScan(Base):
    __tablename__ = "pipeline_scans"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    pipeline_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("ci_pipelines.id"))
    scan_type: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(50), default="pending")
    tool_used: Mapped[str] = mapped_column(String(200))
    commit_sha: Mapped[str] = mapped_column(String(40))
    branch: Mapped[str] = mapped_column(String(200))
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    results: Mapped[dict] = mapped_column(JSONB, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    duration_seconds: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
