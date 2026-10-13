"""CIEM SQLAlchemy models — identity threat findings and scan results."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from gds_api.models import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class CIEMFinding(Base):
    __tablename__ = "ciem_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    cloud_account_id: Mapped[str] = mapped_column(String(64), index=True)
    provider: Mapped[str] = mapped_column(String(20))
    identity_type: Mapped[str] = mapped_column(String(30))  # user, role, service-account
    identity_name: Mapped[str] = mapped_column(String(256))
    identity_arn: Mapped[str] = mapped_column(String(512))
    finding_type: Mapped[str] = mapped_column(String(60), index=True)
    title: Mapped[str] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(10), index=True)  # critical, high, medium, low
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)
    permissions_granted: Mapped[int] = mapped_column(Integer, default=0)
    permissions_used: Mapped[int] = mapped_column(Integer, default=0)
    unused_permissions: Mapped[int] = mapped_column(Integer, default=0)
    last_used: Mapped[str | None] = mapped_column(DateTime, nullable=True)
    days_inactive: Mapped[int] = mapped_column(Integer, default=0)
    blast_radius: Mapped[float] = mapped_column(Float, default=0.0)  # 0-100
    privilege_escalation_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class CIEMScanResult(Base):
    __tablename__ = "ciem_scan_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    cloud_account_id: Mapped[str] = mapped_column(String(64), index=True)
    provider: Mapped[str] = mapped_column(String(20))
    identities_analyzed: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)  # 0-100
    started_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="running")
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
