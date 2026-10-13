"""Continuous Monitoring Engine: the system that makes GDS OS "continuous."

A Temporal-scheduled workflow that runs defensive agents on configurable intervals.
Unlike ad-hoc missions (human-triggered), monitoring runs autonomously on a schedule,
creates findings, triages them, and escalates critical ones — the "continuous
detection, continuous defending, continuous triage" promise.

Each ScanSchedule defines:
  - What agent/tool to run (check_cisa_kev, search_osv_vulnerabilities, etc.)
  - How often (every N minutes/hours/days)
  - What target to scan (CVE watchlist, package list, domain, etc.)
  - Whether auto-triage is enabled
  - Whether auto-escalation to incidents is enabled

The engine uses Temporal's native scheduling — not a separate cron daemon — so
every scheduled run gets the same durable execution, retry, and audit guarantees
as a human-triggered mission.

This module provides:
  - ScanSchedule SQLAlchemy model (the schedule config)
  - MonitoringResult SQLAlchemy model (each run's outcome)
  - API routes for CRUD on schedules + viewing results
  - The activity functions the workflow calls
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String, Text, Integer, Float, Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import JSONB

from gds_api.db import get_db
from gds_api.models import Base
from gds_api.security import CurrentUser, require_permission


class ScanScheduleStatus(StrEnum):
    ACTIVE = "active"
    PAUSED = "paused"
    ERROR = "error"


class MonitorType(StrEnum):
    CISA_KEV = "cisa_kev"              # Check CISA KEV feed against watchlist
    OSV_SCAN = "osv_scan"             # Scan packages for vulnerabilities via OSV.dev
    URLHAUS_CHECK = "urlhaus_check"    # Check domains against abuse.ch URLhaus
    MALWARE_HASH = "malware_hash"      # Check file hashes against MalwareBazaar
    TLS_CERT = "tls_cert"              # Check TLS certificates for expiry/weakness
    SECURITY_HEADERS = "security_headers"  # Check HTTP security headers
    CLOUD_POSTURE = "cloud_posture"    # Run cloud posture evaluation
    DEPENDENCY_SCAN = "dependency_scan"  # SCA on own codebase dependencies
    EPSS_LOOKUP = "epss_lookup"        # Enrich findings with EPSS scores
    SAST_SCAN = "sast_scan"            # Static analysis via Semgrep
    DAST_SCAN = "dast_scan"             # Dynamic testing via Nuclei
    CONTAINER_SCAN = "container_scan"   # Container image scanning via Trivy
    IAC_SCAN = "iac_scan"              # IaC scanning via Checkov
    DARKWEB_MONITOR = "darkweb_monitor"  # Credential leak monitoring via HIBP
    IDENTITY_THREATS = "identity_threats"  # Identity threat detection


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ScanSchedule(Base):
    """A scheduled, recurring monitoring job. Each row defines one continuous
    monitoring stream — e.g., 'check CISA KEV every 6 hours' or 'scan our
    dependencies every 24 hours'."""
    __tablename__ = "scan_schedules"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    name: Mapped[str] = mapped_column(String(200))
    monitor_type: Mapped[str] = mapped_column(String(50))  # MonitorType enum
    target_config: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    # e.g., {"packages": ["requests", "anthropic"], "ecosystem": "pypi"}
    # e.g., {"domains": ["globaldigitalstreams.com"]}
    # e.g., {"cloud_environment_id": "...", "policy_ids": [...]}

    interval_minutes: Mapped[int] = mapped_column(Integer, default=360)  # 6 hours default
    auto_triage: Mapped[bool] = mapped_column(Boolean, default=True)
    auto_escalate: Mapped[bool] = mapped_column(Boolean, default=True)  # auto-create incidents for critical

    status: Mapped[str] = mapped_column(String(20), default=ScanScheduleStatus.ACTIVE.value)
    last_run_at: Mapped[datetime | None] = mapped_column(default=None)
    next_run_at: Mapped[datetime | None] = mapped_column(default=None)
    last_run_findings: Mapped[int] = mapped_column(Integer, default=0)
    total_runs: Mapped[int] = mapped_column(Integer, default=0)
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, default=None)

    created_at: Mapped[datetime] = mapped_column(server_default=__import__('sqlalchemy').sql.func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=__import__('sqlalchemy').sql.func.now(), onupdate=__import__('sqlalchemy').sql.func.now())


class MonitoringResult(Base):
    """One execution of a ScanSchedule — what was found, how long it took,
    whether it triaged/escalated automatically."""
    __tablename__ = "monitoring_results"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    schedule_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scan_schedules.id"))
    monitor_type: Mapped[str] = mapped_column(String(50))
    started_at: Mapped[datetime] = mapped_column(server_default=__import__('sqlalchemy').sql.func.now())
    completed_at: Mapped[datetime | None] = mapped_column(default=None)
    duration_seconds: Mapped[float | None] = mapped_column(default=None)

    findings_created: Mapped[int] = mapped_column(Integer, default=0)
    findings_triaged: Mapped[int] = mapped_column(Integer, default=0)
    incidents_created: Mapped[int] = mapped_column(Integer, default=0)
    critical_findings: Mapped[int] = mapped_column(Integer, default=0)

    status: Mapped[str] = mapped_column(String(20))  # success, error, partial
    error_message: Mapped[str | None] = mapped_column(Text, default=None)
    result_summary: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/monitoring", tags=["monitoring"])


class ScanScheduleCreate(BaseModel):
    name: str
    monitor_type: str  # MonitorType
    target_config: dict[str, Any] = {}
    interval_minutes: int = 360
    auto_triage: bool = True
    auto_escalate: bool = True


class ScanScheduleOut(BaseModel):
    id: str
    name: str
    monitor_type: str
    target_config: dict[str, Any]
    interval_minutes: int
    auto_triage: bool
    auto_escalate: bool
    status: str
    last_run_at: str | None
    next_run_at: str | None
    last_run_findings: int
    total_runs: int
    total_findings: int
    last_error: str | None

    model_config = {"from_attributes": True}


class MonitoringResultOut(BaseModel):
    id: str
    schedule_id: str
    monitor_type: str
    started_at: str
    completed_at: str | None
    duration_seconds: float | None
    findings_created: int
    findings_triaged: int
    incidents_created: int
    critical_findings: int
    status: str
    error_message: str | None
    result_summary: dict[str, Any]

    model_config = {"from_attributes": True}


@router.get("/schedules", response_model=list[ScanScheduleOut])
async def list_schedules(
    current_user: CurrentUser = Depends(require_permission("monitoring:read")),
    db: AsyncSession = Depends(get_db),
) -> list[ScanSchedule]:
    result = await db.execute(
        select(ScanSchedule)
        .where(ScanSchedule.tenant_id == current_user.tenant_id)
        .order_by(ScanSchedule.created_at.desc())
    )
    return list(result.scalars().all())


@router.post("/schedules", response_model=ScanScheduleOut, status_code=status.HTTP_201_CREATED)
async def create_schedule(
    req: ScanScheduleCreate,
    current_user: CurrentUser = Depends(require_permission("monitoring:write")),
    db: AsyncSession = Depends(get_db),
) -> ScanSchedule:
    if req.monitor_type not in [m.value for m in MonitorType]:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Unknown monitor type: {req.monitor_type}")
    if req.interval_minutes < 5:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Minimum interval is 5 minutes")

    schedule = ScanSchedule(
        tenant_id=current_user.tenant_id,
        name=req.name,
        monitor_type=req.monitor_type,
        target_config=req.target_config,
        interval_minutes=req.interval_minutes,
        auto_triage=req.auto_triage,
        auto_escalate=req.auto_escalate,
        next_run_at=datetime.now(UTC),
    )
    db.add(schedule)
    await db.commit()
    await db.refresh(schedule)
    return schedule


@router.patch("/schedules/{schedule_id}", response_model=ScanScheduleOut)
async def update_schedule(
    schedule_id: uuid.UUID,
    req: dict[str, Any],
    current_user: CurrentUser = Depends(require_permission("monitoring:write")),
    db: AsyncSession = Depends(get_db),
) -> ScanSchedule:
    schedule = await db.get(ScanSchedule, schedule_id)
    if schedule is None or schedule.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Schedule not found")

    for key, value in req.items():
        if hasattr(schedule, key) and key not in ("id", "tenant_id", "created_at"):
            setattr(schedule, key, value)

    await db.commit()
    await db.refresh(schedule)
    return schedule


@router.delete("/schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_schedule(
    schedule_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("monitoring:write")),
    db: AsyncSession = Depends(get_db),
) -> None:
    schedule = await db.get(ScanSchedule, schedule_id)
    if schedule is None or schedule.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Schedule not found")
    await db.delete(schedule)
    await db.commit()


@router.get("/results", response_model=list[MonitoringResultOut])
async def list_results(
    schedule_id: uuid.UUID | None = None,
    limit: int = 50,
    current_user: CurrentUser = Depends(require_permission("monitoring:read")),
    db: AsyncSession = Depends(get_db),
) -> list[MonitoringResult]:
    query = select(MonitoringResult).where(MonitoringResult.tenant_id == current_user.tenant_id)
    if schedule_id:
        query = query.where(MonitoringResult.schedule_id == schedule_id)
    query = query.order_by(MonitoringResult.started_at.desc()).limit(limit)
    result = await db.execute(query)
    return list(result.scalars().all())


@router.get("/results/{result_id}", response_model=MonitoringResultOut)
async def get_result(
    result_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("monitoring:read")),
    db: AsyncSession = Depends(get_db),
) -> MonitoringResult:
    result = await db.get(MonitoringResult, result_id)
    if result is None or result.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Result not found")
    return result


@router.post("/schedules/{schedule_id}/run", response_model=MonitoringResultOut)
async def trigger_manual_run(
    schedule_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("monitoring:write")),
    db: AsyncSession = Depends(get_db),
) -> MonitoringResult:
    """Manually trigger a monitoring run outside its schedule."""
    schedule = await db.get(ScanSchedule, schedule_id)
    if schedule is None or schedule.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Schedule not found")

    # Import the monitoring activity to run it directly
    from gds_api.workflows.monitoring_activities import run_monitoring_cycle

    result = await run_monitoring_cycle(
        str(schedule.id),
        str(current_user.tenant_id),
        str(current_user.user_id),
    )
    return result
