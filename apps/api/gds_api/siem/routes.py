import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.db import get_db
from gds_api.security import CurrentUser, require_permission
from gds_api.siem.correlation import seed_default_rules
from gds_api.siem.ingest import ingest_batch, ingest_log
from gds_api.siem.models import CorrelatedIncident, CorrelationRule, SIEMEvent

router = APIRouter(prefix="/siem", tags=["siem"])


class LogIngestRequest(BaseModel):
    source: str
    source_type: str
    format: str | None = None
    raw_data: Any


class BatchIngestRequest(BaseModel):
    source: str
    source_type: str
    format: str | None = None
    logs: list[Any]


class CorrelationRuleCreate(BaseModel):
    name: str
    description: str | None = None
    rule_type: str  # threshold, sequence, aggregation, mitre_match
    conditions: dict = Field(default_factory=dict)
    time_window_seconds: int = 300
    threshold: int = 1
    severity: str = "high"
    mitre_technique: str | None = None
    is_active: bool = True


class IncidentResolveRequest(BaseModel):
    status: str = "resolved"  # resolved, false_positive, investigating, open
    notes: str | None = None


@router.post("/ingest", status_code=status.HTTP_201_CREATED)
async def ingest_single_log(
    body: LogIngestRequest,
    current_user: CurrentUser = Depends(require_permission("siem:write")),
    db: AsyncSession = Depends(get_db),
):
    """Single log ingestion (body: source, source_type, format, raw_data)"""
    event = await ingest_log(
        db,
        current_user.tenant_id,
        body.source,
        body.source_type,
        body.raw_data,
        body.format,
    )
    return {
        "status": "success",
        "event_id": str(event.id),
        "source": event.source,
        "source_type": event.source_type,
        "severity": event.severity,
        "event_category": event.event_category,
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "user": event.user,
        "action": event.action,
        "result": event.result,
        "country": event.country,
        "threat_intel_match": event.threat_intel_match,
        "correlated": event.correlated,
        "correlation_id": str(event.correlation_id) if event.correlation_id else None,
        "event_time": event.event_time.isoformat() if event.event_time else None,
        "ingested_at": event.ingested_at.isoformat() if event.ingested_at else None,
        "normalized": event.normalized,
    }


@router.post("/ingest/batch", status_code=status.HTTP_201_CREATED)
async def ingest_batch_logs(
    body: BatchIngestRequest,
    current_user: CurrentUser = Depends(require_permission("siem:write")),
    db: AsyncSession = Depends(get_db),
):
    """Batch ingestion (body: source, source_type, format, logs[])"""
    events = await ingest_batch(
        db,
        current_user.tenant_id,
        body.source,
        body.source_type,
        body.logs,
        body.format,
    )
    return {
        "status": "success",
        "ingested_count": len(events),
        "event_ids": [str(e.id) for e in events],
    }


@router.get("/events")
async def list_events(
    source: str | None = None,
    source_type: str | None = None,
    severity: str | None = None,
    src_ip: str | None = None,
    user: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    current_user: CurrentUser = Depends(require_permission("siem:read")),
    db: AsyncSession = Depends(get_db),
):
    """Search events (query params: source, source_type, severity, src_ip, user, start_time, end_time, limit, offset)"""
    stmt = select(SIEMEvent).where(SIEMEvent.tenant_id == current_user.tenant_id)

    if source:
        stmt = stmt.where(SIEMEvent.source == source)
    if source_type:
        stmt = stmt.where(SIEMEvent.source_type == source_type)
    if severity:
        stmt = stmt.where(SIEMEvent.severity == severity)
    if src_ip:
        stmt = stmt.where(SIEMEvent.src_ip == src_ip)
    if user:
        stmt = stmt.where(SIEMEvent.user == user)
    if start_time:
        stmt = stmt.where(SIEMEvent.event_time >= start_time)
    if end_time:
        stmt = stmt.where(SIEMEvent.event_time <= end_time)

    stmt = stmt.order_by(SIEMEvent.event_time.desc()).offset(offset).limit(limit)
    rows = (await db.execute(stmt)).scalars().all()
    return rows


@router.get("/events/{event_id}")
async def get_event(
    event_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("siem:read")),
    db: AsyncSession = Depends(get_db),
):
    """Get specific event"""
    stmt = select(SIEMEvent).where(
        SIEMEvent.id == event_id, SIEMEvent.tenant_id == current_user.tenant_id
    )
    event = (await db.execute(stmt)).scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail="SIEM Event not found")
    return event


@router.post("/correlation/rules", status_code=status.HTTP_201_CREATED)
async def create_correlation_rule(
    body: CorrelationRuleCreate,
    current_user: CurrentUser = Depends(require_permission("siem:write")),
    db: AsyncSession = Depends(get_db),
):
    """Create correlation rule"""
    rule = CorrelationRule(
        tenant_id=current_user.tenant_id,
        name=body.name,
        description=body.description,
        rule_type=body.rule_type,
        conditions=body.conditions,
        time_window_seconds=body.time_window_seconds,
        threshold=body.threshold,
        severity=body.severity,
        mitre_technique=body.mitre_technique,
        is_active=body.is_active,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return rule


@router.get("/correlation/rules")
async def list_rules(
    is_active: bool | None = None,
    current_user: CurrentUser = Depends(require_permission("siem:read")),
    db: AsyncSession = Depends(get_db),
):
    """List rules"""
    stmt = select(CorrelationRule).where(CorrelationRule.tenant_id == current_user.tenant_id)
    if is_active is not None:
        stmt = stmt.where(CorrelationRule.is_active == is_active)

    rules = (await db.execute(stmt)).scalars().all()
    if not rules:
        rules = await seed_default_rules(db, current_user.tenant_id)

    return rules


@router.get("/correlation/incidents")
async def list_correlated_incidents(
    status_filter: str | None = Query(default=None, alias="status"),
    severity: str | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    current_user: CurrentUser = Depends(require_permission("siem:read")),
    db: AsyncSession = Depends(get_db),
):
    """List correlated incidents"""
    stmt = select(CorrelatedIncident).where(
        CorrelatedIncident.tenant_id == current_user.tenant_id
    )
    if status_filter:
        stmt = stmt.where(CorrelatedIncident.status == status_filter)
    if severity:
        stmt = stmt.where(CorrelatedIncident.severity == severity)

    stmt = stmt.order_by(CorrelatedIncident.created_at.desc()).offset(offset).limit(limit)
    incidents = (await db.execute(stmt)).scalars().all()
    return incidents


@router.get("/correlation/incidents/{incident_id}")
async def get_correlated_incident(
    incident_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("siem:read")),
    db: AsyncSession = Depends(get_db),
):
    """Get specific incident"""
    stmt = select(CorrelatedIncident).where(
        CorrelatedIncident.id == incident_id,
        CorrelatedIncident.tenant_id == current_user.tenant_id,
    )
    incident = (await db.execute(stmt)).scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Correlated incident not found")
    return incident


@router.post("/correlation/incidents/{incident_id}/resolve")
async def resolve_correlated_incident(
    incident_id: uuid.UUID,
    body: IncidentResolveRequest,
    current_user: CurrentUser = Depends(require_permission("siem:write")),
    db: AsyncSession = Depends(get_db),
):
    """Resolve incident"""
    stmt = select(CorrelatedIncident).where(
        CorrelatedIncident.id == incident_id,
        CorrelatedIncident.tenant_id == current_user.tenant_id,
    )
    incident = (await db.execute(stmt)).scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Correlated incident not found")

    incident.status = body.status
    incident.resolved_at = datetime.now(UTC)
    if body.notes:
        incident.summary += f"\nResolution Notes: {body.notes}"

    await db.commit()
    await db.refresh(incident)
    return incident


@router.get("/stats")
async def get_event_stats(
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    current_user: CurrentUser = Depends(require_permission("siem:read")),
    db: AsyncSession = Depends(get_db),
):
    """Event statistics (counts by severity, source, type over time range)"""
    base_where = [SIEMEvent.tenant_id == current_user.tenant_id]
    if start_time:
        base_where.append(SIEMEvent.event_time >= start_time)
    if end_time:
        base_where.append(SIEMEvent.event_time <= end_time)

    # Total event count
    tot_stmt = select(func.count(SIEMEvent.id)).where(*base_where)
    total_events = (await db.execute(tot_stmt)).scalar() or 0

    # Counts by severity
    sev_stmt = (
        select(SIEMEvent.severity, func.count(SIEMEvent.id))
        .where(*base_where)
        .group_by(SIEMEvent.severity)
    )
    sev_counts = dict((await db.execute(sev_stmt)).all())

    # Counts by source
    src_stmt = (
        select(SIEMEvent.source, func.count(SIEMEvent.id))
        .where(*base_where)
        .group_by(SIEMEvent.source)
    )
    src_counts = dict((await db.execute(src_stmt)).all())

    # Counts by source_type
    type_stmt = (
        select(SIEMEvent.source_type, func.count(SIEMEvent.id))
        .where(*base_where)
        .group_by(SIEMEvent.source_type)
    )
    type_counts = dict((await db.execute(type_stmt)).all())

    # Counts by event_category
    cat_stmt = (
        select(SIEMEvent.event_category, func.count(SIEMEvent.id))
        .where(*base_where)
        .group_by(SIEMEvent.event_category)
    )
    cat_counts = dict((await db.execute(cat_stmt)).all())

    # Incidents stats
    inc_stmt = select(func.count(CorrelatedIncident.id)).where(
        CorrelatedIncident.tenant_id == current_user.tenant_id
    )
    total_incidents = (await db.execute(inc_stmt)).scalar() or 0

    inc_status_stmt = (
        select(CorrelatedIncident.status, func.count(CorrelatedIncident.id))
        .where(CorrelatedIncident.tenant_id == current_user.tenant_id)
        .group_by(CorrelatedIncident.status)
    )
    inc_status_counts = dict((await db.execute(inc_status_stmt)).all())

    return {
        "total_events": total_events,
        "by_severity": sev_counts,
        "by_source": src_counts,
        "by_source_type": type_counts,
        "by_category": cat_counts,
        "total_incidents": total_incidents,
        "incidents_by_status": inc_status_counts,
    }


@router.get("/search")
async def search_events(
    query: str | None = None,
    source: str | None = None,
    source_type: str | None = None,
    event_category: str | None = None,
    severity: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    user: str | None = None,
    action: str | None = None,
    result: str | None = None,
    threat_intel_match: bool | None = None,
    correlated: bool | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    current_user: CurrentUser = Depends(require_permission("siem:read")),
    db: AsyncSession = Depends(get_db),
):
    """Advanced search with multiple filters"""
    stmt = select(SIEMEvent).where(SIEMEvent.tenant_id == current_user.tenant_id)

    if source:
        stmt = stmt.where(SIEMEvent.source == source)
    if source_type:
        stmt = stmt.where(SIEMEvent.source_type == source_type)
    if event_category:
        stmt = stmt.where(SIEMEvent.event_category == event_category)
    if severity:
        stmt = stmt.where(SIEMEvent.severity == severity)
    if src_ip:
        stmt = stmt.where(SIEMEvent.src_ip == src_ip)
    if dst_ip:
        stmt = stmt.where(SIEMEvent.dst_ip == dst_ip)
    if user:
        stmt = stmt.where(SIEMEvent.user == user)
    if action:
        stmt = stmt.where(SIEMEvent.action == action)
    if result:
        stmt = stmt.where(SIEMEvent.result == result)
    if threat_intel_match is not None:
        stmt = stmt.where(SIEMEvent.threat_intel_match == threat_intel_match)
    if correlated is not None:
        stmt = stmt.where(SIEMEvent.correlated == correlated)
    if start_time:
        stmt = stmt.where(SIEMEvent.event_time >= start_time)
    if end_time:
        stmt = stmt.where(SIEMEvent.event_time <= end_time)

    if query:
        pattern = f"%{query}%"
        stmt = stmt.where(
            or_(
                SIEMEvent.source.ilike(pattern),
                SIEMEvent.user.ilike(pattern),
                SIEMEvent.action.ilike(pattern),
                SIEMEvent.src_ip.ilike(pattern),
                SIEMEvent.dst_ip.ilike(pattern),
            )
        )

    count_stmt = select(func.count()).select_from(stmt.subquery())
    total_count = (await db.execute(count_stmt)).scalar() or 0

    stmt = stmt.order_by(SIEMEvent.event_time.desc()).offset(offset).limit(limit)
    rows = (await db.execute(stmt)).scalars().all()

    return {
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "events": rows,
    }
