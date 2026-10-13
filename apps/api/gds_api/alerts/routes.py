"""FastAPI router for real-time alerting rules, event management, testing, and entity triggers."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.alerts.dispatch import dispatch_all
from gds_api.alerts.engine import check_entity_change
from gds_api.alerts.models import AlertEvent, AlertRule
from gds_api.db import get_db
from gds_api.logging_config import get_logger
from gds_api.security import CurrentUser, get_current_user

logger = get_logger(__name__)

router = APIRouter(prefix="/alerts", tags=["alerts"])


class AlertRuleCreate(BaseModel):
    name: str = Field(..., max_length=200)
    description: str | None = None
    entity_type: str = Field(..., max_length=100)
    condition_field: str = Field(..., max_length=200)
    condition_operator: str = Field(..., max_length=50)
    condition_value: str = Field(..., max_length=500)
    severity: str = Field(..., max_length=50)
    channels: list[Any] = Field(default_factory=list)
    cooldown_minutes: int = Field(default=30, ge=0)
    is_active: bool = True


class AlertRuleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    entity_type: str | None = None
    condition_field: str | None = None
    condition_operator: str | None = None
    condition_value: str | None = None
    severity: str | None = None
    channels: list[Any] | None = None
    cooldown_minutes: int | None = Field(default=None, ge=0)
    is_active: bool | None = None


class TestAlertRequest(BaseModel):
    channels: list[Any] = Field(..., description="List of channel descriptors or channel types")
    alert_data: dict[str, Any] | None = None


class EntityTriggerRequest(BaseModel):
    entity_type: str
    entity_id: str
    old_data: dict[str, Any] | None = None
    new_data: dict[str, Any]


@router.post("/rules", status_code=status.HTTP_201_CREATED)
async def create_rule(
    body: AlertRuleCreate,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Create a new alert rule."""
    rule = AlertRule(
        id=uuid.uuid4(),
        tenant_id=user.tenant_id,
        name=body.name,
        description=body.description,
        entity_type=body.entity_type,
        condition_field=body.condition_field,
        condition_operator=body.condition_operator,
        condition_value=body.condition_value,
        severity=body.severity,
        channels=body.channels,
        cooldown_minutes=body.cooldown_minutes,
        is_active=body.is_active,
        created_by=user.user_id,
        created_at=datetime.now(UTC),
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return {
        "id": str(rule.id),
        "tenant_id": str(rule.tenant_id),
        "name": rule.name,
        "description": rule.description,
        "entity_type": rule.entity_type,
        "condition_field": rule.condition_field,
        "condition_operator": rule.condition_operator,
        "condition_value": rule.condition_value,
        "severity": rule.severity,
        "channels": rule.channels,
        "cooldown_minutes": rule.cooldown_minutes,
        "is_active": rule.is_active,
        "last_fired": rule.last_fired.isoformat() if rule.last_fired else None,
        "fire_count": rule.fire_count,
        "created_by": str(rule.created_by),
        "created_at": rule.created_at.isoformat() if rule.created_at else None,
    }


@router.get("/rules")
async def list_rules(
    entity_type: str | None = None,
    is_active: bool | None = None,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> list[dict[str, Any]]:
    """List alert rules for the tenant with optional filters."""
    stmt = select(AlertRule).where(AlertRule.tenant_id == user.tenant_id)
    if entity_type:
        stmt = stmt.where(AlertRule.entity_type == entity_type)
    if is_active is not None:
        stmt = stmt.where(AlertRule.is_active == is_active)

    res = await db.execute(stmt)
    rules = list(res.scalars().all())
    return [
        {
            "id": str(r.id),
            "tenant_id": str(r.tenant_id),
            "name": r.name,
            "description": r.description,
            "entity_type": r.entity_type,
            "condition_field": r.condition_field,
            "condition_operator": r.condition_operator,
            "condition_value": r.condition_value,
            "severity": r.severity,
            "channels": r.channels,
            "cooldown_minutes": r.cooldown_minutes,
            "is_active": r.is_active,
            "last_fired": r.last_fired.isoformat() if r.last_fired else None,
            "fire_count": r.fire_count,
            "created_by": str(r.created_by),
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rules
    ]


@router.get("/rules/{rule_id}")
async def get_rule(
    rule_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Get a specific alert rule by ID."""
    stmt = select(AlertRule).where(AlertRule.id == rule_id, AlertRule.tenant_id == user.tenant_id)
    res = await db.execute(stmt)
    rule = res.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert rule not found")
    return {
        "id": str(rule.id),
        "tenant_id": str(rule.tenant_id),
        "name": rule.name,
        "description": rule.description,
        "entity_type": rule.entity_type,
        "condition_field": rule.condition_field,
        "condition_operator": rule.condition_operator,
        "condition_value": rule.condition_value,
        "severity": rule.severity,
        "channels": rule.channels,
        "cooldown_minutes": rule.cooldown_minutes,
        "is_active": rule.is_active,
        "last_fired": rule.last_fired.isoformat() if rule.last_fired else None,
        "fire_count": rule.fire_count,
        "created_by": str(rule.created_by),
        "created_at": rule.created_at.isoformat() if rule.created_at else None,
    }


@router.patch("/rules/{rule_id}")
async def update_rule(
    rule_id: uuid.UUID,
    body: AlertRuleUpdate,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Update an existing alert rule."""
    stmt = select(AlertRule).where(AlertRule.id == rule_id, AlertRule.tenant_id == user.tenant_id)
    res = await db.execute(stmt)
    rule = res.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert rule not found")

    update_data = body.model_dump(exclude_unset=True)
    for field, val in update_data.items():
        setattr(rule, field, val)

    await db.commit()
    await db.refresh(rule)
    return {
        "id": str(rule.id),
        "tenant_id": str(rule.tenant_id),
        "name": rule.name,
        "description": rule.description,
        "entity_type": rule.entity_type,
        "condition_field": rule.condition_field,
        "condition_operator": rule.condition_operator,
        "condition_value": rule.condition_value,
        "severity": rule.severity,
        "channels": rule.channels,
        "cooldown_minutes": rule.cooldown_minutes,
        "is_active": rule.is_active,
        "last_fired": rule.last_fired.isoformat() if rule.last_fired else None,
        "fire_count": rule.fire_count,
        "created_by": str(rule.created_by),
        "created_at": rule.created_at.isoformat() if rule.created_at else None,
    }


@router.delete("/rules/{rule_id}")
async def delete_rule(
    rule_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Delete an alert rule."""
    stmt = select(AlertRule).where(AlertRule.id == rule_id, AlertRule.tenant_id == user.tenant_id)
    res = await db.execute(stmt)
    rule = res.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert rule not found")

    await db.delete(rule)
    await db.commit()
    return {"status": "deleted", "id": str(rule_id)}


@router.get("/events")
async def list_events(
    severity: str | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> list[dict[str, Any]]:
    """List alert events with optional filters."""
    stmt = select(AlertEvent).where(AlertEvent.tenant_id == user.tenant_id)
    if severity:
        stmt = stmt.where(AlertEvent.severity == severity)
    if status_filter:
        stmt = stmt.where(AlertEvent.status == status_filter)

    stmt = stmt.order_by(AlertEvent.created_at.desc()).limit(limit).offset(offset)
    res = await db.execute(stmt)
    events = list(res.scalars().all())
    return [
        {
            "id": str(e.id),
            "tenant_id": str(e.tenant_id),
            "rule_id": str(e.rule_id),
            "rule_name": e.rule_name,
            "entity_type": e.entity_type,
            "entity_id": e.entity_id,
            "entity_title": e.entity_title,
            "severity": e.severity,
            "channels_dispatched": e.channels_dispatched,
            "delivery_results": e.delivery_results,
            "status": e.status,
            "acknowledged_by": str(e.acknowledged_by) if e.acknowledged_by else None,
            "acknowledged_at": e.acknowledged_at.isoformat() if e.acknowledged_at else None,
            "resolved_at": e.resolved_at.isoformat() if e.resolved_at else None,
            "created_at": e.created_at.isoformat() if e.created_at else None,
        }
        for e in events
    ]


@router.get("/events/{event_id}")
async def get_event(
    event_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Get a specific alert event by ID."""
    stmt = select(AlertEvent).where(AlertEvent.id == event_id, AlertEvent.tenant_id == user.tenant_id)
    res = await db.execute(stmt)
    event = res.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert event not found")
    return {
        "id": str(event.id),
        "tenant_id": str(event.tenant_id),
        "rule_id": str(event.rule_id),
        "rule_name": event.rule_name,
        "entity_type": event.entity_type,
        "entity_id": event.entity_id,
        "entity_title": event.entity_title,
        "severity": event.severity,
        "channels_dispatched": event.channels_dispatched,
        "delivery_results": event.delivery_results,
        "status": event.status,
        "acknowledged_by": str(event.acknowledged_by) if event.acknowledged_by else None,
        "acknowledged_at": event.acknowledged_at.isoformat() if event.acknowledged_at else None,
        "resolved_at": event.resolved_at.isoformat() if event.resolved_at else None,
        "created_at": event.created_at.isoformat() if event.created_at else None,
    }


@router.post("/events/{event_id}/acknowledge")
async def acknowledge_event(
    event_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Acknowledge an alert event."""
    stmt = select(AlertEvent).where(AlertEvent.id == event_id, AlertEvent.tenant_id == user.tenant_id)
    res = await db.execute(stmt)
    event = res.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert event not found")

    event.status = "acknowledged"
    event.acknowledged_by = user.user_id
    event.acknowledged_at = datetime.now(UTC)

    await db.commit()
    await db.refresh(event)
    return {
        "id": str(event.id),
        "tenant_id": str(event.tenant_id),
        "status": event.status,
        "acknowledged_by": str(event.acknowledged_by),
        "acknowledged_at": event.acknowledged_at.isoformat() if event.acknowledged_at else None,
    }


@router.post("/events/{event_id}/resolve")
async def resolve_event(
    event_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Mark an alert event as resolved."""
    stmt = select(AlertEvent).where(AlertEvent.id == event_id, AlertEvent.tenant_id == user.tenant_id)
    res = await db.execute(stmt)
    event = res.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert event not found")

    event.status = "resolved"
    event.resolved_at = datetime.now(UTC)

    await db.commit()
    await db.refresh(event)
    return {
        "id": str(event.id),
        "tenant_id": str(event.tenant_id),
        "status": event.status,
        "resolved_at": event.resolved_at.isoformat() if event.resolved_at else None,
    }


@router.post("/test")
async def test_alert(
    body: TestAlertRequest,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Send a test alert through configured channels."""
    alert_data = body.alert_data or {
        "rule_id": "test-rule-id",
        "rule_name": "Test Alert Rule",
        "entity_type": "test_entity",
        "entity_id": "test-001",
        "entity_title": "Test Real-time Alerting Trigger",
        "severity": "info",
        "condition_field": "test_status",
        "condition_operator": "eq",
        "condition_value": "triggered",
        "timestamp": datetime.now(UTC).isoformat(),
    }
    dispatch_results = await dispatch_all(body.channels, alert_data)
    return {
        "status": "completed",
        "channels_tested": len(body.channels),
        "dispatch_results": dispatch_results,
    }


@router.post("/entity-trigger")
async def entity_trigger(
    body: EntityTriggerRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Internal trigger to check entity state changes and fire matching alert rules."""
    events = await check_entity_change(
        db=db,
        tenant_id=user.tenant_id,
        entity_type=body.entity_type,
        entity_id=body.entity_id,
        old_data=body.old_data,
        new_data=body.new_data,
    )
    return {
        "status": "processed",
        "fired_count": len(events),
        "event_ids": [str(e.id) for e in events],
    }
