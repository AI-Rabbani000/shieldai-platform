"""GDS OS Data Residency — Routes."""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.data_residency.engine import (
    DataMovementLog,
    DataResidencyRule,
    DataResidencyZone,
    REGULATORY_PRESETS,
    create_rule_from_preset,
    create_zone,
    evaluate_data_movement,
    get_residency_summary,
)
from gds_api.db import get_db
from gds_api.security import CurrentUser

router = APIRouter(prefix="/data-residency", tags=["data-residency"])


class CreateZoneRequest(BaseModel):
    zone_name: str
    region: str
    country: str
    data_classification: str = "internal"
    storage_endpoint: str | None = None
    cross_border_allowed: bool = False
    regulatory_basis: str | None = None
    retention_days: int = 365
    is_primary: bool = False


class CreateRuleFromPresetRequest(BaseModel):
    regulation: str
    data_type: str | None = None


class EvaluateMovementRequest(BaseModel):
    source_zone: str
    dest_zone: str
    data_type: str
    data_classification: str = "internal"
    volume_mb: int = 0
    entity_type: str | None = None
    entity_id: str | None = None


@router.post("/zones", status_code=status.HTTP_201_CREATED)
async def create_data_zone(body: CreateZoneRequest, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    z = await create_zone(db, user.tenant_id, body.zone_name, body.region, body.country,
                          body.data_classification, body.storage_endpoint,
                          body.cross_border_allowed, body.regulatory_basis,
                          body.retention_days, body.is_primary)
    await db.commit()
    return {"id": str(z.id), "zone_name": z.zone_name, "region": z.region, "is_primary": z.is_primary}


@router.get("/zones")
async def list_zones(db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> list[dict]:
    q = select(DataResidencyZone).where(DataResidencyZone.tenant_id == user.tenant_id)
    result = await db.execute(q)
    return [
        {"id": str(z.id), "zone_name": z.zone_name, "region": z.region, "country": z.country,
         "data_classification": z.data_classification, "encryption_required": z.encryption_required,
         "cross_border_allowed": z.cross_border_allowed, "retention_days": z.retention_days,
         "is_primary": z.is_primary, "is_active": z.is_active,
         "regulatory_basis": z.regulatory_basis}
        for z in result.scalars().all()
    ]


@router.get("/zones/{zone_id}")
async def get_zone(zone_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    q = select(DataResidencyZone).where(DataResidencyZone.id == zone_id, DataResidencyZone.tenant_id == user.tenant_id)
    z = (await db.execute(q)).scalar_one_or_none()
    if not z:
        raise HTTPException(status_code=404, detail="Zone not found")
    return {"id": str(z.id), "zone_name": z.zone_name, "region": z.region, "country": z.country,
            "data_classification": z.data_classification, "storage_endpoint": z.storage_endpoint,
            "encryption_required": z.encryption_required, "cross_border_allowed": z.cross_border_allowed,
            "allowed_destinations": z.allowed_destinations, "retention_days": z.retention_days,
            "regulatory_basis": z.regulatory_basis, "is_primary": z.is_primary, "is_active": z.is_active}


@router.post("/rules/from-preset", status_code=status.HTTP_201_CREATED)
async def create_rules_preset(body: CreateRuleFromPresetRequest, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    rules = await create_rule_from_preset(db, user.tenant_id, body.regulation, body.data_type)
    await db.commit()
    return {"created": len(rules), "rules": [{"id": str(r.id), "name": r.rule_name} for r in rules]}


@router.get("/rules")
async def list_rules(db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> list[dict]:
    q = select(DataResidencyRule).where(DataResidencyRule.tenant_id == user.tenant_id)
    result = await db.execute(q)
    return [
        {"id": str(r.id), "rule_name": r.rule_name, "data_type": r.data_type,
         "required_zone": r.required_zone, "blocked_zones": r.blocked_zones,
         "encryption_at_rest": r.encryption_at_rest, "encryption_in_transit": r.encryption_in_transit,
         "anonymization_required": r.anonymization_required, "retention_days": r.retention_days,
         "regulatory_basis": r.regulatory_basis, "violation_action": r.violation_action,
         "is_active": r.is_active}
        for r in result.scalars().all()
    ]


@router.post("/evaluate")
async def evaluate_movement(body: EvaluateMovementRequest, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    result = await evaluate_data_movement(db, user.tenant_id, body.source_zone, body.dest_zone,
                                           body.data_type, body.data_classification,
                                           body.volume_mb, body.entity_type, body.entity_id)
    await db.commit()
    return result


@router.get("/movements")
async def list_movements(data_type: str | None = None, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> list[dict]:
    q = select(DataMovementLog).where(DataMovementLog.tenant_id == user.tenant_id)
    if data_type:
        q = q.where(DataMovementLog.data_type == data_type)
    q = q.order_by(DataMovementLog.occurred_at.desc()).limit(100)
    result = await db.execute(q)
    return [
        {"id": str(l.id), "source_zone": l.source_zone, "dest_zone": l.dest_zone,
         "data_type": l.data_type, "decision": l.decision, "reason": l.reason,
         "rule_evaluated": l.rule_evaluated, "volume_mb": l.volume_mb,
         "occurred_at": l.occurred_at.isoformat() if l.occurred_at else None}
        for l in result.scalars().all()
    ]


@router.get("/summary")
async def residency_summary(db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    return await get_residency_summary(db, user.tenant_id)


@router.get("/presets")
async def list_presets() -> dict[str, Any]:
    return {name: {"description": p["description"], "required_zone": p["required_zone"],
                   "data_types": p["data_types"], "retention_days": p["retention_days"],
                   "regulatory_basis": p["regulatory_basis"]}
            for name, p in REGULATORY_PRESETS.items()}
