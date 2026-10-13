"""Routes for the GDS OS Evidence chain-of-custody engine."""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.compliance.evidence import (
    ChainOfCustody,
    ComplianceEvidence,
    ComplianceGap,
    LegalHold,
    auto_collect_from_findings,
    collect_evidence,
    generate_evidence_package,
    get_chain_of_custody,
    identify_gaps,
    place_legal_hold,
    release_legal_hold,
    transfer_evidence,
    verify_evidence,
)
from gds_api.db import get_db
from gds_api.security import CurrentUser

router = APIRouter(prefix="/compliance/evidence", tags=["compliance-evidence"])


class CollectRequest(BaseModel):
    framework: str
    control_id: str
    control_name: str
    evidence_type: str
    title: str
    description: str | None = None
    content: str | dict
    source_system: str = "GDS OS"
    source_entity_type: str | None = None
    source_entity_id: str | None = None


class TransferRequest(BaseModel):
    to_user_id: str
    reason: str


class LegalHoldRequest(BaseModel):
    title: str
    description: str | None = None
    legal_matter: str | None = None
    evidence_ids: list[str]


class ReleaseHoldRequest(BaseModel):
    reason: str


@router.post("/collect", status_code=status.HTTP_201_CREATED)
async def collect(body: CollectRequest, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    ev = await collect_evidence(
        db=db, tenant_id=user.tenant_id, user_id=user.user_id,
        framework=body.framework, control_id=body.control_id, control_name=body.control_name,
        evidence_type=body.evidence_type, title=body.title, description=body.description,
        content=body.content, source_system=body.source_system,
        source_entity_type=body.source_entity_type, source_entity_id=body.source_entity_id,
    )
    await db.commit()
    return {"id": str(ev.id), "content_hash": ev.content_hash, "status": "collected"}


@router.get("")
async def list_evidence(framework: str | None = None, control_id: str | None = None, status_filter: str | None = None, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> list[dict]:
    q = select(ComplianceEvidence).where(ComplianceEvidence.tenant_id == user.tenant_id)
    if framework:
        q = q.where(ComplianceEvidence.framework == framework)
    if control_id:
        q = q.where(ComplianceEvidence.control_id == control_id)
    if status_filter:
        q = q.where(ComplianceEvidence.status == status_filter)
    q = q.order_by(ComplianceEvidence.collected_at.desc()).limit(100)
    result = await db.execute(q)
    return [
        {"id": str(e.id), "framework": e.framework, "control_id": e.control_id, "control_name": e.control_name,
         "evidence_type": e.evidence_type, "title": e.title, "content_hash": e.content_hash,
         "is_valid": e.is_valid, "status": e.status, "source_system": e.source_system,
         "collected_at": e.collected_at.isoformat() if e.collected_at else None}
        for e in result.scalars().all()
    ]


@router.get("/{evidence_id}")
async def get_evidence(evidence_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    q = select(ComplianceEvidence).where(ComplianceEvidence.id == evidence_id, ComplianceEvidence.tenant_id == user.tenant_id)
    e = (await db.execute(q)).scalar_one_or_none()
    if not e:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return {"id": str(e.id), "framework": e.framework, "control_id": e.control_id, "control_name": e.control_name,
            "evidence_type": e.evidence_type, "title": e.title, "description": e.description,
            "content_hash": e.content_hash, "content_preview": e.content_preview,
            "source_system": e.source_system, "source_entity_type": e.source_entity_type,
            "source_entity_id": e.source_entity_id, "is_valid": e.is_valid, "status": e.status,
            "collected_at": e.collected_at.isoformat() if e.collected_at else None,
            "valid_until": e.valid_until.isoformat() if e.valid_until else None}


@router.post("/{evidence_id}/verify")
async def verify(evidence_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    result = await verify_evidence(db, user.tenant_id, evidence_id, user.user_id)
    await db.commit()
    return result


@router.get("/{evidence_id}/chain")
async def get_chain(evidence_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> list[dict]:
    return await get_chain_of_custody(db, user.tenant_id, evidence_id)


@router.post("/{evidence_id}/transfer")
async def transfer(evidence_id: uuid.UUID, body: TransferRequest, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    chain = await transfer_evidence(db, user.tenant_id, evidence_id, user.user_id, uuid.UUID(body.to_user_id), body.reason)
    await db.commit()
    return {"id": str(chain.id), "action": "transferred"}


@router.post("/legal-hold", status_code=status.HTTP_201_CREATED)
async def create_legal_hold(body: LegalHoldRequest, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    hold = await place_legal_hold(db, user.tenant_id, [uuid.UUID(eid) for eid in body.evidence_ids], user.user_id, body.title, body.description, body.legal_matter)
    await db.commit()
    return {"id": str(hold.id), "status": "active", "evidence_count": len(hold.evidence_ids)}


@router.post("/legal-hold/{hold_id}/release")
async def release_hold(hold_id: uuid.UUID, body: ReleaseHoldRequest, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    hold = await release_legal_hold(db, user.tenant_id, hold_id, user.user_id, body.reason)
    await db.commit()
    return {"id": str(hold.id), "status": "released"}


@router.get("/legal-holds")
async def list_legal_holds(db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> list[dict]:
    q = select(LegalHold).where(LegalHold.tenant_id == user.tenant_id).order_by(LegalHold.issued_at.desc())
    result = await db.execute(q)
    return [
        {"id": str(h.id), "title": h.title, "legal_matter": h.legal_matter,
         "evidence_count": len(h.evidence_ids), "status": h.status,
         "issued_at": h.issued_at.isoformat() if h.issued_at else None,
         "released_at": h.released_at.isoformat() if h.released_at else None}
        for h in result.scalars().all()
    ]


@router.post("/auto-collect")
async def auto_collect(db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    result = await auto_collect_from_findings(db, user.tenant_id, user.user_id)
    await db.commit()
    return result


@router.get("/gaps/{framework}")
async def gaps(framework: str, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> list[dict]:
    gap_list = await identify_gaps(db, user.tenant_id, framework)
    await db.commit()
    return [
        {"id": str(g.id), "control_id": g.control_id, "control_name": g.control_name,
         "gap_type": g.gap_type, "severity": g.severity, "description": g.description, "status": g.status}
        for g in gap_list
    ]


@router.post("/package/{framework}")
async def generate_package(framework: str, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    return await generate_evidence_package(db, user.tenant_id, framework)
