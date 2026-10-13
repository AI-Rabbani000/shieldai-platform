"""GDS OS W10 — Adversary Simulation API Routes."""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.redteam_sim.engine import (
    ADVERSARY_PROFILES, MITRE_TECHNIQUES,
    AdversaryProfile, SimulationCampaign, SimulationStep,
    create_campaign, run_campaign,
)
from gds_api.db import get_db
from gds_api.security import CurrentUser

router = APIRouter(prefix="/redteam", tags=["redteam"])


class CreateCampaignRequest(BaseModel):
    name: str
    adversary_profile: str  # e.g. "APT29 (Cozy Bear)"


@router.get("/profiles")
async def list_profiles() -> dict[str, Any]:
    """List available adversary profiles."""
    return {
        "total": len(ADVERSARY_PROFILES),
        "profiles": [
            {"name": p["name"], "description": p["description"], "sophistication": p["sophistication"],
             "threat_actor": p["threat_actor_ref"], "tactics": p["tactics"], "techniques": p["techniques"]}
            for p in ADVERSARY_PROFILES
        ],
    }


@router.get("/profiles/{profile_name}")
async def get_profile(profile_name: str) -> dict[str, Any]:
    """Get adversary profile details with techniques."""
    profile = next((p for p in ADVERSARY_PROFILES if p["name"] == profile_name), None)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    tech_details = []
    for tech_id in profile["techniques"]:
        tech = next((t for t in MITRE_TECHNIQUES if t["id"] == tech_id), None)
        if tech:
            tech_details.append(tech)
    return {**profile, "technique_details": tech_details}


@router.post("/campaigns")
async def create_sim_campaign(
    req: CreateCampaignRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    """Create a new simulation campaign."""
    return await create_campaign(db, user.tenant_id, req.name, req.adversary_profile)


@router.get("/campaigns")
async def list_campaigns(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
    limit: int = 20,
) -> dict[str, Any]:
    """List all simulation campaigns."""
    stmt = (
        select(SimulationCampaign)
        .where(SimulationCampaign.tenant_id == user.tenant_id)
        .order_by(SimulationCampaign.started_at.desc().nullslast())
        .limit(limit)
    )
    result = await db.execute(stmt)
    campaigns = result.scalars().all()
    return {
        "total": len(campaigns),
        "campaigns": [
            {"id": str(c.id), "name": c.name, "adversary": c.adversary_name,
             "status": c.status, "total_techniques": c.total_techniques,
             "detected": c.detected, "prevented": c.prevented, "missed": c.missed,
             "detection_rate": c.detection_rate, "prevention_rate": c.prevention_rate,
             "coverage_pct": c.coverage_pct,
             "started_at": c.started_at.isoformat() if c.started_at else None,
             "completed_at": c.completed_at.isoformat() if c.completed_at else None}
            for c in campaigns
        ],
    }


@router.get("/campaigns/{campaign_id}")
async def get_campaign(
    campaign_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    """Get campaign with all steps."""
    stmt = select(SimulationCampaign).where(
        SimulationCampaign.id == campaign_id,
        SimulationCampaign.tenant_id == user.tenant_id,
    )
    campaign = (await db.execute(stmt)).scalar_one_or_none()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    step_stmt = select(SimulationStep).where(
        SimulationStep.campaign_id == campaign_id,
    ).order_by(SimulationStep.step_number)
    steps = (await db.execute(step_stmt)).scalars().all()

    return {
        "id": str(campaign.id), "name": campaign.name, "adversary": campaign.adversary_name,
        "status": campaign.status, "total_techniques": campaign.total_techniques,
        "detected": campaign.detected, "prevented": campaign.prevented, "missed": campaign.missed,
        "detection_rate": campaign.detection_rate, "prevention_rate": campaign.prevention_rate,
        "coverage_pct": campaign.coverage_pct,
        "started_at": campaign.started_at.isoformat() if campaign.started_at else None,
        "completed_at": campaign.completed_at.isoformat() if campaign.completed_at else None,
        "steps": [
            {"step": s.step_number, "technique": s.mitre_technique, "name": s.technique_name,
             "tactic": s.mitre_tactic, "atomic_test": s.atomic_test,
             "outcome": s.outcome, "detected": s.actual_detected, "prevented": s.actual_prevented,
             "response_time_s": s.response_time_seconds}
            for s in steps
        ],
    }


@router.post("/campaigns/{campaign_id}/run")
async def run_sim_campaign(
    campaign_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    """Execute a simulation campaign."""
    try:
        result = await run_campaign(db, campaign_id, user.tenant_id)
        await db.commit()
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/campaigns/{campaign_id}/report")
async def get_campaign_report(
    campaign_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    """Generate final report for a completed campaign."""
    stmt = select(SimulationCampaign).where(
        SimulationCampaign.id == campaign_id,
        SimulationCampaign.tenant_id == user.tenant_id,
    )
    campaign = (await db.execute(stmt)).scalar_one_or_none()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if campaign.status != "completed":
        raise HTTPException(status_code=400, detail="Campaign not yet completed")
    return {
        "campaign_id": str(campaign.id), "name": campaign.name,
        "adversary": campaign.adversary_name,
        "report": campaign.report,
    }


@router.get("/techniques")
async def list_techniques() -> dict[str, Any]:
    """List all MITRE techniques in catalog."""
    return {
        "total": len(MITRE_TECHNIQUES),
        "techniques": MITRE_TECHNIQUES,
    }


@router.get("/stats")
async def get_stats(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    """Overall simulation statistics."""
    stmt = select(SimulationCampaign).where(SimulationCampaign.tenant_id == user.tenant_id)
    campaigns = (await db.execute(stmt)).scalars().all()
    completed = [c for c in campaigns if c.status == "completed"]
    return {
        "total_campaigns": len(campaigns),
        "completed": len(completed),
        "avg_detection_rate": round(sum(c.detection_rate for c in completed) / max(len(completed), 1), 1),
        "avg_prevention_rate": round(sum(c.prevention_rate for c in completed) / max(len(completed), 1), 1),
        "avg_coverage": round(sum(c.coverage_pct for c in completed) / max(len(completed), 1), 1),
        "total_techniques_tested": sum(c.total_techniques for c in campaigns),
        "total_detected": sum(c.detected for c in campaigns),
        "total_missed": sum(c.missed for c in campaigns),
        "available_profiles": len(ADVERSARY_PROFILES),
        "available_techniques": len(MITRE_TECHNIQUES),
    }
