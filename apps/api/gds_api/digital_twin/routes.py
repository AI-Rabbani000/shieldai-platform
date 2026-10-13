"""GDS OS W13 — Digital Twin API Routes."""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.digital_twin.engine import (
    CHAOS_TYPES,
    DigitalTwinEnvironment, TwinAsset, ChaosExperiment,
    create_twin_environment, mirror_assets, run_chaos_experiment,
    measure_resilience, assess_blast_radius, generate_resilience_report,
)
from gds_api.db import get_db
from gds_api.security import CurrentUser

router = APIRouter(prefix="/digital-twin", tags=["digital-twin"])


class CreateEnvRequest(BaseModel):
    name: str
    description: str = ""
    twin_type: str = "full"
    isolation_level: str = "isolated"


class MirrorAssetsRequest(BaseModel):
    assets: list[dict[str, Any]]


class ChaosRequest(BaseModel):
    chaos_type: str
    name: str
    hypothesis: str = ""
    target_asset: str | None = None


@router.post("/environments")
async def create_env(
    req: CreateEnvRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    return await create_twin_environment(db, user.tenant_id, req.name, req.description, req.twin_type, req.isolation_level)


@router.get("/environments")
async def list_envs(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
    limit: int = 20,
) -> dict[str, Any]:
    stmt = (
        select(DigitalTwinEnvironment)
        .where(DigitalTwinEnvironment.tenant_id == user.tenant_id)
        .order_by(DigitalTwinEnvironment.created_at.desc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    envs = result.scalars().all()
    return {
        "total": len(envs),
        "environments": [
            {"id": str(e.id), "name": e.name, "description": e.description,
             "type": e.twin_type, "status": e.status,
             "isolation": e.isolation_level, "assets_mirrored": e.assets_mirrored,
             "created_at": e.created_at.isoformat() if e.created_at else None}
            for e in envs
        ],
    }


@router.get("/environments/{env_id}")
async def get_env(
    env_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    stmt = select(DigitalTwinEnvironment).where(
        DigitalTwinEnvironment.id == env_id,
        DigitalTwinEnvironment.tenant_id == user.tenant_id,
    )
    env = (await db.execute(stmt)).scalar_one_or_none()
    if not env:
        raise HTTPException(status_code=404, detail="Environment not found")

    asset_stmt = select(TwinAsset).where(TwinAsset.twin_env_id == env_id)
    assets = (await db.execute(asset_stmt)).scalars().all()

    return {
        "id": str(env.id), "name": env.name, "description": env.description,
        "type": env.twin_type, "status": env.status,
        "isolation": env.isolation_level, "assets_mirrored": env.assets_mirrored,
        "created_at": env.created_at.isoformat() if env.created_at else None,
        "assets": [
            {"id": str(a.id), "name": a.asset_name, "type": a.asset_type,
             "risk_score": a.risk_score, "is_critical": a.is_critical,
             "is_internet_facing": a.is_internet_facing,
             "vuln_count": a.vulnerability_count, "dependencies": a.dependencies}
            for a in assets
        ],
    }


@router.post("/environments/{env_id}/mirror")
async def mirror_prod_assets(
    env_id: uuid.UUID,
    req: MirrorAssetsRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    if not req.assets:
        raise HTTPException(status_code=400, detail="No assets provided")
    return await mirror_assets(db, user.tenant_id, env_id, req.assets)


@router.post("/environments/{env_id}/chaos")
async def trigger_chaos(
    env_id: uuid.UUID,
    req: ChaosRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    try:
        result = await run_chaos_experiment(db, user.tenant_id, env_id, req.chaos_type, req.name, req.hypothesis, req.target_asset)
        await db.commit()
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/environments/{env_id}/resilience")
async def get_resilience(
    env_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    return await measure_resilience(db, user.tenant_id, env_id)


@router.post("/environments/{env_id}/resilience-report")
async def get_resilience_report(
    env_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    return await generate_resilience_report(db, user.tenant_id, env_id)


@router.get("/experiments")
async def list_experiments(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
    limit: int = 20,
) -> dict[str, Any]:
    stmt = (
        select(ChaosExperiment)
        .where(ChaosExperiment.tenant_id == user.tenant_id)
        .order_by(ChaosExperiment.started_at.desc().nullslast())
        .limit(limit)
    )
    result = await db.execute(stmt)
    experiments = result.scalars().all()
    return {
        "total": len(experiments),
        "experiments": [
            {"id": str(e.id), "name": e.name, "chaos_type": e.chaos_type,
             "status": e.status, "hypothesis_confirmed": e.hypothesis_confirmed,
             "service_degraded": e.service_degraded,
             "recovery_time_s": e.recovery_time_seconds,
             "rto_met": e.rto_met, "blast_radius": e.blast_radius,
             "started_at": e.started_at.isoformat() if e.started_at else None,
             "completed_at": e.completed_at.isoformat() if e.completed_at else None}
            for e in experiments
        ],
    }


@router.get("/experiments/{exp_id}")
async def get_experiment(
    exp_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    stmt = select(ChaosExperiment).where(
        ChaosExperiment.id == exp_id,
        ChaosExperiment.tenant_id == user.tenant_id,
    )
    exp = (await db.execute(stmt)).scalar_one_or_none()
    if not exp:
        raise HTTPException(status_code=404, detail="Experiment not found")
    return {
        "id": str(exp.id), "name": exp.name, "chaos_type": exp.chaos_type,
        "hypothesis": exp.hypothesis, "target_asset": exp.target_asset,
        "blast_radius": exp.blast_radius, "status": exp.status,
        "hypothesis_confirmed": exp.hypothesis_confirmed,
        "service_degraded": exp.service_degraded,
        "recovery_time_s": exp.recovery_time_seconds,
        "rto_met": exp.rto_met,
        "steady_state_before": exp.steady_state_before,
        "steady_state_after": exp.steady_state_after,
        "results": exp.results,
        "started_at": exp.started_at.isoformat() if exp.started_at else None,
        "completed_at": exp.completed_at.isoformat() if exp.completed_at else None,
    }


@router.get("/chaos-types")
async def list_chaos_types() -> dict[str, Any]:
    """List available chaos experiment types."""
    return {"total": len(CHAOS_TYPES), "types": CHAOS_TYPES}
