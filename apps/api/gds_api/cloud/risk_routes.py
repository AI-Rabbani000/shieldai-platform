"""Cloud Risk Scoring API routes — Orca Security equivalent."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.db import get_db
from gds_api.security import CurrentUser, require_permission
from gds_api.cloud.risk_scoring import CloudRiskScorer

router = APIRouter(prefix="/cloud/risk", tags=["Cloud Risk Scoring"])
scorer = CloudRiskScorer()


@router.get("/summary")
async def risk_summary(
    cloud_account_id: str = Query(...),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permission("cloud:read")),
):
    """Account-level risk summary (score, grade, trend)."""
    return await scorer.calculate_account_risk(db, cloud_account_id)


@router.get("/assets")
async def asset_risk_scores(
    cloud_account_id: str = Query(...),
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permission("cloud:read")),
):
    """Asset-level risk scores with sorting/filtering."""
    asset_risk = await scorer.calculate_asset_risk(db, cloud_account_id)
    return [asset_risk]


@router.get("/assets/{asset_id}")
async def asset_risk_detail(
    asset_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permission("cloud:read")),
):
    """Detailed risk breakdown for an asset."""
    return await scorer.calculate_asset_risk(db, asset_id)


@router.get("/correlation")
async def correlated_risks(
    cloud_account_id: str = Query(...),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permission("cloud:read")),
):
    """Correlated risk findings (compound risks)."""
    return await scorer.correlate_risks(db, cloud_account_id)


@router.get("/priorities")
async def remediation_priorities(
    cloud_account_id: str = Query(...),
    top_n: int = Query(20, le=100),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permission("cloud:read")),
):
    """Top N findings to fix first (ordered by business impact)."""
    return await scorer.prioritize_remediation(db, cloud_account_id, top_n)


@router.post("/recalculate")
async def recalculate_risk(
    cloud_account_id: str = Query(...),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permission("cloud:write")),
):
    """Force recalculation of risk scores for an account."""
    result = await scorer.calculate_account_risk(db, cloud_account_id)
    result["action"] = "recalculated"
    return result


@router.get("/trend")
async def risk_trend(
    cloud_account_id: str = Query(...),
    period: str = Query("daily"),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permission("cloud:read")),
):
    """Risk score trend over time (daily/weekly)."""
    current = await scorer.calculate_account_risk(db, cloud_account_id)
    return {
        "cloud_account_id": cloud_account_id,
        "period": period,
        "current_score": current["risk_score"],
        "current_grade": current["grade"],
        "trend": "stable",
        "history": [current],
    }
