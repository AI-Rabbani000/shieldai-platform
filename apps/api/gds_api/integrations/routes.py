"""GDS OS IDE/CI-CD Integration — Routes."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.db import get_db
from gds_api.integrations.engine import (
    evaluate_gate,
    generate_github_actions_yaml,
    generate_gitlab_ci_yaml,
    get_pipeline_posture,
    process_gate_result,
    register_pipeline,
)
from gds_api.integrations.models import CIGateResult, CIPipeline, PipelineScan
from gds_api.security import CurrentUser

router = APIRouter(prefix="/ci-cd", tags=["ci-cd"])


class RegisterPipelineRequest(BaseModel):
    name: str
    platform: str
    repo_name: str
    repo_url: str | None = None
    branch: str = "main"
    config: dict | None = None


class GateResultRequest(BaseModel):
    pipeline_id: str
    run_id: str
    commit_sha: str
    branch: str = "main"
    gate_type: str
    findings: dict[str, int]
    gate_level: str = "standard"
    findings_detail: list | None = None
    duration_seconds: int = 0
    triggered_by: str = "ci_system"


class GenerateConfigRequest(BaseModel):
    pipeline_id: str
    gate_level: str = "standard"


@router.post("/pipelines", status_code=status.HTTP_201_CREATED)
async def create_pipeline(body: RegisterPipelineRequest, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    p = await register_pipeline(db, user.tenant_id, body.name, body.platform, body.repo_name, body.repo_url, body.branch, body.config)
    await db.commit()
    return {"id": str(p.id), "name": p.name, "security_score": p.security_score}


@router.get("/pipelines")
async def list_pipelines(db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> list[dict]:
    q = select(CIPipeline).where(CIPipeline.tenant_id == user.tenant_id).order_by(CIPipeline.created_at.desc())
    result = await db.execute(q)
    return [
        {"id": str(p.id), "name": p.name, "platform": p.platform, "repo_name": p.repo_name,
         "branch": p.branch, "security_score": p.security_score, "risk_score": p.risk_score,
         "has_sast": p.has_sast, "has_sca": p.has_sca, "has_secret_scan": p.has_secret_scan,
         "has_container_scan": p.has_container_scan, "has_iac_scan": p.has_iac_scan,
         "has_dast": p.has_dast, "has_sbom": p.has_sbom, "has_signing": p.has_signing,
         "has_policy_gate": p.has_policy_gate, "is_active": p.is_active,
         "last_run": p.last_run.isoformat() if p.last_run else None, "last_run_status": p.last_run_status}
        for p in result.scalars().all()
    ]


@router.get("/pipelines/{pipeline_id}")
async def get_pipeline(pipeline_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    return await get_pipeline_posture(db, user.tenant_id, pipeline_id)


@router.post("/gate-results", status_code=status.HTTP_201_CREATED)
async def submit_gate_result(body: GateResultRequest, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    result = await process_gate_result(
        db, user.tenant_id, uuid.UUID(body.pipeline_id), body.run_id, body.commit_sha,
        body.branch, body.gate_type, body.findings, body.gate_level,
        body.findings_detail, body.duration_seconds, body.triggered_by,
    )
    await db.commit()
    return {"id": str(result.id), "gate_decision": result.gate_decision, "block_reason": result.block_reason}


@router.get("/gate-results")
async def list_gate_results(pipeline_id: uuid.UUID | None = None, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> list[dict]:
    q = select(CIGateResult).where(CIGateResult.tenant_id == user.tenant_id)
    if pipeline_id:
        q = q.where(CIGateResult.pipeline_id == pipeline_id)
    q = q.order_by(CIGateResult.created_at.desc()).limit(50)
    result = await db.execute(q)
    return [
        {"id": str(g.id), "pipeline_id": str(g.pipeline_id), "run_id": g.run_id,
         "commit_sha": g.commit_sha[:8], "gate_type": g.gate_type,
         "gate_decision": g.gate_decision, "critical": g.critical_count,
         "high": g.high_count, "medium": g.medium_count, "total": g.total_findings,
         "block_reason": g.block_reason, "created_at": g.created_at.isoformat() if g.created_at else None}
        for g in result.scalars().all()
    ]


@router.post("/generate-config")
async def generate_config(body: GenerateConfigRequest, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    q = select(CIPipeline).where(CIPipeline.id == uuid.UUID(body.pipeline_id), CIPipeline.tenant_id == user.tenant_id)
    pipeline = (await db.execute(q)).scalar_one_or_none()
    if not pipeline:
        raise HTTPException(status_code=404, detail="Pipeline not found")
    if pipeline.platform == "github_actions":
        yaml = await generate_github_actions_yaml(pipeline, body.gate_level)
    elif pipeline.platform == "gitlab_ci":
        yaml = await generate_gitlab_ci_yaml(pipeline, body.gate_level)
    else:
        return {"error": f"Config generation not supported for {pipeline.platform}"}
    return {"platform": pipeline.platform, "config": yaml}


@router.get("/platforms")
async def list_platforms() -> dict[str, Any]:
    from gds_api.integrations.engine import PLATFORM_CAPABILITIES
    return {platform: {"supported_checks": list(checks.keys()), "tools": checks} for platform, checks in PLATFORM_CAPABILITIES.items()}


@router.post("/evaluate-gate")
async def evaluate(body: GateResultRequest) -> dict:
    """Evaluate gate thresholds without persisting."""
    from gds_api.integrations.engine import GATE_THRESHOLDS
    decision = evaluate_gate(body.findings, body.gate_level)
    return {"gate_level": body.gate_level, "thresholds": GATE_THRESHOLDS.get(body.gate_level, {}), **decision}
