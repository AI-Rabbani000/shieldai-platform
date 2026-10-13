"""Routes for the compliance auto-remediation engine."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.compliance.autofix import (
    ComplianceControlStatus,
    ComplianceRemediationJob,
    auto_remediate_framework,
    execute_remediation,
    generate_remediation_plan,
    get_framework_dict,
    verify_remediation,
)
from gds_api.db import get_db
from gds_api.logging_config import get_logger
from gds_api.security import CurrentUser

logger = get_logger(__name__)

router = APIRouter(prefix="/compliance/autofix", tags=["compliance-autofix"])

class GeneratePlanRequest(BaseModel):
    framework: str
    control_id: str
    gap_description: str | None = None

class ExecuteRequest(BaseModel):
    dry_run: bool = True

class AutoRemediateFrameworkRequest(BaseModel):
    framework: str

@router.post("/generate", status_code=status.HTTP_201_CREATED)
async def generate_plan(body: GeneratePlanRequest, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict[str, Any]:
    job = await generate_remediation_plan(db=db, tenant_id=user.tenant_id, framework=body.framework, control_id=body.control_id, gap_description=body.gap_description or "")
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Control {body.control_id} not found in framework {body.framework}")
    await db.commit()
    return {"job_id": str(job.id), "framework": job.framework, "control_id": job.control_id, "status": job.status, "remediation_type": job.remediation_type, "steps": job.remediation_steps, "aws_cli_command": job.aws_cli_command, "terraform_snippet": job.terraform_snippet}

@router.post("/{job_id}/execute")
async def execute_job(job_id: uuid.UUID, body: ExecuteRequest, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict[str, Any]:
    result = await execute_remediation(db=db, job_id=job_id, dry_run=body.dry_run)
    await db.commit()
    return result

@router.post("/{job_id}/verify")
async def verify_job(job_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict[str, Any]:
    result = await verify_remediation(db=db, job_id=job_id)
    await db.commit()
    return result

@router.get("/jobs")
async def list_jobs(framework: str | None = None, status_filter: str | None = None, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> list[dict[str, Any]]:
    q = select(ComplianceRemediationJob).where(ComplianceRemediationJob.tenant_id == user.tenant_id)
    if framework:
        q = q.where(ComplianceRemediationJob.framework == framework)
    if status_filter:
        q = q.where(ComplianceRemediationJob.status == status_filter)
    q = q.order_by(ComplianceRemediationJob.created_at.desc()).limit(100)
    result = await db.execute(q)
    jobs = result.scalars().all()
    return [{"id": str(j.id), "framework": j.framework, "control_id": j.control_id, "control_name": j.control_name, "status": j.status, "progress_pct": j.progress_pct, "remediation_type": j.remediation_type, "created_at": j.created_at.isoformat() if j.created_at else None, "completed_at": j.completed_at.isoformat() if j.completed_at else None, "error_message": j.error_message} for j in jobs]

@router.get("/jobs/{job_id}")
async def get_job(job_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict[str, Any]:
    q = select(ComplianceRemediationJob).where(ComplianceRemediationJob.id == job_id, ComplianceRemediationJob.tenant_id == user.tenant_id)
    result = await db.execute(q)
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"id": str(job.id), "framework": job.framework, "control_id": job.control_id, "control_name": job.control_name, "gap_description": job.gap_description, "remediation_type": job.remediation_type, "remediation_steps": job.remediation_steps, "aws_cli_command": job.aws_cli_command, "terraform_snippet": job.terraform_snippet, "status": job.status, "progress_pct": job.progress_pct, "error_message": job.error_message, "verification_result": job.verification_result, "created_at": job.created_at.isoformat() if job.created_at else None, "completed_at": job.completed_at.isoformat() if job.completed_at else None}

@router.post("/framework/{framework}")
async def auto_remediate(framework: str, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict[str, Any]:
    result = await auto_remediate_framework(db=db, tenant_id=user.tenant_id, framework=framework, user_id=user.user_id)
    await db.commit()
    return result

@router.get("/frameworks")
async def list_frameworks() -> dict[str, Any]:
    frameworks = {}
    for fw in ["PCI-DSS", "SOC2", "ISO27001", "NIST", "GDPR", "DORA", "NIS2", "EU_AI_Act"]:
        fw_dict = get_framework_dict(fw)
        if fw_dict:
            frameworks[fw] = {"total_controls": len(fw_dict), "controls": [{"control_id": cid, "control_name": v.get("control_name", "")} for cid, v in fw_dict.items()]}
    return frameworks

@router.get("/controls/{framework}")
async def list_controls(framework: str, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> list[dict[str, Any]]:
    fw_dict = get_framework_dict(framework)
    if not fw_dict:
        raise HTTPException(status_code=404, detail=f"Framework {framework} not found")
    q = select(ComplianceControlStatus).where(ComplianceControlStatus.tenant_id == user.tenant_id, ComplianceControlStatus.framework == framework)
    result = await db.execute(q)
    statuses = {s.control_id: s for s in result.scalars().all()}
    controls = []
    for cid, cv in fw_dict.items():
        st = statuses.get(cid)
        controls.append({"control_id": cid, "control_name": cv.get("control_name", ""), "remediation_type": cv.get("remediation_type", ""), "status": st.status if st else "not_tested", "last_checked": st.last_checked.isoformat() if st and st.last_checked else None})
    return controls
