"""Routes for the GDS OS Auto-fix PR generation engine."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.autofix.engine import (
    CWE_FIX_TEMPLATES,
    AutoFixJob,
    process_autofix_job,
)
from gds_api.db import get_db
from gds_api.logging_config import get_logger
from gds_api.security import CurrentUser

logger = get_logger(__name__)

router = APIRouter(prefix="/autofix", tags=["autofix"])


class GenerateFixRequest(BaseModel):
    finding_id: str
    repo_name: str
    repo_url: str | None = None
    file_path: str = ""
    finding_title: str = ""
    cwe_id: str = ""
    fix_type: str = "code_fix"
    package_name: str = ""
    current_version: str = ""
    fixed_version: str = ""
    ecosystem: str = "npm"
    secret_type: str = ""
    line_content: str = ""
    service: str = ""
    remediation: str = ""


class CreatePRRequest(BaseModel):
    github_token: str
    repo_owner: str = ""
    repo_name: str = ""


class BatchFixRequest(BaseModel):
    findings: list[dict[str, Any]]


@router.post("/generate", status_code=status.HTTP_201_CREATED)
async def generate_fix(
    body: GenerateFixRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    job = AutoFixJob(
        tenant_id=user.tenant_id,
        finding_id=body.finding_id,
        repo_name=body.repo_name,
        repo_url=body.repo_url,
        file_path=body.file_path,
        fix_type=body.fix_type,
        status="pending",
        created_by=user.user_id,
    )
    db.add(job)
    await db.flush()

    finding_data = body.model_dump()
    result = await process_autofix_job(db, job.id, finding_data)
    await db.commit()
    return result


@router.post("/{job_id}/create-pr")
async def create_pr(
    job_id: uuid.UUID,
    body: CreatePRRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    q = select(AutoFixJob).where(
        AutoFixJob.id == job_id,
        AutoFixJob.tenant_id == user.tenant_id,
    )
    result = await db.execute(q)
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if not job.repo_url:
        raise HTTPException(status_code=400, detail="No repo URL on this job")

    parts = job.repo_url.rstrip("/").split("/")
    repo_owner = body.repo_owner or (parts[-2] if len(parts) >= 2 else "")
    repo_name = body.repo_name or (parts[-1] if parts else job.repo_name)

    finding_data = {
        "cwe_id": "",
        "fix_type": job.fix_type,
        "title": job.fix_description or "Security fix",
    }
    result = await process_autofix_job(db, job.id, finding_data, body.github_token)
    await db.commit()
    return result


@router.get("/jobs")
async def list_jobs(
    repo_name: str | None = None,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> list[dict[str, Any]]:
    q = select(AutoFixJob).where(AutoFixJob.tenant_id == user.tenant_id)
    if repo_name:
        q = q.where(AutoFixJob.repo_name == repo_name)
    q = q.order_by(AutoFixJob.created_at.desc()).limit(100)
    result = await db.execute(q)
    jobs = result.scalars().all()
    return [
        {
            "id": str(j.id),
            "finding_id": j.finding_id,
            "repo_name": j.repo_name,
            "file_path": j.file_path,
            "fix_type": j.fix_type,
            "status": j.status,
            "pr_url": j.pr_url,
            "pr_number": j.pr_number,
            "fix_description": j.fix_description,
            "created_at": j.created_at.isoformat() if j.created_at else None,
        }
        for j in jobs
    ]


@router.get("/jobs/{job_id}")
async def get_job(
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    q = select(AutoFixJob).where(
        AutoFixJob.id == job_id,
        AutoFixJob.tenant_id == user.tenant_id,
    )
    result = await db.execute(q)
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {
        "id": str(job.id),
        "finding_id": job.finding_id,
        "repo_name": job.repo_name,
        "repo_url": job.repo_url,
        "file_path": job.file_path,
        "fix_type": job.fix_type,
        "status": job.status,
        "pr_url": job.pr_url,
        "pr_number": job.pr_number,
        "branch_name": job.branch_name,
        "fix_description": job.fix_description,
        "diff_preview": job.diff_preview,
        "error_message": job.error_message,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
    }


@router.get("/templates")
async def list_templates() -> dict[str, Any]:
    return {
        cwe_id: {
            "name": t["name"],
            "description": t["description"],
            "file_extension": t["file_extension"],
        }
        for cwe_id, t in CWE_FIX_TEMPLATES.items()
    }


@router.post("/batch")
async def batch_fix(
    body: BatchFixRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> list[dict[str, Any]]:
    results = []
    for finding in body.findings:
        job = AutoFixJob(
            tenant_id=user.tenant_id,
            finding_id=str(finding.get("finding_id", str(uuid.uuid4()))),
            repo_name=finding.get("repo_name", "unknown"),
            repo_url=finding.get("repo_url"),
            file_path=finding.get("file_path", ""),
            fix_type=finding.get("fix_type", "code_fix"),
            status="pending",
            created_by=user.user_id,
        )
        db.add(job)
        await db.flush()
        result = await process_autofix_job(db, job.id, finding)
        results.append(result)
    await db.commit()
    return results
