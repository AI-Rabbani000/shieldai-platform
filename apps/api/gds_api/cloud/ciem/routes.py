"""CIEM FastAPI routes — identity threat detection API."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.db import get_db
from gds_api.security import CurrentUser, require_permission
from gds_api.cloud.ciem.models import CIEMFinding, CIEMScanResult
from gds_api.cloud.ciem.analyzer import (
    analyze_aws_iam,
    analyze_azure_rbac,
    analyze_gcp_iam,
    generate_least_privilege_policy,
)

router = APIRouter(prefix="/cloud/ciem", tags=["CIEM"])


class CIEMScanRequest(BaseModel):
    provider: str
    cloud_account_id: str
    region: str = "us-east-1"
    access_key_id: str | None = None
    secret_access_key: str | None = None
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    project_id: str | None = None


class CIEMFindingOut(BaseModel):
    id: str
    cloud_account_id: str
    provider: str
    identity_type: str
    identity_name: str
    identity_arn: str
    finding_type: str
    title: str
    severity: str
    status: str
    permissions_granted: int
    permissions_used: int
    unused_permissions: int
    days_inactive: int
    blast_radius: float
    privilege_escalation_path: str | None
    remediation: str | None
    detected_at: datetime

    class Config:
        from_attributes = True


class CIEMScanResultOut(BaseModel):
    id: str
    cloud_account_id: str
    provider: str
    identities_analyzed: int
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    risk_score: float
    started_at: datetime
    completed_at: datetime | None
    status: str
    summary: str | None

    class Config:
        from_attributes = True


class CIEMFindingUpdate(BaseModel):
    status: str


class CIEMRemediationRequest(BaseModel):
    used_permissions: list[str] = []


@router.post("/scans", response_model=CIEMScanResultOut)
async def trigger_ciem_scan(
    req: CIEMScanRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permission("cloud:write")),
):
    """Trigger a new CIEM scan for the specified cloud account."""
    scan = CIEMScanResult(
        cloud_account_id=req.cloud_account_id,
        provider=req.provider,
        status="running",
    )
    db.add(scan)
    await db.flush()

    if req.provider == "aws":
        result = await analyze_aws_iam(
            access_key_id=req.access_key_id,
            secret_access_key=req.secret_access_key,
            region=req.region,
        )
    elif req.provider == "azure":
        result = await analyze_azure_rbac(
            tenant_id=req.tenant_id,
            client_id=req.client_id,
            client_secret=req.client_secret,
        )
    elif req.provider == "gcp":
        result = await analyze_gcp_iam(project_id=req.project_id)
    else:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {req.provider}")

    findings_data = result.get("findings", [])
    critical = sum(1 for f in findings_data if f.get("severity") == "critical")
    high = sum(1 for f in findings_data if f.get("severity") == "high")
    medium = sum(1 for f in findings_data if f.get("severity") == "medium")
    low = sum(1 for f in findings_data if f.get("severity") == "low")
    risk_score = min(100.0, (critical * 25) + (high * 15) + (medium * 5) + (low * 1))

    for f in findings_data:
        finding = CIEMFinding(
            cloud_account_id=req.cloud_account_id,
            provider=req.provider,
            identity_type=f.get("identity_type", "unknown"),
            identity_name=f.get("identity_name", "unknown"),
            identity_arn=f.get("identity_arn", ""),
            finding_type=f.get("finding_type", "unknown"),
            title=f.get("title", "Unknown finding"),
            severity=f.get("severity", "low"),
            status="open",
            permissions_granted=f.get("permissions_granted", 0),
            permissions_used=f.get("permissions_used", 0),
            unused_permissions=f.get("unused_permissions", 0),
            days_inactive=f.get("days_inactive", 0),
            blast_radius=f.get("blast_radius", 0.0),
            privilege_escalation_path=f.get("privilege_escalation_path"),
            remediation=f.get("remediation"),
        )
        db.add(finding)

    scan.identities_analyzed = result.get("identities_analyzed", 0)
    scan.findings_count = len(findings_data)
    scan.critical_count = critical
    scan.high_count = high
    scan.medium_count = medium
    scan.low_count = low
    scan.risk_score = risk_score
    scan.status = "completed"
    scan.completed_at = datetime.now(timezone.utc)
    scan.summary = result.get("error") or f"Analyzed {scan.identities_analyzed} identities, found {len(findings_data)} findings"

    await db.flush()
    return scan


@router.get("/scans", response_model=list[CIEMScanResultOut])
async def list_ciem_scans(
    cloud_account_id: str | None = Query(None),
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permission("cloud:read")),
):
    """List CIEM scans."""
    q = select(CIEMScanResult).order_by(CIEMScanResult.started_at.desc()).limit(limit).offset(offset)
    if cloud_account_id:
        q = q.where(CIEMScanResult.cloud_account_id == cloud_account_id)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/scans/{scan_id}", response_model=CIEMScanResultOut)
async def get_ciem_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permission("cloud:read")),
):
    """Get CIEM scan details."""
    q = select(CIEMScanResult).where(CIEMScanResult.id == scan_id)
    result = await db.execute(q)
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/findings", response_model=list[CIEMFindingOut])
async def list_ciem_findings(
    cloud_account_id: str | None = Query(None),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permission("cloud:read")),
):
    """List CIEM findings with filters."""
    q = select(CIEMFinding).order_by(CIEMFinding.detected_at.desc()).limit(limit).offset(offset)
    if cloud_account_id:
        q = q.where(CIEMFinding.cloud_account_id == cloud_account_id)
    if severity:
        q = q.where(CIEMFinding.severity == severity)
    if status:
        q = q.where(CIEMFinding.status == status)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/findings/{finding_id}", response_model=CIEMFindingOut)
async def get_ciem_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permission("cloud:read")),
):
    """Get specific CIEM finding."""
    q = select(CIEMFinding).where(CIEMFinding.id == finding_id)
    result = await db.execute(q)
    finding = result.scalars().first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch("/findings/{finding_id}", response_model=CIEMFindingOut)
async def update_ciem_finding(
    finding_id: str,
    update: CIEMFindingUpdate,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permission("cloud:write")),
):
    """Update CIEM finding status."""
    q = select(CIEMFinding).where(CIEMFinding.id == finding_id)
    result = await db.execute(q)
    finding = result.scalars().first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding.status = update.status
    if update.status == "remediated":
        finding.resolved_at = datetime.now(timezone.utc)
    await db.flush()
    return finding


@router.get("/risk-summary")
async def ciem_risk_summary(
    cloud_account_id: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permission("cloud:read")),
):
    """Aggregate identity risk score per account."""
    q = select(CIEMFinding)
    if cloud_account_id:
        q = q.where(CIEMFinding.cloud_account_id == cloud_account_id)
    result = await db.execute(q)
    findings = result.scalars().all()

    accounts: dict[str, dict[str, Any]] = {}
    for f in findings:
        key = f.cloud_account_id
        if key not in accounts:
            accounts[key] = {
                "cloud_account_id": key,
                "provider": f.provider,
                "total_findings": 0,
                "critical": 0, "high": 0, "medium": 0, "low": 0,
                "avg_blast_radius": 0.0, "risk_score": 0.0,
                "open": 0, "remediated": 0,
            }
        acc = accounts[key]
        acc["total_findings"] += 1
        acc[f.severity] += 1
        acc["avg_blast_radius"] += f.blast_radius
        if f.status == "open":
            acc["open"] += 1
        elif f.status == "remediated":
            acc["remediated"] += 1

    for acc in accounts.values():
        if acc["total_findings"] > 0:
            acc["avg_blast_radius"] = acc["avg_blast_radius"] / acc["total_findings"]
        acc["risk_score"] = min(100.0,
            (acc["critical"] * 25) + (acc["high"] * 15) + (acc["medium"] * 5) + (acc["low"] * 1))

    return list(accounts.values())


@router.post("/findings/{finding_id}/remediate")
async def generate_ciem_remediation(
    finding_id: str,
    req: CIEMRemediationRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permission("cloud:write")),
):
    """Generate a least-privilege remediation plan for a CIEM finding."""
    q = select(CIEMFinding).where(CIEMFinding.id == finding_id)
    result = await db.execute(q)
    finding = result.scalars().first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    policy = generate_least_privilege_policy(finding.identity_arn, req.used_permissions)
    return {
        "finding_id": finding_id,
        "identity": finding.identity_arn,
        "finding_type": finding.finding_type,
        "recommended_policy": policy,
        "remediation_steps": [
            f"1. Review current permissions for {finding.identity_name}",
            "2. Apply the generated least-privilege policy",
            "3. Remove the over-permissive policy attachment",
            "4. Verify the identity can still perform required tasks",
            "5. Monitor for permission-denied errors for 7 days",
        ],
    }
