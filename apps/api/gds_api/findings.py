import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.db import get_db
from gds_api.memory import get_finding_correlation
from gds_api.models import Finding
from gds_api.schemas import FindingCorrelationOut, FindingOut
from gds_api.security import CurrentUser, require_permission

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=list[FindingOut])
async def list_findings(
    current_user: CurrentUser = Depends(require_permission("findings:read")),
    db: AsyncSession = Depends(get_db),
) -> list[Finding]:
    findings = (
        (
            await db.execute(
                select(Finding)
                .where(Finding.tenant_id == current_user.tenant_id)
                .order_by(Finding.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return list(findings)


@router.get("/{finding_id}/correlation", response_model=FindingCorrelationOut)
async def get_finding_correlation_chain(
    finding_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("findings:read")),
    db: AsyncSession = Depends(get_db),
) -> FindingCorrelationOut:
    """Phase 20 (Continuation Prompt 7 / EDP-007), Part 12: the real correlation
    chain for one Finding - attack path/detection (real Postgres text fields),
    remediation MissionPlan, commit, and retest status, traced through the real
    Neo4j edges gds_api.tool_gateway._auto_fix_finding and
    gds_api.engineering.merge_coordinator.commit_mission actually write. Tenant
    ownership is checked against the authoritative Postgres row first - Neo4j is
    never the source of truth for who owns a finding."""
    finding = await db.get(Finding, finding_id)
    if finding is None or finding.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")

    correlation = await get_finding_correlation(finding_id, current_user.tenant_id)
    if correlation is None:
        # Real, honest fallback: this finding has never been routed into a real
        # remediation MissionPlan, so no correlation graph node exists yet - not
        # an error, just nothing further to report beyond Postgres's own data.
        return FindingCorrelationOut(
            finding_id=finding.id,
            finding_title=finding.title,
            finding_status=finding.status,
            attack_path=finding.attack_path,
            detection_coverage=finding.detection_coverage,
            mission_plan_id=None,
            remediation_objective=None,
            commit_hash=None,
            retest_requested=False,
        )

    commit_hash = correlation.get("commit_hash")
    mission_plan_id_str = correlation.get("mission_plan_id")
    return FindingCorrelationOut(
        finding_id=finding.id,
        finding_title=str(correlation.get("finding_title") or finding.title),
        finding_status=str(correlation.get("finding_status") or finding.status),
        attack_path=correlation.get("attack_path"),
        detection_coverage=correlation.get("detection_coverage"),
        mission_plan_id=uuid.UUID(str(mission_plan_id_str)) if mission_plan_id_str else None,
        remediation_objective=correlation.get("remediation_objective"),
        commit_hash=str(commit_hash) if commit_hash else None,
        retest_requested=commit_hash is not None,
    )
