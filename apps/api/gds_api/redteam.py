"""Phase 8: real management of the Red Team safety boundary - authorized targets and
the emergency stop kill switch. Every write here is `redteam:manage`-gated
(platform_owner only in seed_data.ROLE_PERMISSIONS - deliberately stricter than
approvals:decide, which analyst also holds) since this is the highest-scrutiny
permission in the platform. The real enforcement these endpoints configure lives in
gds_api.redteam_safety, checked by every Red Team tool in gds_api.tool_gateway.
"""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.audit import record_audit_event
from gds_api.db import get_db
from gds_api.engagement import (
    KNOWN_TECHNIQUES,
    EngagementStatus,
    InvalidEngagementTransition,
    validate_engagement_transition,
)
from gds_api.metrics import pentest_engagement_transitions_total
from gds_api.mission_taxonomy import MissionType
from gds_api.models import AuthorizedTarget, Engagement, EngagementTarget, Mission
from gds_api.redteam_safety import get_safety_state
from gds_api.schemas import (
    AuthorizedTargetCreateRequest,
    AuthorizedTargetOut,
    EngagementCreateRequest,
    EngagementOut,
    RedTeamStatusOut,
)
from gds_api.security import CurrentUser, require_permission

router = APIRouter(prefix="/red-team", tags=["red-team"])


@router.get("/status", response_model=RedTeamStatusOut)
async def get_status(
    current_user: CurrentUser = Depends(require_permission("redteam:read")),
    db: AsyncSession = Depends(get_db),
) -> RedTeamStatusOut:
    state = await get_safety_state(db, current_user.tenant_id)
    await db.commit()
    active_count = (
        await db.execute(
            select(func.count(AuthorizedTarget.id)).where(
                AuthorizedTarget.tenant_id == current_user.tenant_id,
                AuthorizedTarget.status == "active",
            )
        )
    ).scalar_one()
    return RedTeamStatusOut(
        emergency_stop_engaged=state.emergency_stop_engaged,
        engaged_by_user_id=state.engaged_by_user_id,
        engaged_at=state.engaged_at,
        active_target_count=active_count,
    )


@router.post("/emergency-stop", response_model=RedTeamStatusOut)
async def engage_emergency_stop(
    current_user: CurrentUser = Depends(require_permission("redteam:manage")),
    db: AsyncSession = Depends(get_db),
) -> RedTeamStatusOut:
    state = await get_safety_state(db, current_user.tenant_id)
    state.emergency_stop_engaged = True
    state.engaged_by_user_id = current_user.user_id
    state.engaged_at = datetime.now(UTC)
    await record_audit_event(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="redteam.emergency_stop_engaged",
        detail={},
    )
    await db.commit()
    active_count = (
        await db.execute(
            select(func.count(AuthorizedTarget.id)).where(
                AuthorizedTarget.tenant_id == current_user.tenant_id,
                AuthorizedTarget.status == "active",
            )
        )
    ).scalar_one()
    return RedTeamStatusOut(
        emergency_stop_engaged=True,
        engaged_by_user_id=state.engaged_by_user_id,
        engaged_at=state.engaged_at,
        active_target_count=active_count,
    )


@router.post("/emergency-stop/clear", response_model=RedTeamStatusOut)
async def clear_emergency_stop(
    current_user: CurrentUser = Depends(require_permission("redteam:manage")),
    db: AsyncSession = Depends(get_db),
) -> RedTeamStatusOut:
    state = await get_safety_state(db, current_user.tenant_id)
    state.emergency_stop_engaged = False
    state.engaged_by_user_id = None
    state.engaged_at = None
    await record_audit_event(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="redteam.emergency_stop_cleared",
        detail={},
    )
    await db.commit()
    active_count = (
        await db.execute(
            select(func.count(AuthorizedTarget.id)).where(
                AuthorizedTarget.tenant_id == current_user.tenant_id,
                AuthorizedTarget.status == "active",
            )
        )
    ).scalar_one()
    return RedTeamStatusOut(
        emergency_stop_engaged=False,
        engaged_by_user_id=None,
        engaged_at=None,
        active_target_count=active_count,
    )


@router.get("/targets", response_model=list[AuthorizedTargetOut])
async def list_targets(
    current_user: CurrentUser = Depends(require_permission("redteam:read")),
    db: AsyncSession = Depends(get_db),
) -> list[AuthorizedTarget]:
    rows = (
        (
            await db.execute(
                select(AuthorizedTarget)
                .where(AuthorizedTarget.tenant_id == current_user.tenant_id)
                .order_by(AuthorizedTarget.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


@router.post("/targets", response_model=AuthorizedTargetOut)
async def create_target(
    body: AuthorizedTargetCreateRequest,
    current_user: CurrentUser = Depends(require_permission("redteam:manage")),
    db: AsyncSession = Depends(get_db),
) -> AuthorizedTarget:
    target = body.target.strip().lower()
    if not target:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "target is required")
    if body.target_type not in ("domain", "url", "ip"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "target_type must be domain|url|ip")
    if not body.scope_description.strip():
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "scope_description is required - what is authorized and why",
        )
    if body.valid_until <= datetime.now(UTC):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "valid_until must be in the future")
    if body.max_actions_per_hour < 1:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "max_actions_per_hour must be at least 1")

    authorized_target = AuthorizedTarget(
        tenant_id=current_user.tenant_id,
        target=target,
        target_type=body.target_type,
        scope_description=body.scope_description,
        authorized_by_user_id=current_user.user_id,
        valid_until=body.valid_until,
        max_actions_per_hour=body.max_actions_per_hour,
    )
    db.add(authorized_target)
    await record_audit_event(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="redteam.target_authorized",
        detail={"target": target, "scope_description": body.scope_description},
    )
    await db.commit()
    await db.refresh(authorized_target)
    return authorized_target


@router.post("/targets/{target_id}/revoke", response_model=AuthorizedTargetOut)
async def revoke_target(
    target_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("redteam:manage")),
    db: AsyncSession = Depends(get_db),
) -> AuthorizedTarget:
    row = await db.get(AuthorizedTarget, target_id)
    if row is None or row.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Authorized target not found")
    if row.status == "revoked":
        raise HTTPException(status.HTTP_409_CONFLICT, "Already revoked")

    row.status = "revoked"
    row.revoked_at = datetime.now(UTC)
    await record_audit_event(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="redteam.target_revoked",
        detail={"target": row.target},
    )
    await db.commit()
    await db.refresh(row)
    return row


# ---- Phase 20 (Continuation Prompt 7 / EDP-007), Part 11: Pentest Engagements -----
#
# An Engagement is a real, written authorisation layered on top of AuthorizedTarget/
# redteam_safety (never replacing them - see gds_api.engagement's module docstring).
# Creation/authorisation stay redteam:manage-gated, the same highest-scrutiny
# permission every other Red Team write already requires.


async def _load_target_ids(db: AsyncSession, engagement_id: uuid.UUID) -> list[uuid.UUID]:
    rows = (
        (
            await db.execute(
                select(EngagementTarget.authorized_target_id).where(
                    EngagementTarget.engagement_id == engagement_id
                )
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


async def _engagement_out(db: AsyncSession, engagement: Engagement) -> EngagementOut:
    target_ids = await _load_target_ids(db, engagement.id)
    return EngagementOut(
        id=engagement.id,
        mission_id=engagement.mission_id,
        name=engagement.name,
        rules_of_engagement=engagement.rules_of_engagement,
        allowed_techniques=list(engagement.allowed_techniques),
        prohibited_techniques=list(engagement.prohibited_techniques),
        exclusion_list=list(engagement.exclusion_list),
        status=engagement.status,
        authorized_by_user_id=engagement.authorized_by_user_id,
        report_summary=engagement.report_summary,
        created_at=engagement.created_at,
        started_at=engagement.started_at,
        completed_at=engagement.completed_at,
        target_ids=target_ids,
    )


@router.get("/engagements", response_model=list[EngagementOut])
async def list_engagements(
    current_user: CurrentUser = Depends(require_permission("redteam:read")),
    db: AsyncSession = Depends(get_db),
) -> list[EngagementOut]:
    rows = (
        (
            await db.execute(
                select(Engagement)
                .where(Engagement.tenant_id == current_user.tenant_id)
                .order_by(Engagement.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return [await _engagement_out(db, row) for row in rows]


@router.get("/engagements/{engagement_id}", response_model=EngagementOut)
async def get_engagement(
    engagement_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("redteam:read")),
    db: AsyncSession = Depends(get_db),
) -> EngagementOut:
    row = await db.get(Engagement, engagement_id)
    if row is None or row.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Engagement not found")
    return await _engagement_out(db, row)


@router.post("/engagements", response_model=EngagementOut)
async def create_engagement(
    body: EngagementCreateRequest,
    current_user: CurrentUser = Depends(require_permission("redteam:manage")),
    db: AsyncSession = Depends(get_db),
) -> EngagementOut:
    if not body.name.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "name is required")
    if not body.rules_of_engagement.strip():
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "rules_of_engagement is required - what is in scope and why",
        )
    if not body.target_ids:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "at least one target_id is required")
    unknown_techniques = (set(body.allowed_techniques) | set(body.prohibited_techniques)) - (
        KNOWN_TECHNIQUES
    )
    if unknown_techniques:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"unknown technique(s) {sorted(unknown_techniques)} - must be a subset of "
            f"{sorted(KNOWN_TECHNIQUES)}",
        )

    mission = await db.get(Mission, body.mission_id)
    if mission is None or mission.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Mission not found")
    if mission.mission_type != MissionType.PENETRATION_TEST.value:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "an Engagement must be linked to a real mission_type='penetration_test' Mission",
        )
    existing = (
        await db.execute(select(Engagement.id).where(Engagement.mission_id == body.mission_id))
    ).first()
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "this mission already has an Engagement")

    now = datetime.now(UTC)
    for target_id in body.target_ids:
        target = await db.get(AuthorizedTarget, target_id)
        if (
            target is None
            or target.tenant_id != current_user.tenant_id
            or target.status != "active"
            or target.valid_from > now
            or target.valid_until < now
        ):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"target {target_id} is not a real, currently-active AuthorizedTarget for "
                "this tenant",
            )

    engagement = Engagement(
        tenant_id=current_user.tenant_id,
        mission_id=body.mission_id,
        name=body.name,
        rules_of_engagement=body.rules_of_engagement,
        allowed_techniques=body.allowed_techniques,
        prohibited_techniques=body.prohibited_techniques,
        exclusion_list=body.exclusion_list,
        status=EngagementStatus.PLANNED.value,
        authorized_by_user_id=current_user.user_id,
    )
    db.add(engagement)
    await db.flush()
    pentest_engagement_transitions_total.labels(to_status=EngagementStatus.PLANNED.value).inc()
    for target_id in body.target_ids:
        db.add(EngagementTarget(engagement_id=engagement.id, authorized_target_id=target_id))
    await record_audit_event(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="redteam.engagement_created",
        detail={"engagement_id": str(engagement.id), "mission_id": str(body.mission_id)},
    )
    await db.commit()
    await db.refresh(engagement)
    return await _engagement_out(db, engagement)


@router.post("/engagements/{engagement_id}/authorize", response_model=EngagementOut)
async def authorize_engagement(
    engagement_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("redteam:manage")),
    db: AsyncSession = Depends(get_db),
) -> EngagementOut:
    """The real, distinct 'human pre-execution approval' step the Penetration
    Testing Coordinator's own PlannedAgentManifest description named - separate
    from mere creation, and separate again from the coordinate_pentest_engagement
    capability's own broker-level approval gate at the moment of execution."""
    row = await db.get(Engagement, engagement_id)
    if row is None or row.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Engagement not found")
    try:
        validate_engagement_transition(row.status, EngagementStatus.AUTHORIZED.value)
    except InvalidEngagementTransition as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    row.status = EngagementStatus.AUTHORIZED.value
    pentest_engagement_transitions_total.labels(to_status=EngagementStatus.AUTHORIZED.value).inc()
    await record_audit_event(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="redteam.engagement_authorized",
        detail={"engagement_id": str(row.id)},
    )
    await db.commit()
    await db.refresh(row)
    return await _engagement_out(db, row)


@router.post("/engagements/{engagement_id}/abort", response_model=EngagementOut)
async def abort_engagement(
    engagement_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("redteam:manage")),
    db: AsyncSession = Depends(get_db),
) -> EngagementOut:
    row = await db.get(Engagement, engagement_id)
    if row is None or row.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Engagement not found")
    try:
        validate_engagement_transition(row.status, EngagementStatus.ABORTED.value)
    except InvalidEngagementTransition as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    row.status = EngagementStatus.ABORTED.value
    row.completed_at = datetime.now(UTC)
    pentest_engagement_transitions_total.labels(to_status=EngagementStatus.ABORTED.value).inc()
    await record_audit_event(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="redteam.engagement_aborted",
        detail={"engagement_id": str(row.id)},
    )
    await db.commit()
    await db.refresh(row)
    return await _engagement_out(db, row)
