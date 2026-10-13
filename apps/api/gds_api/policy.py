"""Deterministic policy evaluation. No agent exists yet to call this automatically (the
Tool Gateway that will is Phase 3's job) — this exposes the real mechanism now via an
authenticated endpoint so it's provably working, not a stub waiting for Phase 3.

No agent, and no role, may bypass this by calling something other than evaluate_policy():
that is the single source of truth for whether an action is allowed, needs approval, or
is denied.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.audit import record_audit_event
from gds_api.db import get_db
from gds_api.models import Approval, Notification, Policy, Role, User
from gds_api.schemas import PolicyEvaluateRequest, PolicyEvaluateResponse
from gds_api.security import CurrentUser, require_permission

router = APIRouter(prefix="/policy", tags=["policy"])


async def evaluate_policy(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    requested_by_user_id: uuid.UUID,
    risk_class: str,
    action_description: str,
) -> PolicyEvaluateResponse:
    policy = (
        await db.execute(
            select(Policy).where(Policy.tenant_id == tenant_id, Policy.risk_class == risk_class)
        )
    ).scalar_one_or_none()
    if policy is None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Unknown risk_class '{risk_class}' - no policy rule defines it",
        )

    if not policy.requires_approval:
        await record_audit_event(
            db,
            tenant_id=tenant_id,
            user_id=requested_by_user_id,
            action="policy.evaluate",
            detail={
                "risk_class": risk_class,
                "decision": "allow",
                "action_description": action_description,
            },
        )
        return PolicyEvaluateResponse(decision="allow")

    approval = Approval(
        tenant_id=tenant_id,
        requested_by_user_id=requested_by_user_id,
        risk_class=risk_class,
        action_description=action_description,
    )
    db.add(approval)
    await db.flush()

    # Notify everyone holding the role authorized to decide this approval.
    approvers = (
        (
            await db.execute(
                select(User)
                .join(Role, User.role_id == Role.id)
                .where(Role.tenant_id == tenant_id, Role.name == policy.min_role)
            )
        )
        .scalars()
        .all()
    )
    for approver in approvers:
        db.add(
            Notification(
                tenant_id=tenant_id,
                user_id=approver.id,
                type="approval.pending",
                message=f"Approval requested: {action_description} (risk: {risk_class})",
            )
        )

    await record_audit_event(
        db,
        tenant_id=tenant_id,
        user_id=requested_by_user_id,
        action="policy.evaluate",
        detail={
            "risk_class": risk_class,
            "decision": "require_approval",
            "action_description": action_description,
            "approval_id": str(approval.id),
        },
    )
    return PolicyEvaluateResponse(decision="require_approval", approval_id=approval.id)


@router.post("/evaluate", response_model=PolicyEvaluateResponse)
async def evaluate(
    body: PolicyEvaluateRequest,
    current_user: CurrentUser = Depends(require_permission("policy:evaluate")),
    db: AsyncSession = Depends(get_db),
) -> PolicyEvaluateResponse:
    result = await evaluate_policy(
        db,
        tenant_id=current_user.tenant_id,
        requested_by_user_id=current_user.user_id,
        risk_class=body.risk_class,
        action_description=body.action_description,
    )
    await db.commit()
    return result
