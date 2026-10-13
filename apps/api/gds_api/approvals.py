import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.audit import record_audit_event
from gds_api.db import get_db
from gds_api.models import Approval, Notification
from gds_api.schemas import ApprovalDecisionRequest, ApprovalOut
from gds_api.security import CurrentUser, require_permission

router = APIRouter(prefix="/approvals", tags=["approvals"])


@router.get("", response_model=list[ApprovalOut])
async def list_approvals(
    status_filter: str | None = None,
    current_user: CurrentUser = Depends(require_permission("approvals:read")),
    db: AsyncSession = Depends(get_db),
) -> list[Approval]:
    query = select(Approval).where(Approval.tenant_id == current_user.tenant_id)
    if status_filter:
        query = query.where(Approval.status == status_filter)
    result = await db.execute(query.order_by(Approval.created_at.desc()))
    return list(result.scalars().all())


@router.post("/{approval_id}/decide", response_model=ApprovalOut)
async def decide_approval(
    approval_id: uuid.UUID,
    body: ApprovalDecisionRequest,
    current_user: CurrentUser = Depends(require_permission("approvals:decide")),
    db: AsyncSession = Depends(get_db),
) -> Approval:
    if body.decision not in ("approved", "rejected"):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "decision must be 'approved' or 'rejected'"
        )

    approval = await db.get(Approval, approval_id)
    if approval is None or approval.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Approval not found")
    if approval.status != "pending":
        raise HTTPException(status.HTTP_409_CONFLICT, f"Approval already {approval.status}")

    approval.status = body.decision
    approval.decided_by_user_id = current_user.user_id
    approval.decided_at = datetime.now(UTC)

    db.add(
        Notification(
            tenant_id=approval.tenant_id,
            user_id=approval.requested_by_user_id,
            type="approval.decided",
            message=f"Your request '{approval.action_description}' was {body.decision}",
        )
    )
    await record_audit_event(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="approval.decide",
        detail={"approval_id": str(approval.id), "decision": body.decision},
    )
    await db.commit()
    await db.refresh(approval)
    return approval
