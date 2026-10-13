"""In-app notifications only. No Slack/email/Teams integration is wired up here yet --
there are no credentials for those, and fabricating that integration would violate the
project's "no fabricated integrations" rule. See integrations/README.md.
"""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.db import get_db
from gds_api.models import Notification
from gds_api.schemas import NotificationOut
from gds_api.security import CurrentUser, require_permission

router = APIRouter(prefix="/notifications", tags=["notifications"])


@router.get("", response_model=list[NotificationOut])
async def list_notifications(
    unread_only: bool = False,
    current_user: CurrentUser = Depends(require_permission("notifications:read")),
    db: AsyncSession = Depends(get_db),
) -> list[Notification]:
    query = select(Notification).where(Notification.user_id == current_user.user_id)
    if unread_only:
        query = query.where(Notification.read_at.is_(None))
    result = await db.execute(query.order_by(Notification.created_at.desc()))
    return list(result.scalars().all())


@router.post("/{notification_id}/read", response_model=NotificationOut)
async def mark_read(
    notification_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("notifications:read")),
    db: AsyncSession = Depends(get_db),
) -> Notification:
    notification = await db.get(Notification, notification_id)
    if notification is None or notification.user_id != current_user.user_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Notification not found")
    if notification.read_at is None:
        notification.read_at = datetime.now(UTC)
        await db.commit()
        await db.refresh(notification)
    return notification
