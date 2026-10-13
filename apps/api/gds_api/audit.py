"""Append-only audit trail. record_audit_event() is the only way any code in this project
writes an audit row — there is deliberately no update or delete path anywhere in the API.
"""

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.db import get_db
from gds_api.models import AuditEvent
from gds_api.schemas import AuditEventOut
from gds_api.security import CurrentUser, require_permission

router = APIRouter(prefix="/audit", tags=["audit"])


async def record_audit_event(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID | None,
    user_id: uuid.UUID | None,
    action: str,
    detail: dict[str, object] | None = None,
) -> AuditEvent:
    event = AuditEvent(tenant_id=tenant_id, user_id=user_id, action=action, detail=detail or {})
    db.add(event)
    await db.flush()
    return event


@router.get("", response_model=list[AuditEventOut])
async def list_audit_events(
    limit: int = 50,
    offset: int = 0,
    current_user: CurrentUser = Depends(require_permission("audit:read")),
    db: AsyncSession = Depends(get_db),
) -> list[AuditEvent]:
    limit = max(1, min(limit, 200))
    result = await db.execute(
        select(AuditEvent)
        .where(AuditEvent.tenant_id == current_user.tenant_id)
        .order_by(AuditEvent.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return list(result.scalars().all())
