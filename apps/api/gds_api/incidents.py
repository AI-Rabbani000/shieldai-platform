from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.db import get_db
from gds_api.models import Incident, IncidentFinding
from gds_api.schemas import IncidentOut
from gds_api.security import CurrentUser, require_permission

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("", response_model=list[IncidentOut])
async def list_incidents(
    current_user: CurrentUser = Depends(require_permission("incidents:read")),
    db: AsyncSession = Depends(get_db),
) -> list[IncidentOut]:
    rows = (
        await db.execute(
            select(Incident, func.count(IncidentFinding.finding_id))
            .outerjoin(IncidentFinding, IncidentFinding.incident_id == Incident.id)
            .where(Incident.tenant_id == current_user.tenant_id)
            .group_by(Incident.id)
            .order_by(Incident.created_at.desc())
        )
    ).all()
    return [
        IncidentOut(
            id=incident.id,
            title=incident.title,
            summary=incident.summary,
            severity=incident.severity,
            status=incident.status,
            report=incident.report,
            created_at=incident.created_at,
            resolved_at=incident.resolved_at,
            finding_count=finding_count,
        )
        for incident, finding_count in rows
    ]
