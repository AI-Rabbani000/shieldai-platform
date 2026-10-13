"""Phase 19 (Continuation Prompt 6): real MissionPlan/EngineeringTask read access,
mirroring `session_manager.py`'s own real, tenant-scoped CRUD pattern."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.models import EngineeringTask, MissionMessage, MissionPlan


class MissionPlanNotFound(Exception):
    pass


async def get_mission_plan(
    db: AsyncSession, *, tenant_id: uuid.UUID, mission_plan_id: uuid.UUID
) -> MissionPlan:
    plan = await db.get(MissionPlan, mission_plan_id)
    if plan is None or plan.tenant_id != tenant_id:
        raise MissionPlanNotFound(f"MissionPlan {mission_plan_id} not found for this tenant")
    return plan


async def list_mission_plans(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    repository_id: uuid.UUID | None = None,
    mission_id: uuid.UUID | None = None,
    status_filter: str | None = None,
) -> list[MissionPlan]:
    query = select(MissionPlan).where(MissionPlan.tenant_id == tenant_id)
    if repository_id is not None:
        query = query.where(MissionPlan.repository_id == repository_id)
    if mission_id is not None:
        query = query.where(MissionPlan.mission_id == mission_id)
    if status_filter is not None:
        query = query.where(MissionPlan.status == status_filter)
    result = await db.execute(query.order_by(MissionPlan.created_at.desc()))
    return list(result.scalars().all())


async def list_tasks(
    db: AsyncSession, *, tenant_id: uuid.UUID, mission_plan_id: uuid.UUID
) -> list[EngineeringTask]:
    query = (
        select(EngineeringTask)
        .where(EngineeringTask.tenant_id == tenant_id)
        .where(EngineeringTask.mission_plan_id == mission_plan_id)
        .order_by(EngineeringTask.created_at.asc())
    )
    result = await db.execute(query)
    return list(result.scalars().all())


async def list_messages(
    db: AsyncSession, *, tenant_id: uuid.UUID, mission_plan_id: uuid.UUID
) -> list[MissionMessage]:
    query = (
        select(MissionMessage)
        .where(MissionMessage.tenant_id == tenant_id)
        .where(MissionMessage.mission_plan_id == mission_plan_id)
        .order_by(MissionMessage.created_at.asc())
    )
    result = await db.execute(query)
    return list(result.scalars().all())
