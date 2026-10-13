"""Phase 18 (Continuation Prompt 5), Part 6: real EngineeringSession persistence - CRUD
and status transitions, mirroring gds_api.repository.registry's own real, tenant-scoped
CRUD pattern for Repository/Workspace."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.audit import record_audit_event
from gds_api.models import EngineeringSession

_ACTIVE_STATES = (
    "PENDING",
    "RUNNING",
    "AWAITING_REVIEW",
    "AWAITING_APPROVAL",
    "APPROVED",
    "COMMITTING",
)
_TERMINAL_STATES = ("COMPLETED", "FAILED", "CANCELLED", "REJECTED")


class EngineeringSessionNotFound(Exception):
    pass


async def create_session(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    mission_id: uuid.UUID,
    workflow_run_id: uuid.UUID | None,
    repository_id: uuid.UUID,
    workspace_id: uuid.UUID,
    capability_decision_id: uuid.UUID | None,
    provider: str,
    requested_by_user_id: uuid.UUID,
    agent_id: str | None,
    objective: str,
    compiled_prompt: str,
    prompt_version: str,
) -> EngineeringSession:
    session = EngineeringSession(
        tenant_id=tenant_id,
        mission_id=mission_id,
        workflow_run_id=workflow_run_id,
        repository_id=repository_id,
        workspace_id=workspace_id,
        capability_decision_id=capability_decision_id,
        provider=provider,
        requested_by_user_id=requested_by_user_id,
        agent_id=agent_id,
        objective=objective,
        compiled_prompt=compiled_prompt,
        prompt_version=prompt_version,
        status="PENDING",
    )
    db.add(session)
    await db.flush()
    await record_audit_event(
        db,
        tenant_id=tenant_id,
        user_id=requested_by_user_id,
        action="engineering.session_created",
        detail={
            "session_id": str(session.id),
            "provider": provider,
            "repository_id": str(repository_id),
        },
    )
    await db.commit()
    await db.refresh(session)
    return session


async def get_session(
    db: AsyncSession, *, tenant_id: uuid.UUID, session_id: uuid.UUID
) -> EngineeringSession:
    session = await db.get(EngineeringSession, session_id)
    if session is None or session.tenant_id != tenant_id:
        raise EngineeringSessionNotFound(
            f"EngineeringSession {session_id} not found for this tenant"
        )
    return session


async def list_sessions(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    repository_id: uuid.UUID | None = None,
    mission_id: uuid.UUID | None = None,
    status_filter: str | None = None,
) -> list[EngineeringSession]:
    query = select(EngineeringSession).where(EngineeringSession.tenant_id == tenant_id)
    if repository_id is not None:
        query = query.where(EngineeringSession.repository_id == repository_id)
    if mission_id is not None:
        query = query.where(EngineeringSession.mission_id == mission_id)
    if status_filter is not None:
        query = query.where(EngineeringSession.status == status_filter)
    result = await db.execute(query.order_by(EngineeringSession.created_at.desc()))
    return list(result.scalars().all())


async def mark_running(db: AsyncSession, *, session_id: uuid.UUID) -> None:
    session = await db.get(EngineeringSession, session_id)
    if session is None:
        return
    session.status = "RUNNING"
    session.started_at = datetime.now(UTC)
    await db.commit()


async def mark_terminal(
    db: AsyncSession,
    *,
    session_id: uuid.UUID,
    status: str,
    failure_reason: str | None = None,
) -> None:
    if status not in _TERMINAL_STATES:
        raise ValueError(f"'{status}' is not a real terminal EngineeringSession status")
    session = await db.get(EngineeringSession, session_id)
    if session is None:
        return
    session.status = status
    session.completed_at = datetime.now(UTC)
    if failure_reason:
        session.failure_reason = failure_reason[:2000]
    await db.commit()
