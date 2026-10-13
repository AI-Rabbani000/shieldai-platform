import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.audit import record_audit_event
from gds_api.db import get_db
from gds_api.mission_lifecycle import start_mission_workflow
from gds_api.mission_taxonomy import MissionTypeIneligible, validate_mission_type_eligibility
from gds_api.models import (
    CapabilityRequestRecord,
    EngineeringSession,
    Mission,
    MissionTask,
    PurpleMissionMessage,
    WorkflowRun,
    Workspace,
)
from gds_api.rate_limit import tenant_rate_limit
from gds_api.schemas import (
    CapabilityRequestWithDecisionOut,
    EngineeringSessionOut,
    KnowledgeDocumentOut,
    MissionCreateRequest,
    MissionMemoryOut,
    MissionOut,
    MissionTaskOut,
    PurpleMissionMessageOut,
    WorkflowRunOut,
    WorkingMemoryEntryOut,
    WorkspaceOut,
)
from gds_api.security import CurrentUser, require_permission
from gds_api.workflow_runs import workflow_run_to_out

router = APIRouter(prefix="/missions", tags=["missions"])

# Named the same way gds_api.auth.login_rate_limit is - lets the test suite override
# just this dependency, since many tests create several missions well within an hour in
# ways that have nothing to do with exercising the rate limiter itself (already tested
# directly and for real in tests/test_rate_limit.py).
mission_create_rate_limit = tenant_rate_limit(
    "mission_create", max_requests=20, window_seconds=3600
)


def to_mission_out(mission: Mission, tasks: list[MissionTask]) -> MissionOut:
    return MissionOut(
        id=mission.id,
        objective=mission.objective,
        status=mission.status,
        risk_class=mission.risk_class,
        report=mission.report,
        mission_type=mission.mission_type,
        created_at=mission.created_at,
        completed_at=mission.completed_at,
        conversation_thread_id=mission.conversation_thread_id,
        tasks=[
            MissionTaskOut(
                id=t.id,
                sequence=t.sequence,
                description=t.description,
                tool_name=t.tool_name,
                agent_name=t.agent_name,
                risk_class=t.risk_class,
                status=t.status,
                approval_id=t.approval_id,
                result=t.result,
            )
            for t in tasks
        ],
    )


@router.post("", response_model=MissionOut, dependencies=[Depends(mission_create_rate_limit)])
async def create_mission(
    body: MissionCreateRequest,
    current_user: CurrentUser = Depends(require_permission("missions:create")),
    db: AsyncSession = Depends(get_db),
) -> MissionOut:
    try:
        await validate_mission_type_eligibility(
            db, tenant_id=current_user.tenant_id, mission_type=body.mission_type
        )
    except MissionTypeIneligible as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    mission = Mission(
        tenant_id=current_user.tenant_id,
        requested_by_user_id=current_user.user_id,
        objective=body.objective,
        mission_type=body.mission_type,
    )
    db.add(mission)
    await db.flush()

    await start_mission_workflow(db, mission, kind="direct")
    await record_audit_event(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="mission.created",
        detail={"mission_id": str(mission.id), "objective": body.objective},
    )
    await db.commit()
    return to_mission_out(mission, [])


@router.get("", response_model=list[MissionOut])
async def list_missions(
    current_user: CurrentUser = Depends(require_permission("missions:read")),
    db: AsyncSession = Depends(get_db),
) -> list[MissionOut]:
    missions = (
        (
            await db.execute(
                select(Mission)
                .where(Mission.tenant_id == current_user.tenant_id)
                .order_by(Mission.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return [to_mission_out(m, []) for m in missions]


@router.get("/{mission_id}", response_model=MissionOut)
async def get_mission(
    mission_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("missions:read")),
    db: AsyncSession = Depends(get_db),
) -> MissionOut:
    mission = await db.get(Mission, mission_id)
    if mission is None or mission.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Mission not found")

    tasks = (
        (
            await db.execute(
                select(MissionTask)
                .where(MissionTask.mission_id == mission.id)
                .order_by(MissionTask.sequence)
            )
        )
        .scalars()
        .all()
    )
    return to_mission_out(mission, list(tasks))


@router.get("/{mission_id}/workflow", response_model=WorkflowRunOut)
async def get_mission_workflow(
    mission_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("missions:read")),
    db: AsyncSession = Depends(get_db),
) -> WorkflowRunOut:
    """Phase 15, Part J: lets the Mission detail page find its associated WorkflowRun
    directly, without scanning GET /workflows. Reuses workflow_runs.workflow_run_to_out
    for the exact same shape GET /workflows/{id} returns - no separate, drifting
    representation. 404 (not the reconciler) is the honest answer for a legacy mission
    with no WorkflowRun row that hasn't been through the repair procedure yet - see
    docs/operations/workflow-repair.md."""
    mission = await db.get(Mission, mission_id)
    if mission is None or mission.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Mission not found")
    run = (
        await db.execute(select(WorkflowRun).where(WorkflowRun.mission_id == mission.id))
    ).scalar_one_or_none()
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "This mission has no workflow run record")
    return workflow_run_to_out(run, mission)


@router.get("/{mission_id}/messages", response_model=list[PurpleMissionMessageOut])
async def list_mission_messages(
    mission_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("missions:read")),
    db: AsyncSession = Depends(get_db),
) -> list[PurpleMissionMessage]:
    """Phase 20 (Continuation Prompt 7 / EDP-007), Part 14: the real read-side
    contract for Part 8's PurpleMissionMessage write path - previously write-only
    (see docs/architecture/purple-mission-model.md's own disclosed gap). Every real
    Purple Workforce inter-agent message for this mission, in creation order - the
    same messages a live purple_message SSE event (this sub-phase's other real
    addition) announces in real time; this endpoint is the durable timeline a
    client loads on first render or reconnect."""
    mission = await db.get(Mission, mission_id)
    if mission is None or mission.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Mission not found")

    messages = (
        (
            await db.execute(
                select(PurpleMissionMessage)
                .where(PurpleMissionMessage.mission_id == mission_id)
                .order_by(PurpleMissionMessage.created_at)
            )
        )
        .scalars()
        .all()
    )
    return list(messages)


@router.get(
    "/{mission_id}/capability-requests",
    response_model=list[CapabilityRequestWithDecisionOut],
)
async def list_mission_capability_requests(
    mission_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("missions:read")),
    db: AsyncSession = Depends(get_db),
) -> list[CapabilityRequestWithDecisionOut]:
    """Phase 16, Part R: every real capability request/decision this mission's tasks
    produced - the Mission detail page's real evidence that every tool call this mission
    made was actually gated by the Secure Capability Broker, not just claimed to be."""
    from gds_api.capabilities_api import _decision_to_out, _latest_decision, _request_to_out

    mission = await db.get(Mission, mission_id)
    if mission is None or mission.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Mission not found")

    requests = (
        (
            await db.execute(
                select(CapabilityRequestRecord)
                .where(CapabilityRequestRecord.mission_id == mission_id)
                .order_by(CapabilityRequestRecord.requested_at)
            )
        )
        .scalars()
        .all()
    )
    out: list[CapabilityRequestWithDecisionOut] = []
    for req in requests:
        decision = await _latest_decision(db, req.id)
        out.append(
            CapabilityRequestWithDecisionOut(
                request=_request_to_out(req),
                decision=_decision_to_out(decision) if decision else None,
            )
        )
    return out


@router.get("/{mission_id}/workspaces", response_model=list[WorkspaceOut])
async def list_mission_workspaces(
    mission_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("missions:read")),
    db: AsyncSession = Depends(get_db),
) -> list[WorkspaceOut]:
    """Phase 17, Part 14: the Mission Repository Panel - every real Workspace (isolated
    git worktree) this mission's repository capabilities opened."""
    from gds_api.repository_api import _workspace_to_out

    mission = await db.get(Mission, mission_id)
    if mission is None or mission.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Mission not found")

    rows = (
        (
            await db.execute(
                select(Workspace)
                .where(Workspace.mission_id == mission_id)
                .order_by(Workspace.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return [_workspace_to_out(w) for w in rows]


@router.get("/{mission_id}/engineering-sessions", response_model=list[EngineeringSessionOut])
async def list_mission_engineering_sessions(
    mission_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("missions:read")),
    db: AsyncSession = Depends(get_db),
) -> list[EngineeringSessionOut]:
    """Phase 18, Part 14: the Mission Engineering Panel - every real AI engineering
    session this mission ran."""
    from gds_api.engineering_api import _session_to_out

    mission = await db.get(Mission, mission_id)
    if mission is None or mission.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Mission not found")

    rows = (
        (
            await db.execute(
                select(EngineeringSession)
                .where(EngineeringSession.mission_id == mission_id)
                .order_by(EngineeringSession.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return [_session_to_out(s) for s in rows]


@router.get("/{mission_id}/memory", response_model=MissionMemoryOut)
async def get_mission_memory(
    mission_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("missions:read")),
    db: AsyncSession = Depends(get_db),
) -> MissionMemoryOut:
    """Phase 21 (Continuation Prompt 8 / EDP-008), Part 2: the Mission Memory panel's
    real data source - reuses gds_api.memory's existing Redis working-memory key and
    KnowledgeDocument.source_mission_id (Part 13's lesson write path), neither of
    which had a per-mission read endpoint before this. No new storage, no new write
    path - only the one real query each of those two facts was missing."""
    from gds_api.memory import _get_redis, _working_key
    from gds_api.models import KnowledgeDocument

    mission = await db.get(Mission, mission_id)
    if mission is None or mission.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Mission not found")

    working_memory: WorkingMemoryEntryOut | None = None
    async with _get_redis() as r:
        key = _working_key(mission_id)
        if await r.exists(key):
            ttl = await r.ttl(key)
            working_memory = WorkingMemoryEntryOut(mission_id=mission_id, ttl_seconds=ttl)

    lessons = (
        (
            await db.execute(
                select(KnowledgeDocument)
                .where(KnowledgeDocument.source_mission_id == mission_id)
                .order_by(KnowledgeDocument.created_at)
            )
        )
        .scalars()
        .all()
    )

    return MissionMemoryOut(
        working_memory=working_memory,
        lessons_created=[
            KnowledgeDocumentOut(
                id=doc.id,
                title=doc.title,
                content=doc.content,
                created_at=doc.created_at,
                document_type=doc.document_type,
                source_mission_id=doc.source_mission_id,
            )
            for doc in lessons
        ],
    )


@router.get("/{mission_id}/report/export")
async def export_mission_report(
    mission_id: uuid.UUID,
    export_format: str = "markdown",
    current_user: CurrentUser = Depends(require_permission("missions:read")),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Real export of a completed mission's synthesized report - the Reports page (Phase
    6) downloads this rather than the frontend re-rendering report text itself."""
    if export_format not in ("markdown", "json"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "format must be 'markdown' or 'json'")

    mission = await db.get(Mission, mission_id)
    if mission is None or mission.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Mission not found")
    if not mission.report:
        raise HTTPException(status.HTTP_409_CONFLICT, "Mission has no report yet")

    if export_format == "json":
        body = json.dumps(
            {
                "mission_id": str(mission.id),
                "objective": mission.objective,
                "status": mission.status,
                "risk_class": mission.risk_class,
                "report": mission.report,
                "created_at": mission.created_at.isoformat(),
                "completed_at": mission.completed_at.isoformat() if mission.completed_at else None,
            },
            indent=2,
        )
        return Response(
            content=body,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="mission-{mission.id}-report.json"'
            },
        )

    markdown = (
        f"# Mission Report\n\n"
        f"**Objective:** {mission.objective}\n\n"
        f"**Status:** {mission.status}\n\n"
        f"**Risk class:** {mission.risk_class or 'n/a'}\n\n"
        f"**Completed:** {mission.completed_at.isoformat() if mission.completed_at else 'n/a'}\n\n"
        f"---\n\n{mission.report}\n"
    )
    return Response(
        content=markdown,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="mission-{mission.id}-report.md"'},
    )
