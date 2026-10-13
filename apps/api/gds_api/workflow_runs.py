"""Operational view over gds_api.models.WorkflowRun rows, plus real Temporal control
(cancel) via gds_api.temporal_client, and (Phase 15) the reconciliation service.

Named workflow_runs.py, not workflows.py, because gds_api.workflows is already the
Temporal package (workflows/mission_workflow.py, workflows/activities.py) - a module and
a package can't share a name in the same parent package. The router's URL prefix is
still /workflows.

Scope decision (docs/adr/0005-phase-6-frontend-scope.md): this is an operational list/
detail/cancel view over the one real workflow type this project has (MissionWorkflow) -
not a generic multi-workflow-type visual builder. There is nothing else to build one for
yet; revisit if a second real workflow type is ever added.
"""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.audit import record_audit_event
from gds_api.db import get_db
from gds_api.events import publish_mission_event
from gds_api.models import CapabilityRequestRecord, Mission, WorkflowRun, Workspace
from gds_api.reconciliation import reconcile_tenant_workflows
from gds_api.schemas import (
    CapabilityRequestWithDecisionOut,
    WorkflowReconciliationFindingOut,
    WorkflowReconciliationReportOut,
    WorkflowRunOut,
    WorkspaceOut,
)
from gds_api.security import CurrentUser, require_permission
from gds_api.temporal_client import get_temporal_client
from gds_api.workflow_sync import TEMPORAL_STATUS_NAMES

router = APIRouter(prefix="/workflows", tags=["workflows"])


def workflow_run_to_out(
    run: WorkflowRun, mission: Mission, *, temporal_status: str | None = None
) -> WorkflowRunOut:
    return WorkflowRunOut(
        id=run.id,
        mission_id=run.mission_id,
        mission_objective=mission.objective,
        mission_status=mission.status,
        conversation_thread_id=run.conversation_thread_id,
        temporal_workflow_id=run.temporal_workflow_id,
        temporal_run_id=run.temporal_run_id,
        status=run.status,
        current_stage=run.current_stage,
        retry_count=run.retry_count,
        started_at=run.started_at,
        last_progress_at=run.last_progress_at,
        completed_at=run.completed_at,
        failed_at=run.failed_at,
        cancelled_at=run.cancelled_at,
        failure_message_safe=run.failure_message_safe,
        reconciliation_state=run.reconciliation_state,
        can_cancel=run.status == "running",
        is_live=run.status == "running",
        temporal_status=temporal_status,
    )


async def _load_run(
    db: AsyncSession, tenant_id: uuid.UUID, workflow_run_id: uuid.UUID
) -> tuple[WorkflowRun, Mission]:
    run = await db.get(WorkflowRun, workflow_run_id)
    if run is None or run.tenant_id != tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Workflow run not found")
    mission = await db.get(Mission, run.mission_id)
    if mission is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Workflow run not found")
    return run, mission


@router.get("", response_model=list[WorkflowRunOut])
async def list_workflow_runs(
    current_user: CurrentUser = Depends(require_permission("workflows:read")),
    db: AsyncSession = Depends(get_db),
) -> list[WorkflowRunOut]:
    rows = (
        await db.execute(
            select(WorkflowRun, Mission)
            .join(Mission, WorkflowRun.mission_id == Mission.id)
            .where(WorkflowRun.tenant_id == current_user.tenant_id)
            .order_by(WorkflowRun.started_at.desc())
        )
    ).all()
    return [workflow_run_to_out(run, mission) for run, mission in rows]


@router.get(
    "/{workflow_run_id}/capability-requests",
    response_model=list[CapabilityRequestWithDecisionOut],
)
async def list_workflow_run_capability_requests(
    workflow_run_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("workflows:read")),
    db: AsyncSession = Depends(get_db),
) -> list[CapabilityRequestWithDecisionOut]:
    from gds_api.capabilities_api import _decision_to_out, _latest_decision, _request_to_out

    run, _mission = await _load_run(db, current_user.tenant_id, workflow_run_id)
    requests = (
        (
            await db.execute(
                select(CapabilityRequestRecord)
                .where(CapabilityRequestRecord.workflow_run_id == run.id)
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


@router.get("/{workflow_run_id}/workspaces", response_model=list[WorkspaceOut])
async def list_workflow_run_workspaces(
    workflow_run_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("workflows:read")),
    db: AsyncSession = Depends(get_db),
) -> list[WorkspaceOut]:
    """Phase 17, Part 14: the Workflow Repository Panel."""
    from gds_api.repository_api import _workspace_to_out

    run, _mission = await _load_run(db, current_user.tenant_id, workflow_run_id)
    rows = (
        (
            await db.execute(
                select(Workspace)
                .where(Workspace.workflow_run_id == run.id)
                .order_by(Workspace.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return [_workspace_to_out(w) for w in rows]


@router.get("/{workflow_run_id}", response_model=WorkflowRunOut)
async def get_workflow_run(
    workflow_run_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("workflows:read")),
    db: AsyncSession = Depends(get_db),
) -> WorkflowRunOut:
    run, mission = await _load_run(db, current_user.tenant_id, workflow_run_id)

    temporal_status: str | None = None
    client = await get_temporal_client()
    try:
        handle = client.get_workflow_handle(run.temporal_workflow_id, run_id=run.temporal_run_id)
        description = await handle.describe()
        if description.status is not None:
            temporal_status = TEMPORAL_STATUS_NAMES.get(description.status, str(description.status))
    except Exception:  # noqa: BLE001 - a Temporal lookup failure shouldn't 500 the page;
        # surface it as "unknown" rather than crash the detail view.
        temporal_status = "unknown"

    return workflow_run_to_out(run, mission, temporal_status=temporal_status)


@router.post("/{workflow_run_id}/cancel", response_model=WorkflowRunOut)
async def cancel_workflow_run(
    workflow_run_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("workflows:manage")),
    db: AsyncSession = Depends(get_db),
) -> WorkflowRunOut:
    """Phase 15: now also updates Mission.status - previously only WorkflowRun.status
    was ever touched here, leaving the Mission row showing whatever it last had (usually
    "planning", since Mission.status had no real "running" tracking before this phase
    either). Deliberately synchronous, not left to in-workflow cancellation-handling
    code - see docs/architecture/mission-workflow-lifecycle.md's "Cancellation
    semantics" for why."""
    run, mission = await _load_run(db, current_user.tenant_id, workflow_run_id)
    if run.status not in ("running",):
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"Workflow run is already {run.status}, cannot cancel"
        )

    client = await get_temporal_client()
    handle = client.get_workflow_handle(run.temporal_workflow_id, run_id=run.temporal_run_id)
    await handle.cancel()

    now = datetime.now(UTC)
    run.status = "canceled"
    run.cancelled_at = now
    run.status_version += 1
    mission.status = "cancelled"
    mission.cancelled_at = now
    mission.completed_at = now
    await record_audit_event(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="workflow.canceled",
        detail={"workflow_run_id": str(run.id), "mission_id": str(run.mission_id)},
    )
    await db.commit()
    await db.refresh(run)
    await db.refresh(mission)
    # So a real open SSE tab (streaming.py) sees the cancellation immediately, instead of
    # waiting for the polling fallback - the same terminal event synthesize_report and
    # mark_mission_failed already publish on their own real completion paths.
    await publish_mission_event(str(mission.id), "mission_finished", status="cancelled")

    return workflow_run_to_out(run, mission)


@router.post("/{workflow_run_id}/reconcile", response_model=WorkflowReconciliationReportOut)
async def reconcile_one_workflow_run(
    workflow_run_id: uuid.UUID,
    dry_run: bool = True,
    current_user: CurrentUser = Depends(require_permission("workflows:manage")),
    db: AsyncSession = Depends(get_db),
) -> WorkflowReconciliationReportOut:
    """RBAC-restricted (workflows:manage, the same permission cancellation requires) and
    audited - every real repair writes a workflow.reconciled audit event (see
    gds_api.reconciliation._record_repair). Defaults to dry_run=True so a client must
    explicitly opt into applying repairs."""
    run, _mission = await _load_run(db, current_user.tenant_id, workflow_run_id)
    findings = await reconcile_tenant_workflows(
        db, current_user.tenant_id, dry_run=dry_run, actor_user_id=current_user.user_id
    )
    relevant = [f for f in findings if f.workflow_run_id == run.id]
    return WorkflowReconciliationReportOut(
        dry_run=dry_run,
        checked_count=1,
        findings=[
            WorkflowReconciliationFindingOut(
                workflow_run_id=f.workflow_run_id,
                mission_id=f.mission_id,
                issue=f.issue,
                detail=f.detail,
                repaired=f.repaired,
            )
            for f in relevant
        ],
    )


@router.post("/reconcile", response_model=WorkflowReconciliationReportOut)
async def reconcile_all_workflows(
    dry_run: bool = True,
    current_user: CurrentUser = Depends(require_permission("workflows:manage")),
    db: AsyncSession = Depends(get_db),
) -> WorkflowReconciliationReportOut:
    """Tenant-wide reconciliation - RBAC-restricted and audited, same as the single-run
    endpoint above. Defaults to dry_run=True."""
    findings = await reconcile_tenant_workflows(
        db, current_user.tenant_id, dry_run=dry_run, actor_user_id=current_user.user_id
    )
    checked = (
        await db.execute(select(WorkflowRun).where(WorkflowRun.tenant_id == current_user.tenant_id))
    ).scalars()
    checked_count = len(list(checked))
    return WorkflowReconciliationReportOut(
        dry_run=dry_run,
        checked_count=checked_count,
        findings=[
            WorkflowReconciliationFindingOut(
                workflow_run_id=f.workflow_run_id,
                mission_id=f.mission_id,
                issue=f.issue,
                detail=f.detail,
                repaired=f.repaired,
            )
            for f in findings
        ],
    )
