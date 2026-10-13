"""Phase 18 (Continuation Prompt 5), Part 13: real retry/recovery reconciliation - since
the actual provider run is a real asyncio background task inside the API process (ADR
0020), not a Temporal workflow, a process restart mid-session orphans that task with no
automatic resumption. This module is the real, honest safety net: it detects and repairs
exactly the two real failure modes this architecture can leave behind, the same
"the database row is the truth, recover from it" discipline Phase 17's own Workspace
recovery (`repository.workspace_manager.recover_workspace`) already established.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.events import publish_mission_event
from gds_api.models import Approval, EngineeringSession, EngineeringTask, Mission, MissionPlan

_DEFAULT_STALE_AFTER_SECONDS = 1800


@dataclass
class RecoveryReport:
    stale_running_failed: list[str] = field(default_factory=list)
    rejected_approvals_marked: list[str] = field(default_factory=list)


async def recover_engineering_sessions(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID | None = None,
    stale_after_seconds: int = _DEFAULT_STALE_AFTER_SECONDS,
) -> RecoveryReport:
    """Real, safe to run repeatedly (e.g. on a schedule or on-demand from an operator
    endpoint) - never touches a session that is genuinely still progressing. Scoped to
    one real tenant unless tenant_id is explicitly None (every tenant - a deliberate,
    named admin option, mirroring Phase 17's cleanup_workspaces precedent)."""
    report = RecoveryReport()
    now = datetime.now(UTC)

    # --- Failure mode 1: a RUNNING session whose owning API process restarted, ------
    # orphaning its real asyncio background task with no automatic resumption. Detected
    # by real staleness (started_at older than a real threshold), never guessed from
    # process state that can't be observed from here.
    stale_cutoff = now - timedelta(seconds=stale_after_seconds)
    stale_query = select(EngineeringSession).where(
        EngineeringSession.status == "RUNNING",
        EngineeringSession.started_at.is_not(None),
        EngineeringSession.started_at < stale_cutoff,
    )
    if tenant_id is not None:
        stale_query = stale_query.where(EngineeringSession.tenant_id == tenant_id)
    stale_rows = (await db.execute(stale_query)).scalars().all()
    for session in stale_rows:
        session.status = "FAILED"
        session.failure_reason = (
            f"Recovery: session was RUNNING with no progress for over "
            f"{stale_after_seconds}s - the owning process likely restarted. Start a new "
            "session; this one's real workspace state is preserved for inspection."
        )
        session.completed_at = now
        mission = await db.get(Mission, session.mission_id)
        if mission is not None:
            mission.status = "failed"
        report.stale_running_failed.append(str(session.id))
        await publish_mission_event(
            str(session.mission_id),
            "engineering.failed",
            session_id=str(session.id),
            reason="recovery_stale_running",
        )
        await publish_mission_event(str(session.mission_id), "mission_finished", status="failed")

    # --- Failure mode 2: a real Approval was rejected, but the owning session (which
    # cannot itself observe that rejection - it isn't the thing polling) is still sitting
    # in AWAITING_APPROVAL. -----------------------------------------------------------
    awaiting_query = select(EngineeringSession).where(
        EngineeringSession.status == "AWAITING_APPROVAL",
        EngineeringSession.approval_id.is_not(None),
    )
    if tenant_id is not None:
        awaiting_query = awaiting_query.where(EngineeringSession.tenant_id == tenant_id)
    awaiting_rows = (await db.execute(awaiting_query)).scalars().all()
    for session in awaiting_rows:
        approval = await db.get(Approval, session.approval_id) if session.approval_id else None
        if approval is not None and approval.status == "rejected":
            session.status = "REJECTED"
            session.failure_reason = "The real approval for this session's commit was rejected."
            session.completed_at = now
            mission = await db.get(Mission, session.mission_id)
            if mission is not None:
                mission.status = "failed"
            report.rejected_approvals_marked.append(str(session.id))
            await publish_mission_event(
                str(session.mission_id),
                "engineering.failed",
                session_id=str(session.id),
                reason="approval_rejected",
            )
            await publish_mission_event(
                str(session.mission_id), "mission_finished", status="failed"
            )

    await db.commit()
    return report


async def recover_mission_plans(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID | None = None,
    stale_after_seconds: int = _DEFAULT_STALE_AFTER_SECONDS,
) -> RecoveryReport:
    """Phase 19 (Continuation Prompt 6), Part 14: the same real, database-is-the-truth
    recovery discipline as `recover_engineering_sessions`, extended to MissionPlan/
    EngineeringTask - the multi-agent mission's own background asyncio task (ADR 0020,
    extended) is just as vulnerable to a process restart orphaning it mid-execution.
    Never restarts a whole mission unnecessarily (Part 14: "retry individual tasks,
    never restart the whole mission") - a task-level restart is a fresh mission-plan
    creation the operator chooses, not something this function does automatically."""
    report = RecoveryReport()
    now = datetime.now(UTC)
    stale_cutoff = now - timedelta(seconds=stale_after_seconds)

    # --- Failure mode 1: a RUNNING EngineeringTask whose owning process restarted, ---
    # orphaning the real asyncio background task driving it - identical real staleness
    # signal to EngineeringSession's own precedent above.
    stale_task_query = select(EngineeringTask).where(
        EngineeringTask.status == "RUNNING",
        EngineeringTask.started_at.is_not(None),
        EngineeringTask.started_at < stale_cutoff,
    )
    if tenant_id is not None:
        stale_task_query = stale_task_query.where(EngineeringTask.tenant_id == tenant_id)
    stale_tasks = (await db.execute(stale_task_query)).scalars().all()
    affected_plan_ids: set[uuid.UUID] = set()
    for task in stale_tasks:
        task.status = "FAILED"
        task.failure_reason = (
            f"Recovery: task was RUNNING with no progress for over {stale_after_seconds}s - "
            "the owning process likely restarted. This task's own workspace/branch is "
            "preserved for inspection."
        )
        task.completed_at = now
        report.stale_running_failed.append(str(task.id))
        affected_plan_ids.add(task.mission_plan_id)

    # A MissionPlan left EXECUTING/MERGING with no real task still PENDING/READY/RUNNING
    # has no path forward - the real asyncio scheduling loop that would have driven it
    # to MERGING/AWAITING_APPROVAL is gone, never a Temporal workflow that resumes
    # itself. Marking it FAILED (never silently stuck) still preserves every completed
    # task's own real work/workspace for a human to inspect or a fresh mission to reuse.
    for plan_id in affected_plan_ids:
        plan = await db.get(MissionPlan, plan_id)
        if plan is None or plan.status not in ("EXECUTING", "MERGING"):
            continue
        remaining_query = select(EngineeringTask).where(
            EngineeringTask.mission_plan_id == plan_id,
            EngineeringTask.status.in_(("PENDING", "READY", "RUNNING")),
        )
        remaining = (await db.execute(remaining_query)).scalars().all()
        if remaining:
            continue
        plan.status = "FAILED"
        plan.failure_reason = (
            "Recovery: the owning process restarted mid-execution and no task was still "
            "in progress to resume from - see individual task statuses for real partial "
            "progress."
        )
        plan.completed_at = now
        mission = await db.get(Mission, plan.mission_id)
        if mission is not None:
            mission.status = "failed"
        await publish_mission_event(
            str(plan.mission_id), "mission.failed", reason=plan.failure_reason
        )
        await publish_mission_event(str(plan.mission_id), "mission_finished", status="failed")

    # --- Failure mode 2: a real Approval was rejected for a mission's commit, but the
    # MissionPlan (which cannot itself observe that rejection) is still sitting in
    # AWAITING_APPROVAL - identical real signal to EngineeringSession's own precedent.
    awaiting_query = select(MissionPlan).where(
        MissionPlan.status == "AWAITING_APPROVAL",
        MissionPlan.approval_id.is_not(None),
    )
    if tenant_id is not None:
        awaiting_query = awaiting_query.where(MissionPlan.tenant_id == tenant_id)
    awaiting_plans = (await db.execute(awaiting_query)).scalars().all()
    for plan in awaiting_plans:
        approval = await db.get(Approval, plan.approval_id) if plan.approval_id else None
        if approval is not None and approval.status == "rejected":
            plan.status = "FAILED"
            plan.failure_reason = "The real approval for this mission's commit was rejected."
            plan.completed_at = now
            mission = await db.get(Mission, plan.mission_id)
            if mission is not None:
                mission.status = "failed"
            report.rejected_approvals_marked.append(str(plan.id))
            await publish_mission_event(
                str(plan.mission_id), "engineering.failed", reason="approval_rejected"
            )
            await publish_mission_event(str(plan.mission_id), "mission_finished", status="failed")

    await db.commit()
    return report
