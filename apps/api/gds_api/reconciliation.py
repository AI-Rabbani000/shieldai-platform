"""Phase 15 (Continuation Prompt 2), Part H: detects and, for safe/deterministic cases,
repairs disagreement between Mission.status, WorkflowRun.status, and Temporal's own real
execution status. See docs/architecture/workflow-reconciliation.md for the full design
and docs/reviews/phase-15-workflow-lifecycle-audit.md for why this was needed.

Deliberately Postgres-driven (iterates real Mission/WorkflowRun rows in this tenant),
not a full reverse scan of every Temporal execution ever started - every real Temporal
execution in this codebase is now started exclusively through
gds_api.mission_lifecycle.start_mission_workflow, which always creates a WorkflowRun row
in the same transaction, so "a real Temporal execution exists with no WorkflowRun at
all" cannot occur going forward for any execution started after this phase. A full
reverse scan (enumerating Temporal's own execution list and cross-checking each against
Postgres) was considered and left out of scope - see ADR 0013's "Alternatives rejected"
for why.
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.audit import record_audit_event
from gds_api.models import Mission, WorkflowRun
from gds_api.temporal_client import get_temporal_client
from gds_api.workflow_sync import TEMPORAL_STATUS_NAMES, sync_workflow_run

# A "running" WorkflowRun with no real progress in this long is flagged STALLED - never
# auto-repaired (it may simply be a genuinely slow real mission), just surfaced for
# administrative review. 60 minutes is well beyond the longest real durable wait this
# platform has (the 10-minute approval-poll timeout in reasoning_loop.py).
_STALLED_THRESHOLD = timedelta(minutes=60)

_TERMINAL_MISSION_STATUSES = ("completed", "failed", "cancelled")
_LEGAL_WORKFLOW_RUN_STATUSES = ("running", "completed", "failed", "canceled", "orphaned")

# A stable sentinel used only for the MISSING_WORKFLOW finding, where by definition no
# real WorkflowRun row/id exists to report - never persisted, never used to look
# anything up.
_NO_WORKFLOW_RUN_SENTINEL = uuid.UUID(int=0)


@dataclass
class ReconciliationFinding:
    workflow_run_id: uuid.UUID
    mission_id: uuid.UUID
    issue: str
    detail: str
    repaired: bool


async def reconcile_tenant_workflows(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    *,
    dry_run: bool,
    actor_user_id: uuid.UUID | None,
) -> list[ReconciliationFinding]:
    findings: list[ReconciliationFinding] = []

    missions = (
        (await db.execute(select(Mission).where(Mission.tenant_id == tenant_id))).scalars().all()
    )
    runs = (
        await db.execute(
            select(WorkflowRun, Mission)
            .join(Mission, WorkflowRun.mission_id == Mission.id)
            .where(WorkflowRun.tenant_id == tenant_id)
        )
    ).all()
    mission_ids_with_run = {run.mission_id for run, _ in runs}

    # 1. Missions with no WorkflowRun row at all (MISSING_WORKFLOW). Never auto-repaired
    # here - fabricating a WorkflowRun with invented Temporal IDs would violate "do not
    # fabricate workflow progress." Real repair for pre-existing legacy rows is a
    # separate, explicit, disclosed procedure - docs/operations/workflow-repair.md.
    for mission in missions:
        if mission.id not in mission_ids_with_run:
            findings.append(
                ReconciliationFinding(
                    workflow_run_id=_NO_WORKFLOW_RUN_SENTINEL,
                    mission_id=mission.id,
                    issue="MISSING_WORKFLOW",
                    detail=f"Mission status={mission.status!r} has no WorkflowRun row.",
                    repaired=False,
                )
            )

    # 2. Duplicate WorkflowRun rows per mission - defensive; the DB UNIQUE constraint on
    # workflow_runs.mission_id should make this impossible, checked anyway since a
    # reconciler that assumes its own invariants are unbreakable isn't a real safety net.
    seen_mission_ids: set[uuid.UUID] = set()
    for run, _mission in runs:
        if run.mission_id in seen_mission_ids:
            findings.append(
                ReconciliationFinding(
                    workflow_run_id=run.id,
                    mission_id=run.mission_id,
                    issue="DUPLICATED",
                    detail="More than one WorkflowRun row exists for this mission.",
                    repaired=False,
                )
            )
        seen_mission_ids.add(run.mission_id)

    client = await get_temporal_client()

    for run, mission in runs:
        # 3. Invalid/unrecognized status value.
        if run.status not in _LEGAL_WORKFLOW_RUN_STATUSES:
            findings.append(
                ReconciliationFinding(
                    workflow_run_id=run.id,
                    mission_id=mission.id,
                    issue="INVALID_STATUS",
                    detail=f"WorkflowRun.status={run.status!r} is not a recognized value.",
                    repaired=False,
                )
            )
            continue

        # 4. Mission is terminal but WorkflowRun still says "running" - safe, deterministic
        # repair: Postgres's own Mission row is the authoritative durable application
        # state (see docs/architecture/mission-workflow-lifecycle.md's source-of-truth
        # hierarchy), so mirroring WorkflowRun to it is not a guess.
        if mission.status in _TERMINAL_MISSION_STATUSES and run.status == "running":
            detail = f"Mission is {mission.status!r} but WorkflowRun still shows 'running'."
            if dry_run:
                findings.append(
                    ReconciliationFinding(run.id, mission.id, "DRIFTED", detail, repaired=False)
                )
            else:
                target_status = "canceled" if mission.status == "cancelled" else mission.status
                await sync_workflow_run(
                    db,
                    mission,
                    status=target_status,
                    completed_at=mission.completed_at if mission.status == "completed" else None,
                    failed_at=mission.completed_at if mission.status == "failed" else None,
                )
                if mission.status == "cancelled":
                    run.cancelled_at = mission.cancelled_at
                await _record_repair(
                    db, tenant_id, actor_user_id, run, mission, "drifted_terminal_mission"
                )
                findings.append(
                    ReconciliationFinding(run.id, mission.id, "DRIFTED", detail, repaired=True)
                )
            continue

        if run.status != "running":
            # Already terminal on both sides (or "orphaned", which only the reconciler
            # itself sets and which requires a human to clear) - nothing further to check.
            continue

        # From here, run.status == "running" and mission.status is not yet terminal -
        # cross-check against Temporal's own real, authoritative execution status.
        try:
            handle = client.get_workflow_handle(
                run.temporal_workflow_id, run_id=run.temporal_run_id
            )
            description = await handle.describe()
            temporal_status = (
                TEMPORAL_STATUS_NAMES.get(description.status)
                if description.status is not None
                else None
            )
        except Exception:  # noqa: BLE001 - Temporal unreachable or execution gone; both
            # mean "can't confirm", handled identically below (temporal_status is None).
            temporal_status = None

        if temporal_status is None:
            # 5. Temporal can't describe this execution at all - ambiguous by definition
            # (unreachable Temporal vs. a truly gone execution look identical from here).
            # Never auto-repaired, even in repair mode - mark ORPHANED and require review.
            detail = (
                "Temporal could not describe this execution "
                "(unreachable, or the execution no longer exists)."
            )
            if not dry_run:
                run.status = "orphaned"
                run.status_version += 1
                await _record_repair(
                    db,
                    tenant_id,
                    actor_user_id,
                    run,
                    mission,
                    "marked_orphaned_missing_temporal_execution",
                )
            findings.append(
                ReconciliationFinding(
                    run.id, mission.id, "MISSING_TEMPORAL_EXECUTION", detail, repaired=not dry_run
                )
            )
        elif temporal_status == "completed":
            # 6. Temporal is authoritative that this execution finished, but our own
            # Mission row never reflected it - a narrow legacy/partial-write gap (see
            # the Phase 15 audit). Safe to repair using Temporal's own real close_time.
            detail = (
                "Temporal reports this execution completed, "
                "but Mission/WorkflowRun still show 'running'."
            )
            if dry_run:
                findings.append(
                    ReconciliationFinding(run.id, mission.id, "DRIFTED", detail, repaired=False)
                )
            else:
                completed_at = description.close_time or datetime.now(UTC)
                mission.status = "completed"
                mission.completed_at = completed_at
                await sync_workflow_run(db, mission, status="completed", completed_at=completed_at)
                await _record_repair(
                    db, tenant_id, actor_user_id, run, mission, "repaired_from_temporal_completed"
                )
                findings.append(
                    ReconciliationFinding(run.id, mission.id, "DRIFTED", detail, repaired=True)
                )
        elif temporal_status in ("failed", "timed_out", "terminated"):
            # 7. Same principle for a real Temporal-side failure/timeout/termination.
            detail = (
                f"Temporal reports this execution {temporal_status}, "
                "but Mission/WorkflowRun still show 'running'."
            )
            if dry_run:
                findings.append(
                    ReconciliationFinding(run.id, mission.id, "DRIFTED", detail, repaired=False)
                )
            else:
                failed_at = description.close_time or datetime.now(UTC)
                mission.status = "failed"
                mission.completed_at = failed_at
                await sync_workflow_run(
                    db,
                    mission,
                    status="failed",
                    failed_at=failed_at,
                    failure_message_safe=f"Reconciled from real Temporal status: {temporal_status}",
                )
                await _record_repair(
                    db, tenant_id, actor_user_id, run, mission, "repaired_from_temporal_failed"
                )
                findings.append(
                    ReconciliationFinding(run.id, mission.id, "DRIFTED", detail, repaired=True)
                )
        elif temporal_status == "canceled" and mission.status != "cancelled":
            # 9 (part 1). Temporal itself confirms the cancellation actually completed -
            # safe to mirror, same reasoning as the completed/failed cases above.
            detail = (
                "Temporal reports this execution canceled, but Mission does not show 'cancelled'."
            )
            if dry_run:
                findings.append(
                    ReconciliationFinding(run.id, mission.id, "DRIFTED", detail, repaired=False)
                )
            else:
                cancelled_at = description.close_time or datetime.now(UTC)
                mission.status = "cancelled"
                mission.cancelled_at = cancelled_at
                await sync_workflow_run(db, mission, status="canceled")
                run.cancelled_at = cancelled_at
                await _record_repair(
                    db, tenant_id, actor_user_id, run, mission, "repaired_from_temporal_canceled"
                )
                findings.append(
                    ReconciliationFinding(run.id, mission.id, "DRIFTED", detail, repaired=True)
                )
        elif mission.status == "cancelled" and temporal_status == "running":
            # 9 (part 2). We asked Temporal to cancel (Mission already shows
            # "cancelled") but its execution is still genuinely running - ambiguous
            # (could be mid-teardown, or the cancel request never landed). Never
            # auto-repaired - re-issuing cancellation is a real action, not a data fix.
            findings.append(
                ReconciliationFinding(
                    run.id,
                    mission.id,
                    "DRIFTED",
                    "Mission is 'cancelled' but Temporal still reports the execution running.",
                    repaired=False,
                )
            )
        elif (
            run.last_progress_at is not None
            and datetime.now(UTC) - run.last_progress_at > _STALLED_THRESHOLD
        ):
            # 8. Genuinely still running on both sides, but no real progress in over an
            # hour - ambiguous (could be a legitimately slow mission), never auto-repaired.
            findings.append(
                ReconciliationFinding(
                    run.id,
                    mission.id,
                    "STALLED",
                    f"No progress recorded since {run.last_progress_at.isoformat()}.",
                    repaired=False,
                )
            )
        elif (
            run.last_progress_at is None and datetime.now(UTC) - run.started_at > _STALLED_THRESHOLD
        ):
            findings.append(
                ReconciliationFinding(
                    run.id,
                    mission.id,
                    "STALLED",
                    f"No progress ever recorded; started at {run.started_at.isoformat()}.",
                    repaired=False,
                )
            )
        # else: genuinely, currently, consistently running - CONSISTENT, no finding.

    if not dry_run and findings:
        await db.commit()

    return findings


async def _record_repair(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    actor_user_id: uuid.UUID | None,
    run: WorkflowRun,
    mission: Mission,
    reason: str,
) -> None:
    run.reconciliation_state = "REPAIRED"
    run.reconciled_at = datetime.now(UTC)
    await record_audit_event(
        db,
        tenant_id=tenant_id,
        user_id=actor_user_id,
        action="workflow.reconciled",
        detail={
            "workflow_run_id": str(run.id),
            "mission_id": str(mission.id),
            "reason": reason,
            "new_workflow_run_status": run.status,
            "new_mission_status": mission.status,
        },
    )
