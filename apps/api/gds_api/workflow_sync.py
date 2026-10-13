"""Phase 15 (Continuation Prompt 2): the one shared function that keeps WorkflowRun in
sync with a Mission's real lifecycle. Used by both gds_api.workflows.activities (from
inside real Temporal activities, as each real lifecycle event happens) and
gds_api.reconciliation (from a plain FastAPI request/scheduled-job context, when
repairing drift after the fact) - kept in its own module rather than living inside
activities.py so reconciliation.py doesn't need to import across the Temporal-activity
boundary for a function that isn't itself a Temporal activity.

See docs/architecture/mission-workflow-lifecycle.md for the status model this maintains
and docs/reviews/phase-15-workflow-lifecycle-audit.md findings 1-2 for why this never
existed before this phase.
"""

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from temporalio.client import WorkflowExecutionStatus

from gds_api.models import Mission, WorkflowRun

# The one shared mapping from Temporal's real WorkflowExecutionStatus enum to this
# codebase's lowercase status strings - previously duplicated separately in
# workflow_runs.py and reconciliation.py; centralized here so the two can never drift
# out of sync with each other.
TEMPORAL_STATUS_NAMES: dict[WorkflowExecutionStatus, str] = {
    WorkflowExecutionStatus.RUNNING: "running",
    WorkflowExecutionStatus.COMPLETED: "completed",
    WorkflowExecutionStatus.FAILED: "failed",
    WorkflowExecutionStatus.CANCELED: "canceled",
    WorkflowExecutionStatus.TERMINATED: "terminated",
    WorkflowExecutionStatus.CONTINUED_AS_NEW: "continued_as_new",
    WorkflowExecutionStatus.TIMED_OUT: "timed_out",
}


async def sync_workflow_run(
    db: AsyncSession,
    mission: Mission,
    *,
    status: str | None = None,
    current_stage: str | None = None,
    completed_at: datetime | None = None,
    failed_at: datetime | None = None,
    failure_message_safe: str | None = None,
) -> None:
    """Deliberately tolerant of a missing WorkflowRun row (a legacy chat mission created
    before this phase, or a genuinely orphaned Mission) - that gap is what the
    reconciliation service surfaces and repairs, not something this sync function should
    paper over by fabricating a row. Does not commit - callers fold this into their own
    existing transaction."""
    run = (
        await db.execute(select(WorkflowRun).where(WorkflowRun.mission_id == mission.id))
    ).scalar_one_or_none()
    if run is None:
        return
    run.status_version += 1
    run.last_progress_at = datetime.now(UTC)
    if status is not None:
        run.status = status
    if current_stage is not None:
        run.current_stage = current_stage
    if completed_at is not None:
        run.completed_at = completed_at
    if failed_at is not None:
        run.failed_at = failed_at
    if failure_message_safe is not None:
        run.failure_message_safe = failure_message_safe[:500]
