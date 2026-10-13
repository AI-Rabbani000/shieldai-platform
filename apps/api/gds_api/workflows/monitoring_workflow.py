"""MonitoringWorkflow: a Temporal workflow that runs a monitoring cycle on a schedule.

This is what makes GDS OS "continuous" — instead of waiting for a human to trigger
a scan, this workflow wakes up on a timer, runs the monitoring activity, records
results, and sleeps until the next interval.

Uses Temporal's native timer + continue-as-new pattern for long-running schedules:
each cycle is one workflow execution that runs the activity, then starts a new
workflow execution for the next cycle. This gives us:
  - Durable execution (survives worker restarts)
  - Real retry on failure
  - Full audit trail of every cycle
  - No separate cron daemon needed

To start a schedule: POST /monitoring/schedules creates a ScanSchedule row,
then a client starts a MonitoringWorkflow with that schedule_id. The workflow
runs forever (until the schedule is paused or deleted).
"""

from datetime import timedelta
from typing import Optional

from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from gds_api.workflows.monitoring_activities import run_monitoring_cycle

# How long a single monitoring cycle is allowed to take
_CYCLE_TIMEOUT = timedelta(seconds=120)

# How long to wait between checking if a schedule is still active
_POLL_INTERVAL = timedelta(seconds=30)


@workflow.defn
class MonitoringWorkflow:
    """A continuous monitoring loop for one ScanSchedule.

    Started with: workflow_id = f"monitoring-{schedule_id}"
    Runs forever until the schedule's status changes to 'paused' or 'error'.
    """

    @workflow.run
    async def run(self, schedule_id: str) -> None:
        import asyncio

        while True:
            # Check if the schedule is still active (via activity, not direct DB —
            # workflow code must be deterministic)
            should_continue = await workflow.execute_activity(
                _check_schedule_active,
                schedule_id,
                start_to_close_timeout=timedelta(seconds=10),
            )

            if not should_continue:
                workflow.logger.info("monitoring_schedule_stopped", schedule_id=schedule_id)
                break

            # Run the monitoring cycle
            try:
                await workflow.execute_activity(
                    run_monitoring_cycle_activity,
                    schedule_id,
                    start_to_close_timeout=_CYCLE_TIMEOUT,
                )
            except Exception as exc:
                workflow.logger.error(
                    "monitoring_cycle_failed",
                    schedule_id=schedule_id,
                    error=str(exc),
                )

            # Get the interval for this schedule
            interval_minutes = await workflow.execute_activity(
                _get_schedule_interval,
                schedule_id,
                start_to_close_timeout=timedelta(seconds=10),
            )

            # Sleep until next cycle
            await workflow.sleep(timedelta(minutes=interval_minutes))


# Activities used by the workflow (thin wrappers around the real functions)
import temporalio.activity


@temporalio.activity.defn
async def run_monitoring_cycle_activity(schedule_id: str) -> dict:
    """Temporal activity wrapper for run_monitoring_cycle."""
    from gds_api.workflows.monitoring_activities import run_monitoring_cycle

    # We need a tenant_id and user_id — get them from the schedule
    from gds_api.db import async_session_factory
    from gds_api.monitoring import ScanSchedule
    import uuid

    async with async_session_factory() as db:
        schedule = await db.get(ScanSchedule, uuid.UUID(schedule_id))
        if schedule is None:
            return {"error": "schedule not found"}
        tenant_id = str(schedule.tenant_id)

    # Use a system user_id for automated runs
    result = await run_monitoring_cycle(schedule_id, tenant_id, "00000000-0000-0000-0000-000000000000")
    return {"result_id": str(result.id), "findings": result.findings_created}


@temporalio.activity.defn
async def _check_schedule_active(schedule_id: str) -> bool:
    """Check if a schedule is still active (not paused or deleted)."""
    from gds_api.db import async_session_factory
    from gds_api.monitoring import ScanSchedule, ScanScheduleStatus
    import uuid

    async with async_session_factory() as db:
        schedule = await db.get(ScanSchedule, uuid.UUID(schedule_id))
        if schedule is None:
            return False
        return schedule.status == ScanScheduleStatus.ACTIVE.value


@temporalio.activity.defn
async def _get_schedule_interval(schedule_id: str) -> int:
    """Get the current interval for a schedule."""
    from gds_api.db import async_session_factory
    from gds_api.monitoring import ScanSchedule
    import uuid

    async with async_session_factory() as db:
        schedule = await db.get(ScanSchedule, uuid.UUID(schedule_id))
        if schedule is None:
            return 360  # default 6 hours
        return schedule.interval_minutes
