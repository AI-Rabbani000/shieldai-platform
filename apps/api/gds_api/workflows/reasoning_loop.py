"""Phase 10.1's shared iterative reasoning loop, used by both MissionWorkflow and (Phase
10.3) ConversationTurnWorkflow. Extracted into a plain function - not a separate
@workflow.defn - so both workflow types get the exact same adaptive step-by-step
behavior without duplicating the loop body or forcing chat through a second, parallel
execution engine. Workflow code calling a plain shared coroutine like this is normal,
idiomatic Temporal usage; the determinism rule is about avoiding direct I/O/randomness in
workflow code, not about how many files that code is split across.

Each iteration: decide_next_step (one real LLM call deciding the single next action,
given the real transcript of every prior step and its real result) -> if the model says
the mission is finished, stop -> otherwise evaluate_task (real policy check, may create a
real Approval) -> durably wait for approval if required -> execute_task (the real tool/
agent call). Bounded by max_iterations to control real Anthropic cost and guard against a
stuck loop that keeps proposing actions without making real progress - both denial and
non-approval outcomes still consume an iteration for the same reason.
"""

from datetime import timedelta

from temporalio import workflow
from temporalio.exceptions import CancelledError

with workflow.unsafe.imports_passed_through():
    from gds_api.workflows import activities

_SHORT_TIMEOUT = timedelta(seconds=15)
_DEFAULT_TIMEOUT = timedelta(seconds=90)
_APPROVAL_POLL_INTERVAL = timedelta(seconds=5)
_APPROVAL_TIMEOUT = timedelta(minutes=10)


async def run_reasoning_loop(mission_id: str, *, max_iterations: int) -> None:
    """Phase 15: now wrapped in a try/except so a real activity failure (exhausted
    Temporal retries, a timeout) actually marks the Mission/WorkflowRun failed - see
    docs/reviews/phase-15-workflow-lifecycle-audit.md finding 2. CancelledError is caught
    and re-raised WITHOUT calling mark_mission_failed: a real cancellation is handled
    synchronously by the POST /workflows/{id}/cancel endpoint itself (which sets
    Mission.status="cancelled" before requesting Temporal cancellation) - marking it
    failed here would be a real race that could overwrite a correct "cancelled" outcome
    with an incorrect "failed" one. Both branches re-raise afterward so Temporal's own
    execution history still shows the real outcome too - nothing is hidden from it."""
    try:
        await _run_reasoning_loop_inner(mission_id, max_iterations=max_iterations)
    except CancelledError:
        raise
    except Exception as exc:
        # A real activity failure arrives here wrapped as ActivityError, whose own
        # str() is a generic "Activity task failed" - the actual real error text lives
        # on .cause (confirmed via a live WorkflowEnvironment test during this phase's
        # own verification; the first version of this code used str(exc) directly and
        # silently lost the real error message). Falls back to str(exc) for any
        # exception type that doesn't carry a .cause, so nothing is ever left blank.
        cause = getattr(exc, "cause", None)
        detail = str(cause) if cause is not None else str(exc)
        await workflow.execute_activity(
            activities.mark_mission_failed,
            {"mission_id": mission_id, "error_message_safe": detail},
            start_to_close_timeout=_SHORT_TIMEOUT,
        )
        raise


async def _run_reasoning_loop_inner(mission_id: str, *, max_iterations: int) -> None:
    step_count = 0
    hit_iteration_limit = False

    while True:
        if step_count >= max_iterations:
            hit_iteration_limit = True
            break

        decision = await workflow.execute_activity(
            activities.decide_next_step,
            {"mission_id": mission_id},
            start_to_close_timeout=_DEFAULT_TIMEOUT,
        )
        if decision["action"] == "finish":
            break

        task_id = decision["task_id"]
        evaluation = await workflow.execute_activity(
            activities.evaluate_task,
            task_id,
            start_to_close_timeout=_SHORT_TIMEOUT,
        )

        if evaluation["decision"] == "deny":
            await workflow.execute_activity(
                activities.deny_task, task_id, start_to_close_timeout=_SHORT_TIMEOUT
            )
            step_count += 1
            continue

        if evaluation["decision"] == "require_approval":
            approval_id = evaluation["approval_id"]
            deadline = workflow.now() + _APPROVAL_TIMEOUT
            status = "pending"
            while status == "pending" and workflow.now() < deadline:
                await workflow.sleep(_APPROVAL_POLL_INTERVAL)
                status = await workflow.execute_activity(
                    activities.check_approval,
                    args=[approval_id],
                    start_to_close_timeout=_SHORT_TIMEOUT,
                )
            if status != "approved":
                await workflow.execute_activity(
                    activities.deny_task, task_id, start_to_close_timeout=_SHORT_TIMEOUT
                )
                step_count += 1
                continue

        await workflow.execute_activity(
            activities.execute_task,
            task_id,
            start_to_close_timeout=_DEFAULT_TIMEOUT,
        )
        step_count += 1

    await workflow.execute_activity(
        activities.synthesize_report,
        {"mission_id": mission_id, "hit_iteration_limit": hit_iteration_limit},
        start_to_close_timeout=_DEFAULT_TIMEOUT,
    )
