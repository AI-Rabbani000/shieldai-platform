"""Phase 15 (Continuation Prompt 2), Part D: the one canonical function that starts a
Mission's real Temporal workflow and creates its WorkflowRun row.

Before this phase, apps/api/src/gds_api/missions.py's create_mission and
apps/api/src/gds_api/conversations.py's send_message each inlined their own
start-workflow-then-create-WorkflowRun logic - and conversations.py's copy silently
omitted the WorkflowRun creation entirely (the real defect
docs/reviews/phase-15-workflow-lifecycle-audit.md's finding 3 root-caused). Routing both
through this one function means that specific class of divergence can't recur: there is
now exactly one place a WorkflowRun gets created, and it always runs.

Audit-event creation deliberately stays in each caller, not here - "mission.created" and
"conversation.message_sent" carry meaningfully different detail payloads (objective vs.
thread_id+message), and collapsing them into one generic audit action would be a real
loss of audit specificity, not a simplification. What was actually duplicated - and
actually buggy - was the Temporal-start + WorkflowRun-creation pair, so that's what this
function owns.
"""

from typing import Any, Literal

from sqlalchemy.ext.asyncio import AsyncSession
from temporalio.client import WorkflowHandle

from gds_api.models import Mission, WorkflowRun
from gds_api.temporal_client import TASK_QUEUE, get_temporal_client
from gds_api.workflows.conversation_workflow import ConversationTurnWorkflow
from gds_api.workflows.mission_workflow import MissionWorkflow

MissionKind = Literal["direct", "chat"]


async def start_mission_workflow(
    db: AsyncSession, mission: Mission, *, kind: MissionKind
) -> WorkflowRun:
    """`mission` must already be added to `db` and flushed (so `mission.id` is real) but
    not yet committed - the caller commits once, after this returns, so the Mission and
    its WorkflowRun land in the same transaction. Idempotency: Temporal itself rejects a
    second start_workflow call reusing the same deterministic workflow ID
    (`mission-{id}` / `conversation-turn-{id}`) with WorkflowAlreadyStartedError - since
    `mission.id` is a fresh UUID minted once per Mission row, this protects against ever
    starting two real Temporal executions for the same Mission, though it does not (and
    cannot) protect against two distinct Missions being created by a genuine duplicate
    API request - see the audit doc's "Scope boundary" section for why full
    idempotency-key infrastructure was judged out of scope this phase. The database's
    own UNIQUE constraint on workflow_runs.mission_id is the backstop against ever
    getting two WorkflowRun rows for one mission, regardless."""
    client = await get_temporal_client()
    handle: WorkflowHandle[Any, Any]
    if kind == "direct":
        handle = await client.start_workflow(
            MissionWorkflow.run,
            str(mission.id),
            id=f"mission-{mission.id}",
            task_queue=TASK_QUEUE,
        )
    else:
        handle = await client.start_workflow(
            ConversationTurnWorkflow.run,
            str(mission.id),
            id=f"conversation-turn-{mission.id}",
            task_queue=TASK_QUEUE,
        )

    run = WorkflowRun(
        mission_id=mission.id,
        tenant_id=mission.tenant_id,
        conversation_thread_id=mission.conversation_thread_id,
        temporal_workflow_id=handle.id,
        temporal_run_id=handle.run_id or "",
    )
    db.add(run)
    await db.flush()
    return run
