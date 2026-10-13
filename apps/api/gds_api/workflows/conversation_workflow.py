"""ConversationTurnWorkflow: Phase 10.3's real chat turn. Deliberately thin - reuses the
exact same shared reasoning_loop.run_reasoning_loop MissionWorkflow uses, since a chat
turn is a real Mission underneath (see gds_api.models.Mission.conversation_thread_id).
Bounded to fewer iterations than a full mission (a chat reply should be quick, not an
open-ended autonomous run) - see docs/adr/0010.

Phase 11: deliberately does NOT call assess_mission (unlike MissionWorkflow) - its
output (mission.risk_class, working-memory intent) is real waste for a chat turn.
Verified before removing: conversations/[id]/page.tsx never renders mission.risk_class
(only the mastermind mission page does), and task-level approval gating always uses
tool_gateway.TOOL_REGISTRY's authoritative risk_class via
activities._resolve_task_risk_class, never the mission-level one - so a chat turn's
safety posture is unaffected. This cuts one full sequential real Anthropic round trip
off every chat turn, which previously ran even for a one-word greeting.
"""

from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from gds_api.workflows import reasoning_loop

# Deliberately lower than MissionWorkflow's _MAX_ITERATIONS (5) - a chat reply should be
# a quick, bounded exchange, not a long autonomous run. See docs/adr/0010.
_MAX_ITERATIONS = 3


@workflow.defn
class ConversationTurnWorkflow:
    @workflow.run
    async def run(self, mission_id: str) -> None:
        await reasoning_loop.run_reasoning_loop(mission_id, max_iterations=_MAX_ITERATIONS)
