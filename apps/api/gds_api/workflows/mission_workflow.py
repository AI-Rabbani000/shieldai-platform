"""MissionWorkflow: Rabbani AI Core's orchestration of a single mission. Workflow code
stays deterministic (no direct I/O, per Temporal's rules) - it only sequences activities
and durably waits for human approval via a poll loop. All real work (LLM calls, DB
writes, tool execution) happens in activities.py. The actual step-by-step adaptive loop
lives in reasoning_loop.py (Phase 10.1) - shared with Phase 10.3's
ConversationTurnWorkflow - see that module's docstring for the loop's shape.
"""

from datetime import timedelta

from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from gds_api.workflows import activities, reasoning_loop

_ASSESS_TIMEOUT = timedelta(seconds=90)

# Bounds real Anthropic cost per mission and guards against a stuck loop. Started at 5
# (not higher) deliberately for the initial real-cost/behavior verification pass - see
# docs/adr/0009. Raise once real usage patterns are observed.
_MAX_ITERATIONS = 5


@workflow.defn
class MissionWorkflow:
    @workflow.run
    async def run(self, mission_id: str) -> None:
        await workflow.execute_activity(
            activities.assess_mission,
            mission_id,
            start_to_close_timeout=_ASSESS_TIMEOUT,
        )
        await reasoning_loop.run_reasoning_loop(mission_id, max_iterations=_MAX_ITERATIONS)
