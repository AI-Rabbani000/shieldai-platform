"""Phase 16 (Continuation Prompt 3), Part I: the Tool Gateway enforcement layer - the
one real place gds_api.tool_gateway.execute_tool is allowed to run for a
broker-governed capability request. Both real production entry points
(FoundationAgent.execute in gds_api.agents.manifest, and the Rabbani-direct branch in
gds_api.workflows.activities.execute_task - see docs/reviews/phase-16-capability-control
-audit.md's Entry Point A/B) call execute_capability_request() instead of
tool_gateway.execute_tool directly.

Re-evaluates the capability request immediately before executing - "never assume a
previously allowed decision remains safe indefinitely" - so a target authorization that
expired, an emergency stop engaged, or a capability disabled between proposal and
execution is caught right here, not just at proposal time. Only a fresh ALLOW may
proceed to a real tool call; anything else raises CapabilityExecutionDenied with the
decision's own safe, non-leaking message.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from gds_api import tool_gateway
from gds_api.capabilities.broker import mark_capability_execution, reevaluate_capability_request
from gds_api.models import CapabilityRequestRecord


class CapabilityExecutionDenied(Exception):
    def __init__(self, decision: str, denial_code: str | None, safe_message: str) -> None:
        self.decision = decision
        self.denial_code = denial_code
        self.safe_message = safe_message
        super().__init__(safe_message)


async def execute_capability_request(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    request_id: uuid.UUID,
    tool_name: str,
    input_data: dict[str, Any],
    user_id: uuid.UUID,
    mission_id: uuid.UUID,
) -> dict[str, Any]:
    """Raises CapabilityExecutionDenied on anything other than a fresh ALLOW. On ALLOW,
    runs the real tool and records the real outcome (executed|failed) on the decision
    that authorized it - a given decision can only ever be marked executed once
    (gds_api.capabilities.broker.CapabilityExecutionConflict guards real reuse)."""
    result = await reevaluate_capability_request(db, tenant_id=tenant_id, request_id=request_id)
    if result.decision != "ALLOW":
        await db.commit()
        raise CapabilityExecutionDenied(result.decision, result.denial_code, result.safe_message)

    # Phase 17: real requesting_agent_id/workflow_run_id, read off the same real
    # CapabilityRequestRecord the broker already persisted - so the 10 real repository
    # tools (gds_api.tool_gateway) can resolve/create a real Workspace tied to the real
    # agent and workflow run that proposed this request, not just the mission.
    request_record = await db.get(CapabilityRequestRecord, request_id)
    requesting_agent_id = request_record.requesting_agent_id if request_record else None
    workflow_run_id = request_record.workflow_run_id if request_record else None

    try:
        output = await tool_gateway.execute_tool(
            db,
            tenant_id=tenant_id,
            user_id=user_id,
            mission_id=mission_id,
            tool_name=tool_name,
            input_data=input_data,
            requesting_agent_id=requesting_agent_id,
            workflow_run_id=workflow_run_id,
            capability_decision_id=result.decision_id,
        )
    except Exception:
        await mark_capability_execution(
            db, tenant_id=tenant_id, decision_id=result.decision_id, status="failed"
        )
        await db.commit()
        raise
    await mark_capability_execution(
        db, tenant_id=tenant_id, decision_id=result.decision_id, status="executed"
    )
    await db.commit()
    return output
