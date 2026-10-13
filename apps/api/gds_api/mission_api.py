"""Phase 19 (Continuation Prompt 6), Part 15: the real HTTP surface over the
Autonomous Multi-Agent Engineering System. Mirrors `engineering_api.py`'s own real
split: plain RBAC-protected REST for read-only mission-plan/task visibility, plus two
broker-gated endpoints (start a mission plan, request/execute its commit) - both go
through the same real `evaluate_capability_request` -> `execute_capability_request`
pipeline every other real capability in this platform uses.

Reuses the existing `engineering:*` RBAC permission set (Phase 18) - a mission plan is
the multi-agent extension of a single engineering session, not a separate resource
class requiring its own permissions.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.capabilities.broker import evaluate_capability_request
from gds_api.capabilities.gateway import CapabilityExecutionDenied, execute_capability_request
from gds_api.db import get_db
from gds_api.engineering import mission_manager
from gds_api.engineering.recovery import RecoveryReport, recover_mission_plans
from gds_api.models import Mission
from gds_api.rate_limit import tenant_rate_limit
from gds_api.schemas import (
    EngineeringRecoveryReportOut,
    EngineeringTaskOut,
    MissionMessageOut,
    MissionPlanCreateRequest,
    MissionPlanExecuteResponse,
    MissionPlanOut,
)
from gds_api.security import CurrentUser, require_permission

router = APIRouter(tags=["missions"])

# Same rationale/bound as gds_api.missions.mission_create_rate_limit and
# gds_api.engineering_api.engineering_session_rate_limit - a mission plan runs multiple
# real agents, each making real metered LLM calls, and had no rate limit at all before
# EDP-008 Part 8's API hardening audit found the gap.
mission_plan_create_rate_limit = tenant_rate_limit(
    "mission_plan_create", max_requests=20, window_seconds=3600
)


def _plan_to_out(plan) -> MissionPlanOut:  # type: ignore[no-untyped-def]
    return MissionPlanOut(
        id=plan.id,
        tenant_id=plan.tenant_id,
        mission_id=plan.mission_id,
        repository_id=plan.repository_id,
        requested_by_user_id=plan.requested_by_user_id,
        objective=plan.objective,
        complexity=plan.complexity,
        affected_systems=plan.affected_systems,
        execution_strategy=plan.execution_strategy,
        status=plan.status,
        max_concurrency=plan.max_concurrency,
        mission_memory=plan.mission_memory,
        integration_workspace_id=plan.integration_workspace_id,
        integration_branch=plan.integration_branch,
        conflict_report=plan.conflict_report,
        merged_review_result=plan.merged_review_result,
        merged_review_findings=plan.merged_review_findings,
        approval_id=plan.approval_id,
        commit_request_id=plan.commit_request_id,
        commit_hash=plan.commit_hash,
        failure_reason=plan.failure_reason,
        created_at=plan.created_at,
        planned_at=plan.planned_at,
        completed_at=plan.completed_at,
    )


def _task_to_out(task) -> EngineeringTaskOut:  # type: ignore[no-untyped-def]
    return EngineeringTaskOut(
        id=task.id,
        tenant_id=task.tenant_id,
        mission_plan_id=task.mission_plan_id,
        repository_id=task.repository_id,
        task_key=task.task_key,
        title=task.title,
        description=task.description,
        specialist_role=task.specialist_role,
        provider=task.provider,
        depends_on=task.depends_on,
        required_capabilities=task.required_capabilities,
        output_contract=task.output_contract,
        status=task.status,
        risk_estimate=task.risk_estimate,
        duration_estimate_seconds=task.duration_estimate_seconds,
        workspace_id=task.workspace_id,
        branch_name=task.branch_name,
        engineering_session_id=task.engineering_session_id,
        patch_summary=task.patch_summary,
        review_result=task.review_result,
        review_findings=task.review_findings,
        input_tokens=task.input_tokens,
        output_tokens=task.output_tokens,
        cost_usd=task.cost_usd,
        failure_reason=task.failure_reason,
        retry_count=task.retry_count,
        created_at=task.created_at,
        started_at=task.started_at,
        completed_at=task.completed_at,
    )


@router.get("/mission-plans", response_model=list[MissionPlanOut])
async def list_mission_plans(
    repository_id: uuid.UUID | None = None,
    mission_id: uuid.UUID | None = None,
    status_filter: str | None = None,
    current_user: CurrentUser = Depends(require_permission("engineering:read")),
    db: AsyncSession = Depends(get_db),
) -> list[MissionPlanOut]:
    plans = await mission_manager.list_mission_plans(
        db,
        tenant_id=current_user.tenant_id,
        repository_id=repository_id,
        mission_id=mission_id,
        status_filter=status_filter,
    )
    return [_plan_to_out(p) for p in plans]


@router.get("/mission-plans/{mission_plan_id}", response_model=MissionPlanOut)
async def get_mission_plan(
    mission_plan_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("engineering:read")),
    db: AsyncSession = Depends(get_db),
) -> MissionPlanOut:
    try:
        plan = await mission_manager.get_mission_plan(
            db, tenant_id=current_user.tenant_id, mission_plan_id=mission_plan_id
        )
    except mission_manager.MissionPlanNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Mission plan not found") from exc
    return _plan_to_out(plan)


@router.get("/mission-plans/{mission_plan_id}/tasks", response_model=list[EngineeringTaskOut])
async def list_mission_plan_tasks(
    mission_plan_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("engineering:read")),
    db: AsyncSession = Depends(get_db),
) -> list[EngineeringTaskOut]:
    try:
        await mission_manager.get_mission_plan(
            db, tenant_id=current_user.tenant_id, mission_plan_id=mission_plan_id
        )
    except mission_manager.MissionPlanNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Mission plan not found") from exc
    tasks = await mission_manager.list_tasks(
        db, tenant_id=current_user.tenant_id, mission_plan_id=mission_plan_id
    )
    return [_task_to_out(t) for t in tasks]


@router.get("/mission-plans/{mission_plan_id}/messages", response_model=list[MissionMessageOut])
async def list_mission_plan_messages(
    mission_plan_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("engineering:read")),
    db: AsyncSession = Depends(get_db),
) -> list[MissionMessageOut]:
    try:
        await mission_manager.get_mission_plan(
            db, tenant_id=current_user.tenant_id, mission_plan_id=mission_plan_id
        )
    except mission_manager.MissionPlanNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Mission plan not found") from exc
    messages = await mission_manager.list_messages(
        db, tenant_id=current_user.tenant_id, mission_plan_id=mission_plan_id
    )
    return [
        MissionMessageOut(
            id=m.id,
            tenant_id=m.tenant_id,
            mission_plan_id=m.mission_plan_id,
            task_id=m.task_id,
            related_task_id=m.related_task_id,
            message_type=m.message_type,
            content=m.content,
            created_at=m.created_at,
        )
        for m in messages
    ]


@router.post(
    "/mission-plans",
    response_model=MissionPlanExecuteResponse,
    dependencies=[Depends(mission_plan_create_rate_limit)],
)
async def create_mission_plan_endpoint(
    body: MissionPlanCreateRequest,
    current_user: CurrentUser = Depends(require_permission("engineering:execute")),
    db: AsyncSession = Depends(get_db),
) -> MissionPlanExecuteResponse:
    mission = Mission(
        tenant_id=current_user.tenant_id,
        requested_by_user_id=current_user.user_id,
        objective=body.objective,
        status="planning",
    )
    db.add(mission)
    await db.commit()
    await db.refresh(mission)

    input_data: dict[str, object] = {
        "repository_id": str(body.repository_id),
        "objective": body.objective,
        "max_concurrency": body.max_concurrency,
    }

    eval_result = await evaluate_capability_request(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        mission_id=mission.id,
        requesting_agent_id=None,
        supervising_agent_id=None,
        capability_key="engineering.plan_mission",
        requested_tool_id="start_mission_plan",
        target_type=None,
        target_reference=None,
        target_scope=None,
        purpose="Real autonomous multi-agent mission via API",
        requested_parameters=input_data,
    )
    if eval_result.decision != "ALLOW":
        return MissionPlanExecuteResponse(
            decision=eval_result.decision,
            capability_key="engineering.plan_mission",
            request_id=eval_result.request_id,
            output=None,
            safe_message=eval_result.safe_message,
        )

    try:
        output = await execute_capability_request(
            db,
            tenant_id=current_user.tenant_id,
            request_id=eval_result.request_id,
            tool_name="start_mission_plan",
            input_data=input_data,
            user_id=current_user.user_id,
            mission_id=mission.id,
        )
    except CapabilityExecutionDenied as denied:
        return MissionPlanExecuteResponse(
            decision=denied.decision,
            capability_key="engineering.plan_mission",
            request_id=eval_result.request_id,
            output=None,
            safe_message=denied.safe_message,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    return MissionPlanExecuteResponse(
        decision="ALLOW",
        capability_key="engineering.plan_mission",
        request_id=eval_result.request_id,
        output=output,
        safe_message=None,
    )


@router.post("/mission-plans/{mission_plan_id}/commit", response_model=MissionPlanExecuteResponse)
async def commit_mission_plan_endpoint(
    mission_plan_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("engineering:approve")),
    db: AsyncSession = Depends(get_db),
) -> MissionPlanExecuteResponse:
    """Real, two-call approval flow (mirrors `engineering_api.py`'s own established
    pattern): the first call evaluates `engineering.commit_mission` (always
    REQUIRE_APPROVAL) and records the real request id on the plan; a human then
    approves via the existing `/approvals` page; a second call to this same endpoint
    re-evaluates the SAME real request (reusing the same Approval, never minting a
    second one) and, once approved, performs the real merged-branch commit."""
    try:
        plan = await mission_manager.get_mission_plan(
            db, tenant_id=current_user.tenant_id, mission_plan_id=mission_plan_id
        )
    except mission_manager.MissionPlanNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Mission plan not found") from exc

    input_data = {"mission_plan_id": str(mission_plan_id)}

    if plan.commit_request_id is None:
        eval_result = await evaluate_capability_request(
            db,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
            mission_id=plan.mission_id,
            requesting_agent_id=None,
            supervising_agent_id=None,
            capability_key="engineering.commit_mission",
            requested_tool_id="commit_mission_plan",
            target_type=None,
            target_reference=None,
            target_scope=None,
            purpose="Real merged mission commit via API",
            requested_parameters=input_data,
        )
        plan.commit_request_id = eval_result.request_id
        if eval_result.approval_id is not None:
            plan.approval_id = eval_result.approval_id
        await db.commit()
        request_id = eval_result.request_id
        decision = eval_result.decision
        safe_message = eval_result.safe_message
    else:
        request_id = plan.commit_request_id
        decision = None
        safe_message = None

    if decision is not None and decision != "ALLOW":
        return MissionPlanExecuteResponse(
            decision=decision,
            capability_key="engineering.commit_mission",
            request_id=request_id,
            output=None,
            safe_message=safe_message,
        )

    try:
        output = await execute_capability_request(
            db,
            tenant_id=current_user.tenant_id,
            request_id=request_id,
            tool_name="commit_mission_plan",
            input_data=input_data,
            user_id=current_user.user_id,
            mission_id=plan.mission_id,
        )
    except CapabilityExecutionDenied as denied:
        return MissionPlanExecuteResponse(
            decision=denied.decision,
            capability_key="engineering.commit_mission",
            request_id=request_id,
            output=None,
            safe_message=denied.safe_message,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    return MissionPlanExecuteResponse(
        decision="ALLOW",
        capability_key="engineering.commit_mission",
        request_id=request_id,
        output=output,
        safe_message=None,
    )


@router.post("/mission-plans/recover", response_model=EngineeringRecoveryReportOut)
async def recover_mission_plans_endpoint(
    current_user: CurrentUser = Depends(require_permission("engineering:manage")),
    db: AsyncSession = Depends(get_db),
) -> EngineeringRecoveryReportOut:
    """Part 14: real reconciliation for MissionPlan/EngineeringTask, mirroring
    `engineering_api.py`'s own `/engineering-sessions/recover` - detects stale RUNNING
    tasks and stuck plans left behind by a process restart, and AWAITING_APPROVAL plans
    whose real Approval was rejected. Safe to call repeatedly."""
    report: RecoveryReport = await recover_mission_plans(db, tenant_id=current_user.tenant_id)
    return EngineeringRecoveryReportOut(
        stale_running_failed=report.stale_running_failed,
        rejected_approvals_marked=report.rejected_approvals_marked,
    )
