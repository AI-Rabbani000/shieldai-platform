"""Phase 18 (Continuation Prompt 5), Part 1/14: the real HTTP surface over the AI
Engineering Execution Platform. Mirrors `repository_api.py`'s own real split: plain
RBAC-protected REST for read-only session visibility, plus exactly two broker-gated
endpoints (start a session, request/execute its commit) - every one of which goes
through the same real `evaluate_capability_request` -> `execute_capability_request`
pipeline every other real capability in this platform uses, never a shortcut.

Unlike repository browsing (which reuses one shared "browsing Mission"),
`POST /engineering-sessions` creates a real, distinct Mission per session - each one is
real engineering work with its own real objective, not incidental browsing.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.capabilities.broker import evaluate_capability_request
from gds_api.capabilities.gateway import CapabilityExecutionDenied, execute_capability_request
from gds_api.db import get_db
from gds_api.engineering import session_manager
from gds_api.engineering.recovery import RecoveryReport, recover_engineering_sessions
from gds_api.models import EngineeringSession, Mission
from gds_api.rate_limit import tenant_rate_limit
from gds_api.schemas import (
    EngineeringRecoveryReportOut,
    EngineeringSessionCreateRequest,
    EngineeringSessionExecuteResponse,
    EngineeringSessionOut,
)
from gds_api.security import CurrentUser, require_permission

router = APIRouter(tags=["engineering"])

# Same real, metered-Anthropic/OpenAI-spend rationale as gds_api.missions'
# mission_create_rate_limit, and the same 20/hour bound (a real engineering session is
# at least as expensive as a real mission run) - see EDP-008 Part 8's API hardening
# audit, which found this endpoint had no rate limit despite matching that endpoint's
# own stated justification for one.
engineering_session_rate_limit = tenant_rate_limit(
    "engineering_session_create", max_requests=20, window_seconds=3600
)


def _session_to_out(session: EngineeringSession) -> EngineeringSessionOut:
    return EngineeringSessionOut(
        id=session.id,
        tenant_id=session.tenant_id,
        mission_id=session.mission_id,
        workflow_run_id=session.workflow_run_id,
        repository_id=session.repository_id,
        workspace_id=session.workspace_id,
        capability_decision_id=session.capability_decision_id,
        provider=session.provider,
        requested_by_user_id=session.requested_by_user_id,
        agent_id=session.agent_id,
        objective=session.objective,
        prompt_version=session.prompt_version,
        status=session.status,
        provider_session_id=session.provider_session_id,
        exit_code=session.exit_code,
        reasoning_summary=session.reasoning_summary,
        patch_summary=session.patch_summary,
        review_result=session.review_result,
        review_findings=session.review_findings,
        sensitive_area_hit=session.sensitive_area_hit,
        approval_id=session.approval_id,
        commit_hash=session.commit_hash,
        input_tokens=session.input_tokens,
        output_tokens=session.output_tokens,
        cost_usd=session.cost_usd,
        failure_reason=session.failure_reason,
        created_at=session.created_at,
        started_at=session.started_at,
        completed_at=session.completed_at,
    )


@router.get("/engineering-sessions", response_model=list[EngineeringSessionOut])
async def list_engineering_sessions(
    repository_id: uuid.UUID | None = None,
    mission_id: uuid.UUID | None = None,
    status_filter: str | None = None,
    current_user: CurrentUser = Depends(require_permission("engineering:read")),
    db: AsyncSession = Depends(get_db),
) -> list[EngineeringSessionOut]:
    sessions = await session_manager.list_sessions(
        db,
        tenant_id=current_user.tenant_id,
        repository_id=repository_id,
        mission_id=mission_id,
        status_filter=status_filter,
    )
    return [_session_to_out(s) for s in sessions]


@router.get("/engineering-sessions/{session_id}", response_model=EngineeringSessionOut)
async def get_engineering_session(
    session_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("engineering:read")),
    db: AsyncSession = Depends(get_db),
) -> EngineeringSessionOut:
    try:
        session = await session_manager.get_session(
            db, tenant_id=current_user.tenant_id, session_id=session_id
        )
    except session_manager.EngineeringSessionNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Engineering session not found") from exc
    return _session_to_out(session)


@router.post(
    "/engineering-sessions",
    response_model=EngineeringSessionExecuteResponse,
    dependencies=[Depends(engineering_session_rate_limit)],
)
async def create_engineering_session(
    body: EngineeringSessionCreateRequest,
    current_user: CurrentUser = Depends(require_permission("engineering:execute")),
    db: AsyncSession = Depends(get_db),
) -> EngineeringSessionExecuteResponse:
    if body.provider not in ("claude", "openai"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "provider must be 'claude' or 'openai'")

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
        "provider": body.provider,
        "objective": body.objective,
    }
    if body.developer_instructions:
        input_data["developer_instructions"] = body.developer_instructions

    eval_result = await evaluate_capability_request(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        mission_id=mission.id,
        requesting_agent_id=None,
        supervising_agent_id=None,
        capability_key="engineering.execute_session",
        requested_tool_id="start_engineering_session",
        target_type=None,
        target_reference=None,
        target_scope=None,
        purpose="Real AI engineering session via API",
        requested_parameters=input_data,
    )
    if eval_result.decision != "ALLOW":
        return EngineeringSessionExecuteResponse(
            decision=eval_result.decision,
            capability_key="engineering.execute_session",
            request_id=eval_result.request_id,
            output=None,
            safe_message=eval_result.safe_message,
        )

    try:
        output = await execute_capability_request(
            db,
            tenant_id=current_user.tenant_id,
            request_id=eval_result.request_id,
            tool_name="start_engineering_session",
            input_data=input_data,
            user_id=current_user.user_id,
            mission_id=mission.id,
        )
    except CapabilityExecutionDenied as denied:
        return EngineeringSessionExecuteResponse(
            decision=denied.decision,
            capability_key="engineering.execute_session",
            request_id=eval_result.request_id,
            output=None,
            safe_message=denied.safe_message,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    return EngineeringSessionExecuteResponse(
        decision="ALLOW",
        capability_key="engineering.execute_session",
        request_id=eval_result.request_id,
        output=output,
        safe_message=None,
    )


@router.post(
    "/engineering-sessions/{session_id}/commit", response_model=EngineeringSessionExecuteResponse
)
async def commit_engineering_session_endpoint(
    session_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("engineering:approve")),
    db: AsyncSession = Depends(get_db),
) -> EngineeringSessionExecuteResponse:
    """Real, two-call approval flow (mirrors Phase 16's own established pattern): the
    first call evaluates `engineering.commit` (always REQUIRE_APPROVAL - ADR 0024) and
    records the real request id on the session; a human then approves via the existing
    `/approvals` page; a second call to this same endpoint re-evaluates the SAME real
    request (reusing the same Approval, never minting a second one) and, once approved,
    performs the real commit. No bypass path exists."""
    try:
        session = await session_manager.get_session(
            db, tenant_id=current_user.tenant_id, session_id=session_id
        )
    except session_manager.EngineeringSessionNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Engineering session not found") from exc

    input_data = {"session_id": str(session_id)}

    if session.commit_request_id is None:
        eval_result = await evaluate_capability_request(
            db,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
            mission_id=session.mission_id,
            requesting_agent_id=None,
            supervising_agent_id=None,
            capability_key="engineering.commit",
            requested_tool_id="commit_engineering_session",
            target_type=None,
            target_reference=None,
            target_scope=None,
            purpose="Real engineering session commit via API",
            requested_parameters=input_data,
        )
        session.commit_request_id = eval_result.request_id
        if eval_result.approval_id is not None:
            session.approval_id = eval_result.approval_id
        await db.commit()
        request_id = eval_result.request_id
        decision = eval_result.decision
        safe_message = eval_result.safe_message
    else:
        request_id = session.commit_request_id
        decision = None
        safe_message = None

    if decision is not None and decision != "ALLOW":
        return EngineeringSessionExecuteResponse(
            decision=decision,
            capability_key="engineering.commit",
            request_id=request_id,
            output=None,
            safe_message=safe_message,
        )

    try:
        output = await execute_capability_request(
            db,
            tenant_id=current_user.tenant_id,
            request_id=request_id,
            tool_name="commit_engineering_session",
            input_data=input_data,
            user_id=current_user.user_id,
            mission_id=session.mission_id,
        )
    except CapabilityExecutionDenied as denied:
        return EngineeringSessionExecuteResponse(
            decision=denied.decision,
            capability_key="engineering.commit",
            request_id=request_id,
            output=None,
            safe_message=denied.safe_message,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    return EngineeringSessionExecuteResponse(
        decision="ALLOW",
        capability_key="engineering.commit",
        request_id=request_id,
        output=output,
        safe_message=None,
    )


@router.post("/engineering-sessions/recover", response_model=EngineeringRecoveryReportOut)
async def recover_engineering_sessions_endpoint(
    current_user: CurrentUser = Depends(require_permission("engineering:manage")),
    db: AsyncSession = Depends(get_db),
) -> EngineeringRecoveryReportOut:
    """Part 13: real reconciliation - detects stale RUNNING sessions (owning process
    restarted) and AWAITING_APPROVAL sessions whose real Approval was rejected, and
    repairs both. Safe to call repeatedly; on demand today (no scheduler this phase)."""
    report: RecoveryReport = await recover_engineering_sessions(
        db, tenant_id=current_user.tenant_id
    )
    return EngineeringRecoveryReportOut(
        stale_running_failed=report.stale_running_failed,
        rejected_approvals_marked=report.rejected_approvals_marked,
    )
