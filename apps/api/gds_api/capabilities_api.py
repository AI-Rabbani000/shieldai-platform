"""Phase 16 (Continuation Prompt 3), Part R: the real HTTP surface over the Secure
Capability Broker - a read-only Capability Directory (GET /capabilities*), the real
request/decision lifecycle (POST/GET /capability-requests*), and RBAC-protected admin
endpoints for per-tenant enablement state and decision audit. Every write here is
audited (via gds_api.capabilities.broker, which already records its own audit events for
every decision/execution/cancellation) - this module adds no side-effecting behavior of
its own beyond what the broker already does; it is a thin, real HTTP wrapper.

Non-admin responses never include CapabilityDecisionRecord.decision_trace (the internal,
check-by-check evaluation trace) - only the admin decisions endpoint
(capabilities:manage) returns it, per Part P's "safe external explanation vs. internal
trace" split.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.agents.registry import AGENT_REGISTRY
from gds_api.capabilities.broker import (
    CapabilityCancelConflict,
    CapabilityDenied,
    cancel_capability_request,
    evaluate_capability_request,
    reevaluate_capability_request,
)
from gds_api.capabilities.catalog import CAPABILITY_REGISTRY
from gds_api.capabilities.definitions import CapabilityDefinition
from gds_api.db import get_db
from gds_api.models import CapabilityDecisionRecord, CapabilityRequestRecord, CapabilityState
from gds_api.schemas import (
    AgentCapabilitiesOut,
    AgentCapabilityDenialOut,
    CapabilityCategoryOut,
    CapabilityDecisionAdminOut,
    CapabilityDecisionOut,
    CapabilityOut,
    CapabilityPolicyVersionOut,
    CapabilityRequestCreateRequest,
    CapabilityRequestOut,
    CapabilityRequestWithDecisionOut,
    CapabilityStateOut,
    CapabilityStatePatchRequest,
)
from gds_api.security import CurrentUser, require_permission

router = APIRouter(tags=["capabilities"])
admin_router = APIRouter(prefix="/admin", tags=["capabilities-admin"])


async def _effective_enabled_for_tenant(
    db: AsyncSession, tenant_id: uuid.UUID, capability: CapabilityDefinition
) -> bool:
    if not capability.enabled:
        return False
    state = await db.get(CapabilityState, (capability.stable_key, tenant_id))
    return not (state is not None and state.disabled)


async def _capability_to_out(
    db: AsyncSession, tenant_id: uuid.UUID, capability: CapabilityDefinition
) -> CapabilityOut:
    return CapabilityOut(
        id=capability.id,
        stable_key=capability.stable_key,
        display_name=capability.display_name,
        description=capability.description,
        category=capability.category,
        risk_class=capability.risk_class.value,
        side_effect_type=capability.side_effect_type.value,
        status=capability.status.value,
        version=capability.version,
        target_types=list(capability.target_types),
        allowed_team_types=[t.value for t in capability.allowed_team_types],
        allowed_agent_ids=list(capability.allowed_agent_ids),
        required_connector_ids=list(capability.required_connector_ids),
        requires_mission=capability.requires_mission,
        requires_workflow_run=capability.requires_workflow_run,
        requires_human_approval=capability.requires_human_approval,
        requires_target_authorisation=capability.requires_target_authorisation,
        requires_emergency_stop_clear=capability.requires_emergency_stop_clear,
        evidence_required=capability.evidence_required,
        audit_level=capability.audit_level,
        enabled=capability.enabled,
        effective_enabled=await _effective_enabled_for_tenant(db, tenant_id, capability),
    )


def _request_to_out(request: CapabilityRequestRecord) -> CapabilityRequestOut:
    return CapabilityRequestOut(
        id=request.id,
        tenant_id=request.tenant_id,
        mission_id=request.mission_id,
        workflow_run_id=request.workflow_run_id,
        requesting_agent_id=request.requesting_agent_id,
        capability_key=request.capability_key,
        requested_tool_id=request.requested_tool_id,
        target_type=request.target_type,
        target_reference=request.target_reference,
        purpose=request.purpose,
        requested_parameters_safe=request.requested_parameters_safe,
        idempotency_key=request.idempotency_key,
        requested_at=request.requested_at,
    )


def _decision_to_out(decision: CapabilityDecisionRecord) -> CapabilityDecisionOut:
    return CapabilityDecisionOut(
        id=decision.id,
        request_id=decision.request_id,
        decision=decision.decision,
        capability_key=decision.capability_key,
        capability_version=decision.capability_version,
        authoritative_risk_class=decision.authoritative_risk_class,
        approval_required=decision.approval_required,
        approval_id=decision.approval_id,
        target_authorisation_required=decision.target_authorisation_required,
        target_authorisation_id=decision.target_authorisation_id,
        denial_code=decision.denial_code,
        safe_denial_message=decision.safe_denial_message,
        policy_version=decision.policy_version,
        decided_at=decision.decided_at,
        expires_at=decision.expires_at,
        executed_at=decision.executed_at,
        execution_status=decision.execution_status,
    )


async def _load_request(
    db: AsyncSession, tenant_id: uuid.UUID, request_id: uuid.UUID
) -> CapabilityRequestRecord:
    request = await db.get(CapabilityRequestRecord, request_id)
    if request is None or request.tenant_id != tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Capability request not found")
    return request


async def _latest_decision(
    db: AsyncSession, request_id: uuid.UUID
) -> CapabilityDecisionRecord | None:
    return (
        (
            await db.execute(
                select(CapabilityDecisionRecord)
                .where(CapabilityDecisionRecord.request_id == request_id)
                .order_by(CapabilityDecisionRecord.decided_at.desc())
            )
        )
        .scalars()
        .first()
    )


# ---- Capability Directory (read-only) ----------------------------------------------


@router.get("/capabilities", response_model=list[CapabilityOut])
async def list_capabilities(
    status_filter: str | None = None,
    risk_class: str | None = None,
    category: str | None = None,
    team: str | None = None,
    requires_human_approval: bool | None = None,
    requires_target_authorisation: bool | None = None,
    current_user: CurrentUser = Depends(require_permission("capabilities:read")),
    db: AsyncSession = Depends(get_db),
) -> list[CapabilityOut]:
    capabilities = list(CAPABILITY_REGISTRY.values())
    if status_filter:
        capabilities = [c for c in capabilities if c.status.value == status_filter]
    if risk_class:
        capabilities = [c for c in capabilities if c.risk_class.value == risk_class]
    if category:
        capabilities = [c for c in capabilities if c.category == category]
    if team:
        capabilities = [c for c in capabilities if team in [t.value for t in c.allowed_team_types]]
    if requires_human_approval is not None:
        capabilities = [
            c for c in capabilities if c.requires_human_approval == requires_human_approval
        ]
    if requires_target_authorisation is not None:
        capabilities = [
            c
            for c in capabilities
            if c.requires_target_authorisation == requires_target_authorisation
        ]
    capabilities.sort(key=lambda c: c.stable_key)
    return [await _capability_to_out(db, current_user.tenant_id, c) for c in capabilities]


@router.get("/capabilities/categories", response_model=list[CapabilityCategoryOut])
async def list_capability_categories(
    current_user: CurrentUser = Depends(require_permission("capabilities:read")),
) -> list[CapabilityCategoryOut]:
    counts: dict[str, int] = {}
    for capability in CAPABILITY_REGISTRY.values():
        counts[capability.category] = counts.get(capability.category, 0) + 1
    return [
        CapabilityCategoryOut(category=category, count=count)
        for category, count in sorted(counts.items())
    ]


@router.get("/capabilities/agents/{agent_id}", response_model=AgentCapabilitiesOut)
async def get_agent_capabilities(
    agent_id: str,
    current_user: CurrentUser = Depends(require_permission("capabilities:read")),
    db: AsyncSession = Depends(get_db),
) -> AgentCapabilitiesOut:
    manifest = AGENT_REGISTRY.get(agent_id)
    if manifest is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent not found")

    allowed: list[CapabilityOut] = []
    denied: list[AgentCapabilityDenialOut] = []
    for capability in CAPABILITY_REGISTRY.values():
        if capability.stable_key in manifest.allowed_capability_ids:
            allowed.append(await _capability_to_out(db, current_user.tenant_id, capability))
        elif capability.status.value == "OPERATIONAL":
            if capability.allowed_team_types and manifest.team not in capability.allowed_team_types:
                allowed_teams = [t.value for t in capability.allowed_team_types]
                reason = f"capability is scoped to team(s) {allowed_teams}"
            elif capability.risk_class.value > manifest.risk_ceiling.value:
                reason = (
                    f"capability risk_class {capability.risk_class.value} exceeds this "
                    f"agent's risk ceiling {manifest.risk_ceiling.value}"
                )
            else:
                reason = "not present in this agent's allowed_capability_ids"
            denied.append(
                AgentCapabilityDenialOut(capability_key=capability.stable_key, reason=reason)
            )

    return AgentCapabilitiesOut(
        agent_id=agent_id,
        risk_ceiling=manifest.risk_ceiling.value,
        allowed_capabilities=allowed,
        denied_capabilities=denied,
    )


@router.get("/capabilities/{stable_key}", response_model=CapabilityOut)
async def get_capability(
    stable_key: str,
    current_user: CurrentUser = Depends(require_permission("capabilities:read")),
    db: AsyncSession = Depends(get_db),
) -> CapabilityOut:
    capability = CAPABILITY_REGISTRY.get(stable_key)
    if capability is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Capability not found")
    return await _capability_to_out(db, current_user.tenant_id, capability)


# ---- Capability request/decision lifecycle -------------------------------------


@router.post("/capability-requests", response_model=CapabilityRequestWithDecisionOut)
async def create_capability_request(
    body: CapabilityRequestCreateRequest,
    current_user: CurrentUser = Depends(require_permission("capabilities:request")),
    db: AsyncSession = Depends(get_db),
) -> CapabilityRequestWithDecisionOut:
    result = await evaluate_capability_request(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        mission_id=body.mission_id,
        requesting_agent_id=body.requesting_agent_id,
        supervising_agent_id=None,
        capability_key=body.capability_key,
        requested_tool_id=body.requested_tool_id,
        target_type=body.target_type,
        target_reference=body.target_reference,
        target_scope=body.target_scope,
        purpose=body.purpose,
        requested_parameters=body.requested_parameters,
        idempotency_key=body.idempotency_key,
    )
    request = await db.get(CapabilityRequestRecord, result.request_id)
    if request is None or request.tenant_id != current_user.tenant_id:
        # A fabricated mission_id/user_id fails closed before any row is persisted -
        # gds_api.capabilities.broker.evaluate_capability_request's pre-flight check.
        # Echo the real evaluation outcome without pretending a request was recorded.
        raise HTTPException(status.HTTP_400_BAD_REQUEST, result.safe_message)
    decision = await _latest_decision(db, result.request_id)
    return CapabilityRequestWithDecisionOut(
        request=_request_to_out(request),
        decision=_decision_to_out(decision) if decision else None,
    )


@router.get("/capability-requests/{request_id}", response_model=CapabilityRequestOut)
async def get_capability_request(
    request_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("capabilities:read")),
    db: AsyncSession = Depends(get_db),
) -> CapabilityRequestOut:
    request = await _load_request(db, current_user.tenant_id, request_id)
    return _request_to_out(request)


@router.get(
    "/capability-requests/{request_id}/decision",
    response_model=CapabilityDecisionOut,
)
async def get_capability_request_decision(
    request_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("capabilities:read")),
    db: AsyncSession = Depends(get_db),
) -> CapabilityDecisionOut:
    await _load_request(db, current_user.tenant_id, request_id)
    decision = await _latest_decision(db, request_id)
    if decision is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No decision recorded for this request")
    return _decision_to_out(decision)


@router.post(
    "/capability-requests/{request_id}/reevaluate",
    response_model=CapabilityDecisionOut,
)
async def reevaluate_capability_request_endpoint(
    request_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("capabilities:request")),
    db: AsyncSession = Depends(get_db),
) -> CapabilityDecisionOut:
    await _load_request(db, current_user.tenant_id, request_id)
    result = await reevaluate_capability_request(
        db, tenant_id=current_user.tenant_id, request_id=request_id
    )
    decision = await _latest_decision(db, result.request_id)
    if decision is None:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR, "Re-evaluation produced no decision"
        )
    return _decision_to_out(decision)


@router.post(
    "/capability-requests/{request_id}/cancel",
    response_model=CapabilityDecisionOut,
)
async def cancel_capability_request_endpoint(
    request_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("capabilities:request")),
    db: AsyncSession = Depends(get_db),
) -> CapabilityDecisionOut:
    try:
        decision = await cancel_capability_request(
            db,
            tenant_id=current_user.tenant_id,
            actor_user_id=current_user.user_id,
            request_id=request_id,
        )
    except CapabilityDenied as denied:
        raise HTTPException(status.HTTP_404_NOT_FOUND, denied.safe_message) from denied
    except CapabilityCancelConflict as conflict:
        raise HTTPException(status.HTTP_409_CONFLICT, str(conflict)) from conflict
    await db.commit()
    return _decision_to_out(decision)


# ---- Admin: enablement state + decision audit ----------------------------------


@admin_router.get("/capabilities", response_model=list[CapabilityOut])
async def admin_list_capabilities(
    current_user: CurrentUser = Depends(require_permission("capabilities:manage")),
    db: AsyncSession = Depends(get_db),
) -> list[CapabilityOut]:
    capabilities = sorted(CAPABILITY_REGISTRY.values(), key=lambda c: c.stable_key)
    return [await _capability_to_out(db, current_user.tenant_id, c) for c in capabilities]


@admin_router.patch("/capabilities/{stable_key}/state", response_model=CapabilityStateOut)
async def admin_patch_capability_state(
    stable_key: str,
    body: CapabilityStatePatchRequest,
    current_user: CurrentUser = Depends(require_permission("capabilities:manage")),
    db: AsyncSession = Depends(get_db),
) -> CapabilityStateOut:
    """Can only ever narrow a capability (disable it) - never widen it beyond the
    code-defined default (ADR 0015). Setting disabled=True on a capability whose code
    default is already enabled=False is accepted but has no additional effect; there is
    no code path anywhere that lets this endpoint re-enable a code-disabled capability."""
    if stable_key not in CAPABILITY_REGISTRY:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Capability not found")

    state = await db.get(CapabilityState, (stable_key, current_user.tenant_id))
    if state is None:
        state = CapabilityState(capability_key=stable_key, tenant_id=current_user.tenant_id)
        db.add(state)
    state.disabled = body.disabled
    state.disabled_reason = body.reason
    state.disabled_by_user_id = current_user.user_id

    from gds_api.audit import record_audit_event

    await record_audit_event(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="capability.state.patch",
        detail={"capability_key": stable_key, "disabled": body.disabled, "reason": body.reason},
    )
    await db.commit()
    await db.refresh(state)
    return CapabilityStateOut(
        capability_key=state.capability_key,
        tenant_id=state.tenant_id,
        disabled=state.disabled,
        disabled_reason=state.disabled_reason,
        updated_at=state.updated_at,
    )


@admin_router.get("/capability-decisions", response_model=list[CapabilityDecisionAdminOut])
async def admin_list_capability_decisions(
    decision: str | None = None,
    capability_key: str | None = None,
    limit: int = 100,
    current_user: CurrentUser = Depends(require_permission("capabilities:manage")),
    db: AsyncSession = Depends(get_db),
) -> list[CapabilityDecisionAdminOut]:
    # Clamped to match every other paginated list endpoint's own bound
    # (audit.py/evidence.py/knowledge.py) - EDP-008 Part 8 API hardening audit finding:
    # this was the one paginated endpoint with no upper clamp.
    limit = max(1, min(limit, 200))
    query = select(CapabilityDecisionRecord).where(
        CapabilityDecisionRecord.tenant_id == current_user.tenant_id
    )
    if decision:
        query = query.where(CapabilityDecisionRecord.decision == decision)
    if capability_key:
        query = query.where(CapabilityDecisionRecord.capability_key == capability_key)
    rows = (
        (await db.execute(query.order_by(CapabilityDecisionRecord.decided_at.desc()).limit(limit)))
        .scalars()
        .all()
    )
    return [
        CapabilityDecisionAdminOut(
            **_decision_to_out(d).model_dump(),
            decision_trace=d.decision_trace,
            tenant_id=d.tenant_id,
        )
        for d in rows
    ]


@admin_router.get("/capability-policy-versions", response_model=CapabilityPolicyVersionOut)
async def admin_get_capability_policy_version(
    current_user: CurrentUser = Depends(require_permission("capabilities:manage")),
) -> CapabilityPolicyVersionOut:
    from gds_api.capabilities.broker import CAPABILITY_POLICY_VERSION

    return CapabilityPolicyVersionOut(policy_version=CAPABILITY_POLICY_VERSION)
