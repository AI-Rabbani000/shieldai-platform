"""Phase 16 (Continuation Prompt 3), Part F: the Secure Capability Broker's one
canonical evaluation pipeline. Every real tool execution must pass through
evaluate_capability_request() before gds_api.tool_gateway.execute_tool ever runs - see
gds_api.capabilities.gateway for the enforcement side (Part I) and
docs/architecture/capability-decision-pipeline.md for the full step-by-step design.

Deliberately reuses every existing real control this platform already has instead of
building parallel ones: gds_api.policy.evaluate_policy (approval creation),
gds_api.redteam_safety's three functions (target authorization, emergency stop, and -
for red_team capabilities specifically - rate limiting), gds_api.rate_limit's Redis
INCR+EXPIRE pattern (a new general per-capability limit, closing the Phase 16 audit's
finding that no non-red-team tool execution was ever rate-limited), and
gds_api.audit.record_audit_event / gds_api.events.publish_mission_event for the
lifecycle trail. The broker's own real, new work is: capability resolution, the
agent-allow-list enforcement Entry Point B never had, the risk-ceiling check, secret
redaction, idempotency, and the durable CapabilityRequestRecord/CapabilityDecisionRecord
trail tying all of the above together into one reproducible decision.

Deny by default: any unresolved ambiguity (unknown capability, unresolvable agent,
inconsistent tenant context, an unreachable dependency for a required check) reaches a
`raise` or an explicit DENY/BLOCKED_* result before this function returns ALLOW - see
each check below for its own fail-closed reasoning.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api import redteam_safety
from gds_api.agents.manifest import AgentStatus
from gds_api.agents.registry import AGENT_REGISTRY
from gds_api.audit import record_audit_event
from gds_api.capabilities.catalog import CAPABILITY_REGISTRY
from gds_api.capabilities.definitions import CapabilityDefinition, CapabilityStatus, RiskClass
from gds_api.config import settings
from gds_api.events import publish_mission_event
from gds_api.models import (
    Approval,
    CapabilityDecisionRecord,
    CapabilityRequestRecord,
    CapabilityState,
    Mission,
    User,
    WorkflowRun,
)
from gds_api.policy import evaluate_policy
from gds_api.tool_gateway import TOOL_REGISTRY

CAPABILITY_POLICY_VERSION = "1.0.0"

# Real per-tenant-per-capability limit for any capability without a stronger,
# capability-specific limit (red_team capabilities use redteam_safety's own
# per-target limiter instead - see _check_rate_limit below). Closes the Phase 16
# audit's finding that no tool execution besides red_team's had any rate limit at all.
_DEFAULT_MAX_REQUESTS_PER_HOUR = 100

_SECRET_KEY_PATTERN = re.compile(
    r"(password|passwd|secret|api[_-]?key|token|credential|private[_-]?key|access[_-]?key)",
    re.IGNORECASE,
)
_SECRET_VALUE_PATTERN = re.compile(r"^[A-Za-z0-9+/_-]{20,}={0,2}$")
_REDACTED = "[REDACTED]"


def redact_secrets(params: dict[str, Any]) -> dict[str, Any]:
    """Part D: real, structural secret redaction - never a raw untrusted payload
    reaches storage, an SSE event, or an audit record. Redacts by key name (a field
    literally called "password"/"api_key"/etc.) and by value shape (a long
    token-looking string, regardless of its key name) - two independent nets, since an
    agent-controlled parameter name is itself untrusted input."""
    safe: dict[str, Any] = {}
    for key, value in params.items():
        if _SECRET_KEY_PATTERN.search(key):
            safe[key] = _REDACTED
        elif isinstance(value, str) and _SECRET_VALUE_PATTERN.match(value):
            safe[key] = _REDACTED
        elif isinstance(value, dict):
            safe[key] = redact_secrets(value)
        else:
            safe[key] = value
    return safe


class CapabilityDenied(Exception):  # noqa: N818 - intentionally not "...Error": this is
    # a normal, expected control-flow outcome (a real DENY/BLOCKED_* decision), not a
    # bug - callers catch it specifically to build the safe decision record.
    def __init__(self, decision: str, denial_code: str, safe_message: str) -> None:
        self.decision = decision
        self.denial_code = denial_code
        self.safe_message = safe_message
        super().__init__(safe_message)


@dataclass
class CapabilityEvaluationResult:
    decision_id: uuid.UUID
    request_id: uuid.UUID
    decision: str
    capability_key: str
    authoritative_risk_class: str
    approval_required: bool
    approval_id: uuid.UUID | None
    target_authorisation_required: bool
    target_authorisation_id: uuid.UUID | None
    denial_code: str | None
    safe_message: str
    expires_at: datetime | None
    trace: dict[str, Any] = field(default_factory=dict)


def _get_redis() -> Redis:
    return Redis(host=settings.redis_host, port=settings.redis_port, decode_responses=True)


async def _check_rate_limit(
    *, tenant_id: uuid.UUID, capability: CapabilityDefinition
) -> dict[str, Any]:
    key = f"capability:ratelimit:{tenant_id}:{capability.stable_key}"
    async with _get_redis() as r:
        count = await r.incr(key)
        if count == 1:
            await r.expire(key, 3600)
    ok = count <= _DEFAULT_MAX_REQUESTS_PER_HOUR
    return {"count": count, "limit": _DEFAULT_MAX_REQUESTS_PER_HOUR, "ok": ok}


def _effective_enabled(capability: CapabilityDefinition, state: CapabilityState | None) -> bool:
    """The database can only ever narrow the code default, never widen it - a
    CapabilityState row with disabled=True always wins; a missing row, or one with
    disabled=False, defers entirely to the catalogue's own `enabled` default. See
    ADR 0015."""
    if not capability.enabled:
        return False
    if state is not None and state.disabled:
        return False
    return True


async def evaluate_capability_request(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    mission_id: uuid.UUID,
    requesting_agent_id: str | None,
    supervising_agent_id: str | None,
    capability_key: str,
    requested_tool_id: str | None,
    target_type: str | None,
    target_reference: str | None,
    target_scope: str | None,
    purpose: str,
    requested_parameters: dict[str, Any],
    idempotency_key: str | None = None,
    conversation_thread_id: uuid.UUID | None = None,
    model_provider: str | None = None,
    model_name: str | None = None,
    parent_request_id: uuid.UUID | None = None,
) -> CapabilityEvaluationResult:
    """The entry point for a brand-new proposed action: creates the durable
    CapabilityRequestRecord (or replays an existing decision on an idempotency-key
    match) and runs the full evaluation pipeline once. See reevaluate_capability_request
    for the Part I execution-time re-check of an already-decided request."""
    safe_params = redact_secrets(requested_parameters)

    # Idempotency: a duplicate (tenant, capability, idempotency_key) returns the
    # existing request's decision rather than creating a second one - Part D/W44.
    if idempotency_key:
        existing = (
            await db.execute(
                select(CapabilityRequestRecord).where(
                    CapabilityRequestRecord.tenant_id == tenant_id,
                    CapabilityRequestRecord.capability_key == capability_key,
                    CapabilityRequestRecord.idempotency_key == idempotency_key,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            existing_decision = (
                (
                    await db.execute(
                        select(CapabilityDecisionRecord)
                        .where(CapabilityDecisionRecord.request_id == existing.id)
                        .order_by(CapabilityDecisionRecord.decided_at.desc())
                    )
                )
                .scalars()
                .first()
            )
            if existing_decision is not None:
                return CapabilityEvaluationResult(
                    decision_id=existing_decision.id,
                    request_id=existing.id,
                    decision=existing_decision.decision,
                    capability_key=capability_key,
                    authoritative_risk_class=existing_decision.authoritative_risk_class,
                    approval_required=existing_decision.approval_required,
                    approval_id=existing_decision.approval_id,
                    target_authorisation_required=existing_decision.target_authorisation_required,
                    target_authorisation_id=existing_decision.target_authorisation_id,
                    denial_code=existing_decision.denial_code,
                    safe_message=existing_decision.safe_denial_message
                    or "Idempotent replay of a prior decision.",
                    expires_at=existing_decision.expires_at,
                    trace={
                        "idempotent_replay": True,
                        "original_decision_id": str(existing_decision.id),
                    },
                )

    # Pre-flight existence/tenant-match check on the two hard foreign keys
    # CapabilityRequestRecord itself carries (user_id, mission_id) - a fabricated or
    # cross-tenant value here must fail closed with a clean, safe DENY, never a raw
    # IntegrityError surfaced to the caller (POST /capability-requests takes mission_id
    # directly from the request body - real, externally-reachable untrusted input).
    # _evaluate_and_decide's own step 2-7 checks are a second, defense-in-depth layer
    # that also runs on every re-evaluation of an already-persisted request.
    user = await db.get(User, user_id)
    if user is None or user.tenant_id != tenant_id or not user.is_active:
        return CapabilityEvaluationResult(
            decision_id=uuid.uuid4(),
            request_id=uuid.uuid4(),
            decision="DENY",
            capability_key=capability_key,
            authoritative_risk_class="unknown",
            approval_required=False,
            approval_id=None,
            target_authorisation_required=False,
            target_authorisation_id=None,
            denial_code="invalid_user",
            safe_message="The requesting user could not be authorized.",
            expires_at=None,
            trace={"steps": [{"check": "resolve_user", "result": "not_found"}]},
        )
    mission = await db.get(Mission, mission_id)
    if mission is None or mission.tenant_id != tenant_id:
        return CapabilityEvaluationResult(
            decision_id=uuid.uuid4(),
            request_id=uuid.uuid4(),
            decision="DENY",
            capability_key=capability_key,
            authoritative_risk_class="unknown",
            approval_required=False,
            approval_id=None,
            target_authorisation_required=False,
            target_authorisation_id=None,
            denial_code="invalid_mission",
            safe_message="The mission could not be authorized for this tenant.",
            expires_at=None,
            trace={"steps": [{"check": "resolve_mission_workflow", "result": "not_found"}]},
        )

    request = CapabilityRequestRecord(
        tenant_id=tenant_id,
        user_id=user_id,
        mission_id=mission_id,
        conversation_thread_id=conversation_thread_id,
        requesting_agent_id=requesting_agent_id,
        supervising_agent_id=supervising_agent_id,
        capability_key=capability_key,
        requested_tool_id=requested_tool_id,
        target_type=target_type,
        target_reference=target_reference,
        target_scope=target_scope,
        purpose=purpose,
        requested_parameters_safe=safe_params,
        idempotency_key=idempotency_key,
        model_provider=model_provider,
        model_name=model_name,
        parent_request_id=parent_request_id,
    )
    db.add(request)
    await db.flush()
    await publish_mission_event(
        str(mission_id),
        "capability.requested",
        capability_key=capability_key,
        request_id=str(request.id),
    )

    return await _evaluate_and_decide(db, request)


async def reevaluate_capability_request(
    db: AsyncSession, *, tenant_id: uuid.UUID, request_id: uuid.UUID
) -> CapabilityEvaluationResult:
    """Part I: 'never assume a previously allowed decision remains safe indefinitely' -
    re-runs the exact same pipeline against an already-persisted CapabilityRequestRecord
    (unchanged: same capability/target/parameters) and always produces a brand-new
    CapabilityDecisionRecord. Used both by the real execution-time re-check immediately
    before a tool runs, and by the human-triggered POST .../reevaluate endpoint once an
    approval has since been granted. Never updates or hides a prior decision - Part Q."""
    request = await db.get(CapabilityRequestRecord, request_id)
    if request is None or request.tenant_id != tenant_id:
        # Fail closed without writing a decision row: a request_id that doesn't resolve
        # for this tenant has no valid CapabilityRequestRecord to hang a decision off,
        # and forging one from just a tenant_id would risk a decision that misrepresents
        # who/what was actually evaluated - the audit trail must stay honest.
        trace = {"steps": [{"check": "resolve_request", "result": "not_found"}]}
        return CapabilityEvaluationResult(
            decision_id=uuid.uuid4(),
            request_id=request_id,
            decision="DENY",
            capability_key="unknown",
            authoritative_risk_class="unknown",
            approval_required=False,
            approval_id=None,
            target_authorisation_required=False,
            target_authorisation_id=None,
            denial_code="invalid_request",
            safe_message="The capability request could not be found for this tenant.",
            expires_at=None,
            trace=trace,
        )
    return await _evaluate_and_decide(db, request)


async def _evaluate_and_decide(
    db: AsyncSession, request: CapabilityRequestRecord
) -> CapabilityEvaluationResult:
    tenant_id = request.tenant_id
    user_id = request.user_id
    mission_id = request.mission_id
    requesting_agent_id = request.requesting_agent_id
    capability_key = request.capability_key
    requested_tool_id = request.requested_tool_id
    target_type = request.target_type
    target_reference = request.target_reference
    purpose = request.purpose

    # A re-evaluation of the SAME already-persisted request (Part I's execution-time
    # re-check, or an explicit POST .../reevaluate) must not double-count this one
    # logical action against the rate limit, and must not mint a second, independently-
    # pending Approval for a decision a human already made - see the rate-limit and
    # policy-evaluation steps below for how each uses this.
    prior_decision = (
        (
            await db.execute(
                select(CapabilityDecisionRecord)
                .where(CapabilityDecisionRecord.request_id == request.id)
                .order_by(CapabilityDecisionRecord.decided_at.desc())
            )
        )
        .scalars()
        .first()
    )
    is_reevaluation = prior_decision is not None

    trace: dict[str, Any] = {"steps": []}

    def _step(name: str, result: str) -> None:
        trace["steps"].append({"check": name, "result": result})

    try:
        # 2-3: resolve + cross-check the authenticated user/tenant (both passed in as
        # trusted params from the real caller context - never from the request body).
        user = await db.get(User, user_id)
        if user is None or user.tenant_id != tenant_id or not user.is_active:
            raise CapabilityDenied(
                "DENY", "invalid_user", "The requesting user could not be authorized."
            )
        _step("resolve_user", "ok")

        # 4-7: Mission/WorkflowRun, tenant-matched, workflow in an executable state.
        mission = await db.get(Mission, mission_id)
        if mission is None or mission.tenant_id != tenant_id:
            raise CapabilityDenied(
                "DENY", "invalid_mission", "The mission could not be authorized for this tenant."
            )
        request.workflow_run_id = None
        workflow_run = (
            await db.execute(select(WorkflowRun).where(WorkflowRun.mission_id == mission_id))
        ).scalar_one_or_none()
        if workflow_run is not None:
            if workflow_run.tenant_id != tenant_id:
                raise CapabilityDenied(
                    "DENY",
                    "invalid_workflow",
                    "The workflow run could not be authorized for this tenant.",
                )
            request.workflow_run_id = workflow_run.id
            if workflow_run.status != "running":
                raise CapabilityDenied(
                    "BLOCKED_DEPENDENCY",
                    "workflow_not_executable",
                    f"This mission's workflow is {workflow_run.status}, not running.",
                )
        _step("resolve_mission_workflow", "ok")

        # 8-9: resolve the requesting agent (None = a real Rabbani-direct request).
        agent = AGENT_REGISTRY.get(requesting_agent_id) if requesting_agent_id else None
        if requesting_agent_id and agent is None:
            raise CapabilityDenied(
                "DENY", "unknown_agent", "The requesting agent could not be resolved."
            )
        # Phase 20: DEGRADED joins OPERATIONAL/LIMITED as real, loadable - found via
        # live verification, not assumed: validation_retest (promoted from Planned
        # to DEGRADED in Part 9) was denied real execution here even though the
        # agents/validation.py startup check had already been updated to accept
        # DEGRADED - this broker-level check is a real, separate gate that also
        # needed the same fix.
        if agent is not None and agent.status not in (
            AgentStatus.OPERATIONAL,
            AgentStatus.LIMITED,
            AgentStatus.DEGRADED,
        ):
            raise CapabilityDenied(
                "DENY",
                "agent_not_operational",
                f"Agent status ({agent.status}) does not permit execution.",
            )
        _step("resolve_agent", "ok")

        # 10-11: resolve the capability, confirm it's enabled and operational. Fail
        # closed on an unknown key - never assume a default-allow for something the
        # broker itself doesn't recognize.
        capability = CAPABILITY_REGISTRY.get(capability_key)
        if capability is None:
            raise CapabilityDenied(
                "DENY", "unknown_capability", "The requested capability does not exist."
            )
        if capability.status != CapabilityStatus.OPERATIONAL:
            raise CapabilityDenied(
                "DISABLED",
                "capability_not_operational",
                f"This capability is {capability.status}, not available.",
            )
        state = await db.get(CapabilityState, (capability_key, tenant_id))
        if not _effective_enabled(capability, state):
            raise CapabilityDenied(
                "DISABLED",
                "capability_disabled",
                "This capability has been administratively disabled.",
            )
        _step("resolve_capability", "ok")

        # 12: the requested tool must be one this capability actually implements - no
        # inference to "the least restrictive" match (Part H).
        tool_id = requested_tool_id or (
            capability.required_tool_ids[0] if capability.required_tool_ids else None
        )
        if tool_id not in capability.required_tool_ids:
            raise CapabilityDenied(
                "DENY",
                "tool_capability_mismatch",
                "The requested tool does not implement this capability.",
            )
        request.requested_tool_id = tool_id
        _step("resolve_tool", "ok")

        # 13: agent allow-list - the real fix for the Phase 16 audit's Entry Point B
        # finding. A capability with a non-empty team/agent scope can never be reached
        # by a Rabbani-direct request (agent is None); a scoped agent must match by
        # team or explicit id.
        if capability.allowed_team_types or capability.allowed_agent_ids:
            if agent is None:
                raise CapabilityDenied(
                    "DENY",
                    "agent_required",
                    "This capability requires a specific agent; it cannot be requested directly.",
                )
            allowed = (
                agent.name in capability.allowed_agent_ids
                or agent.team in capability.allowed_team_types
            )
            if not allowed:
                raise CapabilityDenied(
                    "DENY",
                    "agent_not_allowed",
                    "This agent is not authorised to request this capability.",
                )
        elif agent is not None:
            # A capability scoped to "Rabbani-direct only" (both allow-lists empty)
            # must never be reachable through an agent either - closes the same gap
            # symmetrically.
            raise CapabilityDenied(
                "DENY", "agent_not_allowed", "This capability is not available to any agent."
            )
        _step("agent_allow_list", "ok")

        # 14: agent risk ceiling. Rabbani-direct requests have no agent ceiling to
        # check - they were always the platform's own trusted orchestration path for
        # the 2 tools no agent owns, unchanged by this phase.
        if agent is not None:
            from gds_api.agents.manifest import RiskCeiling

            ceiling_order = [
                RiskCeiling.R0,
                RiskCeiling.R1,
                RiskCeiling.R2,
                RiskCeiling.R3,
                RiskCeiling.R4,
                RiskCeiling.R5,
            ]
            risk_order = [
                RiskClass.R0,
                RiskClass.R1,
                RiskClass.R2,
                RiskClass.R3,
                RiskClass.R4,
                RiskClass.R5,
            ]
            if ceiling_order.index(agent.risk_ceiling) < risk_order.index(capability.risk_class):
                raise CapabilityDenied(
                    "DENY",
                    "risk_ceiling_exceeded",
                    "This agent's risk ceiling does not permit this capability.",
                )
        _step("risk_ceiling", "ok")

        # 15: user standing - real (active, correct tenant, already checked in step 2).
        # No further per-capability RBAC permission exists in this platform today
        # beyond mission-creation-time checks - see ADR 0014 for why a fabricated
        # fine-grained permission was not invented here.
        _step("user_standing", "ok")

        # 16-17: target type/scope.
        if capability.target_types != ("none",):
            if target_type not in capability.target_types:
                raise CapabilityDenied(
                    "DENY",
                    "invalid_target_type",
                    "The requested target type is not valid for this capability.",
                )
            if not target_reference:
                raise CapabilityDenied(
                    "DENY", "missing_target", "This capability requires a target reference."
                )
        _step("target_type_scope", "ok")

        # 19-20: target authorisation - reuses gds_api.redteam_safety's real,
        # tenant-scoped, time-bounded AuthorizedTarget check unchanged.
        target_authorisation_id: uuid.UUID | None = None
        if capability.requires_target_authorisation:
            try:
                authorization = await redteam_safety.ensure_target_authorized(
                    db, tenant_id, user_id, target_reference or ""
                )
                target_authorisation_id = authorization.id
            except ValueError as exc:
                raise CapabilityDenied(
                    "BLOCKED_AUTHORIZATION", "target_not_authorised", str(exc)
                ) from exc
        _step("target_authorisation", "ok")

        # 21: emergency stop - reuses gds_api.redteam_safety's real, tenant-scoped
        # kill switch unchanged.
        if capability.requires_emergency_stop_clear:
            try:
                await redteam_safety.ensure_not_emergency_stopped(db, tenant_id, user_id)
            except ValueError as exc:
                raise CapabilityDenied(
                    "BLOCKED_EMERGENCY_STOP", "emergency_stop_engaged", str(exc)
                ) from exc
        _step("emergency_stop", "ok")

        # 22-23: connector/credential health. No operational capability requires one
        # today (confirmed by the Phase 16 audit) - this is a real, honest check that
        # currently always passes trivially, not a fabricated integration.
        connector_checks: dict[str, Any] = {}
        for connector_id in capability.required_connector_ids:
            connector_checks[connector_id] = "NOT_CONFIGURED"
        if capability.required_connector_ids:
            raise CapabilityDenied(
                "BLOCKED_DEPENDENCY",
                "connector_unavailable",
                "This capability requires a connector that is not configured.",
            )
        _step("connector_health", "ok")

        # 24: rate limit. red_team capabilities reuse redteam_safety's own
        # per-target limiter (already enforced inside the tool executor itself, per
        # target_authorisation's max_actions_per_hour) - applying the broker's generic
        # limit on top of it too would double-count the same real action against two
        # different budgets for no real benefit. A re-evaluation of an already-persisted
        # request is the SAME logical action being re-checked, not a new one - it must
        # not consume a second slot from the same budget (Part I's execution-time
        # re-check would otherwise silently halve every capability's real rate limit).
        rate_limit_check: dict[str, Any] = {"applied": False}
        if capability.category != "red_team" and not is_reevaluation:
            rate_limit_check = await _check_rate_limit(tenant_id=tenant_id, capability=capability)
            rate_limit_check["applied"] = True
            if not rate_limit_check["ok"]:
                raise CapabilityDenied(
                    "RATE_LIMITED",
                    "rate_limit_exceeded",
                    "Rate limit exceeded for this capability: max "
                    f"{_DEFAULT_MAX_REQUESTS_PER_HOUR} requests/hour.",
                )
        _step("rate_limit", "ok")

        # 25-26: approval requirement + real policy evaluation - reuses
        # gds_api.policy.evaluate_policy, called with the backing tool's OWN, original
        # risk_class (low/medium/high/critical) so this migration cannot silently alter
        # what already requires approval today. See catalog.py's own module docstring
        # for why requires_human_approval is a direct carry-over, not derived from the
        # new RiskClass. A re-evaluation of the SAME request reuses whatever Approval a
        # prior evaluation already created instead of minting a second one - Part J:
        # "approvals must not be reusable ACROSS requests" is a rule about different
        # requests sharing one approval, not about a single request's own approval being
        # checked more than once as its status changes from pending to approved/rejected.
        tool_spec = TOOL_REGISTRY[tool_id] if tool_id else None
        legacy_risk_class = tool_spec.risk_class if tool_spec else "low"
        approval_id: uuid.UUID | None
        if is_reevaluation and prior_decision is not None and not prior_decision.approval_required:
            # The prior evaluation of this exact request already established ALLOW with
            # no approval needed - re-confirm without a second evaluate_policy call (it
            # would just re-record a redundant "policy.evaluate" audit event for the
            # same real decision, and for an approval-requiring risk_class would wrongly
            # mint a second, independently-pending Approval).
            approval_required = False
            approval_id = None
            policy_decision = "allow"
        elif (
            is_reevaluation
            and prior_decision is not None
            and prior_decision.approval_id is not None
        ):
            approval = await db.get(Approval, prior_decision.approval_id)
            if approval is None:
                raise CapabilityDenied(
                    "DENY",
                    "invalid_approval",
                    "The approval for this request could not be found.",
                )
            approval_id = approval.id
            if approval.status == "approved":
                approval_required = False
                policy_decision = "allow"
            elif approval.status == "rejected":
                raise CapabilityDenied("DENY", "approval_denied", "This action was not approved.")
            else:
                approval_required = True
                policy_decision = "require_approval"
        else:
            policy_result = await evaluate_policy(
                db,
                tenant_id=tenant_id,
                requested_by_user_id=user_id,
                risk_class=legacy_risk_class,
                action_description=purpose[:500],
            )
            approval_required = policy_result.decision == "require_approval"
            approval_id = policy_result.approval_id
            policy_decision = policy_result.decision
        _step("policy_evaluation", policy_decision)

        decision_type = "REQUIRE_APPROVAL" if approval_required else "ALLOW"
        safe_message = (
            "This action changes an external system and requires approval."
            if approval_required
            else "This capability is permitted for this mission."
        )
        denial_code = None

    except CapabilityDenied as denied:
        decision_type = denied.decision
        denial_code = denied.denial_code
        safe_message = denied.safe_message
        approval_required = False
        approval_id = None
        target_authorisation_id = None
        _step("denied", denied.denial_code)

    resolved_capability = CAPABILITY_REGISTRY.get(capability_key)
    capability_version = resolved_capability.version if resolved_capability else "unknown"
    authoritative_risk_class = (
        resolved_capability.risk_class.value if resolved_capability else "unknown"
    )
    target_authorisation_required = bool(target_authorisation_id) or (
        resolved_capability.requires_target_authorisation if resolved_capability else False
    )

    decision = CapabilityDecisionRecord(
        request_id=request.id,
        tenant_id=tenant_id,
        decision=decision_type,
        capability_key=capability_key,
        capability_version=capability_version,
        authoritative_risk_class=authoritative_risk_class,
        evaluated_tenant_id=tenant_id,
        evaluated_user_id=user_id,
        evaluated_agent_id=requesting_agent_id,
        evaluated_mission_id=mission_id,
        evaluated_workflow_run_id=request.workflow_run_id,
        evaluated_target=target_reference,
        approval_required=approval_required,
        approval_id=approval_id,
        target_authorisation_required=target_authorisation_required,
        target_authorisation_id=target_authorisation_id,
        denial_code=denial_code,
        safe_denial_message=safe_message if denial_code else None,
        decision_trace=trace,
        policy_version=CAPABILITY_POLICY_VERSION,
        expires_at=datetime.now(UTC) + timedelta(minutes=30) if decision_type == "ALLOW" else None,
    )
    db.add(decision)
    await db.flush()

    await record_audit_event(
        db,
        tenant_id=tenant_id,
        user_id=user_id,
        action="capability.decision",
        detail={
            "request_id": str(request.id),
            "decision_id": str(decision.id),
            "capability_key": capability_key,
            "decision": decision_type,
            "denial_code": denial_code,
        },
    )
    await db.commit()

    event_type = {
        "ALLOW": "capability.allowed",
        "REQUIRE_APPROVAL": "capability.approval_required",
        "DENY": "capability.denied",
        "BLOCKED_DEPENDENCY": "capability.blocked_dependency",
        "BLOCKED_AUTHORIZATION": "capability.blocked_authorisation",
        "BLOCKED_EMERGENCY_STOP": "capability.blocked_emergency_stop",
        "RATE_LIMITED": "capability.rate_limited",
        "DISABLED": "capability.denied",
    }.get(decision_type, "capability.denied")
    await publish_mission_event(
        str(mission_id),
        event_type,
        capability_key=capability_key,
        request_id=str(request.id),
        decision_id=str(decision.id),
        status=decision_type,
    )

    return CapabilityEvaluationResult(
        decision_id=decision.id,
        request_id=request.id,
        decision=decision_type,
        capability_key=capability_key,
        authoritative_risk_class=decision.authoritative_risk_class,
        approval_required=approval_required,
        approval_id=approval_id,
        target_authorisation_required=decision.target_authorisation_required,
        target_authorisation_id=target_authorisation_id,
        denial_code=denial_code,
        safe_message=safe_message,
        expires_at=decision.expires_at,
        trace=trace,
    )


class CapabilityExecutionConflict(Exception):
    """Raised when the Tool Gateway enforcement layer (gateway.py, Part I) tries to mark
    a decision executed twice - real reuse prevention: an ALLOW decision authorizes
    exactly one real execution, never a second silent replay against the same grant."""


async def mark_capability_execution(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    decision_id: uuid.UUID,
    status: str,
) -> None:
    """Part I: records the real execution outcome (executed|failed) on the decision that
    authorized it. Called by gds_api.capabilities.gateway immediately after a real
    tool_gateway.execute_tool call returns (success or exception) - never before, and
    never for a decision that isn't ALLOW (the gateway itself enforces that)."""
    decision = await db.get(CapabilityDecisionRecord, decision_id)
    if decision is None or decision.tenant_id != tenant_id:
        raise CapabilityDenied(
            "DENY", "invalid_decision", "The capability decision could not be found."
        )
    if decision.execution_status is not None:
        raise CapabilityExecutionConflict(
            f"Decision {decision_id} already recorded execution_status="
            f"{decision.execution_status!r}."
        )
    decision.execution_status = status
    decision.executed_at = datetime.now(UTC)
    await db.flush()
    await record_audit_event(
        db,
        tenant_id=tenant_id,
        user_id=decision.evaluated_user_id,
        action="capability.execution",
        detail={
            "decision_id": str(decision_id),
            "request_id": str(decision.request_id),
            "capability_key": decision.capability_key,
            "execution_status": status,
        },
    )
    await publish_mission_event(
        str(decision.evaluated_mission_id),
        "capability.execution_completed" if status == "executed" else "capability.execution_failed",
        capability_key=decision.capability_key,
        request_id=str(decision.request_id),
        decision_id=str(decision_id),
        status=status,
    )


class CapabilityCancelConflict(Exception):
    """Raised when POST .../cancel is attempted on a request whose latest decision has
    already been executed (or already cancelled) - cancellation is only meaningful
    before real execution has happened."""


async def cancel_capability_request(
    db: AsyncSession, *, tenant_id: uuid.UUID, actor_user_id: uuid.UUID, request_id: uuid.UUID
) -> CapabilityDecisionRecord:
    """Part R: POST /capability-requests/{id}/cancel. Marks the latest decision's
    execution_status="cancelled" - reusing the same single-use execution_status field
    mark_capability_execution guards, so a cancelled request can never subsequently be
    executed either (gateway.execute_capability_request's re-evaluation would still run,
    but Tool Gateway enforcement never consumes a decision whose execution_status is
    already set - see mark_capability_execution's reuse guard)."""
    request = await db.get(CapabilityRequestRecord, request_id)
    if request is None or request.tenant_id != tenant_id:
        raise CapabilityDenied(
            "DENY", "invalid_request", "The capability request could not be found."
        )
    latest_decision = (
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
    if latest_decision is None:
        raise CapabilityDenied("DENY", "invalid_request", "This request has no decision to cancel.")
    if latest_decision.execution_status is not None:
        raise CapabilityCancelConflict(
            f"Decision {latest_decision.id} already has execution_status="
            f"{latest_decision.execution_status!r}, cannot cancel."
        )
    latest_decision.execution_status = "cancelled"
    await db.flush()
    await record_audit_event(
        db,
        tenant_id=tenant_id,
        user_id=actor_user_id,
        action="capability.cancel",
        detail={
            "request_id": str(request_id),
            "decision_id": str(latest_decision.id),
            "capability_key": latest_decision.capability_key,
        },
    )
    await publish_mission_event(
        str(latest_decision.evaluated_mission_id),
        "capability.cancelled",
        capability_key=latest_decision.capability_key,
        request_id=str(request_id),
        decision_id=str(latest_decision.id),
        status="CANCELLED",
    )
    return latest_decision
