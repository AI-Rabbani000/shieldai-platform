"""EDP-009 Part 2, Sections 28-30: governed cloud finding suppression, accepted
risk, and (finding-scoped) policy exceptions. A genuinely new concept in this
codebase - the pre-implementation audit (ADR 0051) found no prior suppression/
waiver/accepted-risk model anywhere.

Reuses the existing `Approval`/`Policy` (risk_class -> requires_approval) tables
directly via `gds_api.policy.evaluate_policy` - the same governed mechanism
`Finding.approval_id` already relies on - never a second, parallel approval
mechanism (Section 29's own "Approval remains authoritative" rule).

Scope decision, disclosed here rather than left implicit: Section 30's own
"Policy Exceptions" describes both finding-scoped and broader (policy-wide,
environment-wide, asset-group-wide) exception scopes. This sub-phase implements
only the finding-scoped case, reusing `CloudFindingSuppression` with
`suppression_type in ("temporary_exception", "not_applicable_override")` - a
single-finding exception is structurally identical to a suppression at this
grain. Broader, non-finding-scoped exceptions (an exception that applies before
any finding exists yet) are deferred to a later sub-phase; Section 30's own
"Do not create a wildcard global exception without strict authorization" rule
makes this a deliberate, conservative scope choice, not an oversight.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.audit import record_audit_event
from gds_api.evidence import create_evidence
from gds_api.finding_lifecycle import FindingStatus, validate_finding_transition
from gds_api.models import CloudFindingSuppression, Finding
from gds_api.policy import evaluate_policy

# Section 28's own real vocabulary.
SUPPRESSION_TYPES: frozenset[str] = frozenset(
    {
        "false_positive",
        "compensating_control",
        "temporary_exception",
        "accepted_risk",
        "test_environment",
        "not_applicable_override",
    }
)

# Terminal statuses - a suppression in one of these never transitions again on
# its own (a new request_suppression() call, not a status refresh, is the only
# way to supersede one).
_TERMINAL_STATUSES = frozenset({"rejected", "expired"})


class InvalidSuppressionType(ValueError):
    pass


class SuppressionNotFound(Exception):
    pass


class DuplicateActiveSuppression(Exception):
    pass


async def _finding_risk_class(finding: Finding) -> str:
    # Finding.risk_class is set for most findings (triage_finding's own
    # deterministic rule) but is nullable on the model - severity is the one
    # field guaranteed to be a real, non-null CSPM value (gds_api.cloud.posture.
    # findings._create_finding always sets both to the same policy severity
    # value), so it is the safe fallback, never a guess.
    return finding.risk_class or finding.severity


async def request_suppression(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    finding_id: uuid.UUID,
    suppression_type: str,
    reason: str,
    expiry_time: datetime | None = None,
    review_date: datetime | None = None,
) -> CloudFindingSuppression:
    """Section 28's own required fields, all populated. Section 29's own rule -
    "Analysts may request suppression" - is enforced by the caller's own RBAC
    check (cloud:findings:suppress), not here; this function only enforces that
    the request is real and non-duplicate."""
    if suppression_type not in SUPPRESSION_TYPES:
        raise InvalidSuppressionType(
            f"'{suppression_type}' is not a real suppression type - must be one of "
            f"{sorted(SUPPRESSION_TYPES)}"
        )
    if not reason.strip():
        raise ValueError("Suppression reason must not be empty")

    finding = await db.get(Finding, finding_id)
    if finding is None or finding.tenant_id != tenant_id:
        raise SuppressionNotFound(f"Finding {finding_id} not found")

    existing = (
        await db.execute(
            select(CloudFindingSuppression).where(
                CloudFindingSuppression.tenant_id == tenant_id,
                CloudFindingSuppression.finding_id == finding_id,
                CloudFindingSuppression.status.in_(("pending_approval", "active")),
            )
        )
    ).scalars().first()
    if existing is not None:
        raise DuplicateActiveSuppression(
            f"Finding {finding_id} already has an active or pending suppression "
            f"({existing.id}) - review or let it resolve before requesting another."
        )

    risk_class = await _finding_risk_class(finding)
    decision = await evaluate_policy(
        db,
        tenant_id=tenant_id,
        requested_by_user_id=user_id,
        risk_class=risk_class,
        action_description=(
            f"Suppress cloud finding {finding_id} (type={suppression_type}): {reason}"
        ),
    )

    suppression = CloudFindingSuppression(
        tenant_id=tenant_id,
        finding_id=finding_id,
        suppression_type=suppression_type,
        reason=reason,
        requested_by_user_id=user_id,
        approval_id=decision.approval_id,
        expiry_time=expiry_time,
        review_date=review_date,
        status="active" if decision.decision == "allow" else "pending_approval",
    )
    db.add(suppression)
    await db.flush()

    evidence_summary = {
        "suppression_id": str(suppression.id),
        "finding_id": str(finding_id),
        "suppression_type": suppression_type,
        "reason": reason,
        "risk_class": risk_class,
        "decision": decision.decision,
        "approval_id": str(decision.approval_id) if decision.approval_id else None,
        "requested_at": datetime.now(UTC).isoformat(),
    }
    evidence = await create_evidence(
        db,
        tenant_id=tenant_id,
        user_id=user_id,
        subject_type="cloud_finding_suppression",
        subject_id=str(suppression.id),
        content=json.dumps(evidence_summary, default=str).encode(),
        content_type="application/json",
        filename=f"cloud-finding-suppression-{suppression.id}.json",
    )
    suppression.evidence_id = evidence.id
    await db.flush()

    await record_audit_event(
        db,
        tenant_id=tenant_id,
        user_id=user_id,
        action="cloud.posture_suppression_requested",
        detail={
            "suppression_id": str(suppression.id),
            "finding_id": str(finding_id),
            "suppression_type": suppression_type,
            "decision": decision.decision,
        },
    )

    if suppression.status == "active":
        await _apply_active_effects(db, tenant_id=tenant_id, suppression=suppression)

    return suppression


async def _apply_active_effects(
    db: AsyncSession, *, tenant_id: uuid.UUID, suppression: CloudFindingSuppression
) -> None:
    """The one real side effect a suppression reaching `active` for the first
    time may have on `Finding` itself: `accepted_risk` drives a genuine, existing
    lifecycle transition (VALIDATED -> ACCEPTED_RISK is real and already legal in
    `gds_api.finding_lifecycle`). Every other suppression type never touches
    `Finding.status` or any `CloudPolicyEvaluation` row (Section 28's own "must
    not alter historical evaluation results" / "must not delete the finding")
    - operational surfacing is instead a query-time concern for whatever reads
    `CloudFindingSuppression.status`, not a state mutation here."""
    if suppression.suppression_type != "accepted_risk":
        return
    finding = await db.get(Finding, suppression.finding_id)
    if finding is None or finding.status == FindingStatus.ACCEPTED_RISK.value:
        return
    validate_finding_transition(finding.status, FindingStatus.ACCEPTED_RISK.value)
    finding.status = FindingStatus.ACCEPTED_RISK.value
    await db.flush()
    await record_audit_event(
        db,
        tenant_id=tenant_id,
        user_id=suppression.requested_by_user_id,
        action="cloud.posture_risk_accepted",
        detail={"finding_id": str(finding.id), "suppression_id": str(suppression.id)},
    )


async def refresh_suppression_status(
    db: AsyncSession, suppression: CloudFindingSuppression
) -> CloudFindingSuppression:
    """Section 28's own "suppression must expire automatically" rule, computed
    live rather than trusted from a possibly-stale stored value - mirrors
    `gds_api.cloud.assets.compute_freshness_state`'s own "recompute at read
    time, never assume the stored column is still true" precedent. Also the one
    place a `pending_approval` suppression discovers its real, current Approval
    decision and (for `accepted_risk`) drives the one-time Finding transition."""
    if suppression.status in _TERMINAL_STATUSES:
        return suppression

    now = datetime.now(UTC)
    if suppression.expiry_time is not None and now >= suppression.expiry_time:
        suppression.status = "expired"
        await db.flush()
        await record_audit_event(
            db,
            tenant_id=suppression.tenant_id,
            user_id=None,
            action="cloud.posture_suppression_expired",
            detail={
                "suppression_id": str(suppression.id),
                "finding_id": str(suppression.finding_id),
            },
        )
        return suppression

    if suppression.status == "pending_approval" and suppression.approval_id is not None:
        from gds_api.models import Approval  # local import: avoids a module-level

        approval = await db.get(Approval, suppression.approval_id)
        if approval is not None:
            if approval.status == "approved":
                suppression.status = "active"
                await db.flush()
                await _apply_active_effects(
                    db, tenant_id=suppression.tenant_id, suppression=suppression
                )
            elif approval.status == "rejected":
                suppression.status = "rejected"
                await db.flush()

    return suppression


async def reconcile_suppression_statuses(db: AsyncSession) -> int:
    """Called once at API startup (mirrors `reconcile_stale_evaluation_runs`/
    `reconcile_stale_discovery_jobs`'s own pattern) - refreshes every non-terminal
    suppression so an expiry or an approval decision made while the API process
    was down is reflected the moment it comes back up, never left silently stale."""
    result = await db.execute(
        select(CloudFindingSuppression).where(
            CloudFindingSuppression.status.in_(("pending_approval", "active"))
        )
    )
    suppressions = result.scalars().all()
    reconciled = 0
    for suppression in suppressions:
        previous_status = suppression.status
        await refresh_suppression_status(db, suppression)
        if suppression.status != previous_status:
            reconciled += 1
    if reconciled:
        await db.commit()
    return reconciled


async def is_operationally_suppressed(
    db: AsyncSession, *, finding_id: uuid.UUID
) -> bool:
    """Section 28's own "prevents operational surfacing" rule, real and live -
    a finding with an `active` suppression is excluded from default operational
    views (a later Cloud Findings Workspace sub-phase's own query), while the
    underlying failed evaluation remains fully visible to authorized users who
    query it directly (Section 71's own "keep the underlying failed evaluation
    visible to authorized users" rule) - suppressing *surfacing*, never the data."""
    result = await db.execute(
        select(CloudFindingSuppression).where(
            CloudFindingSuppression.finding_id == finding_id,
            CloudFindingSuppression.status.in_(("pending_approval", "active")),
        )
    )
    suppressions = result.scalars().all()
    for suppression in suppressions:
        await refresh_suppression_status(db, suppression)
    return any(s.status == "active" for s in suppressions)


async def list_suppressions_for_finding(
    db: AsyncSession, *, tenant_id: uuid.UUID, finding_id: uuid.UUID
) -> list[CloudFindingSuppression]:
    result = await db.execute(
        select(CloudFindingSuppression)
        .where(
            CloudFindingSuppression.tenant_id == tenant_id,
            CloudFindingSuppression.finding_id == finding_id,
        )
        .order_by(CloudFindingSuppression.created_at.desc())
    )
    suppressions = list(result.scalars().all())
    for suppression in suppressions:
        await refresh_suppression_status(db, suppression)
    return suppressions
