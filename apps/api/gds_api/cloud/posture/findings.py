"""EDP-009 Part 2, Sections 21-27: connects a real PASS/FAIL `CloudPolicyEvaluation`
result to the existing, platform-wide `Finding` model - never a second,
disconnected finding type Executive/Purple Command can't understand (ADR 0051
Decision D6). Reuses `gds_api.finding_lifecycle`'s real 15-state machine directly;
every status change here goes through `validate_finding_transition()` first,
exactly like every other real Finding-status change in this codebase.

`correlate_findings()` is only ever called after `run_environment_evaluation()`
has fully, successfully completed (see `gds_api.tool_gateway._evaluate_cloud_posture`)
- Section 23's "partial discovery/evaluation must never resolve a finding" rule is
satisfied structurally: if this function is never reached (the core loop raised),
no Finding is ever touched.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.audit import record_audit_event
from gds_api.cloud.posture.registry import PolicyDefinition, get_policy
from gds_api.evidence import create_evidence
from gds_api.finding_lifecycle import FindingStatus, validate_finding_transition
from gds_api.models import (
    CloudFindingContext,
    CloudFindingStatusHistory,
    CloudPolicyEvaluation,
    CloudPostureEvaluationRun,
    Finding,
)

# The single-hop walk a brand-new CSPM-detected failure takes to reach VALIDATED -
# CSPM's own deterministic evaluation IS the validation (Section 26's deterministic
# explanations are the proof), so there is no separate human validation gate the
# way a threat-intel Finding might have one. Mirrors
# tool_gateway._create_incident_from_findings's own precedent of driving real
# intermediate transitions inline rather than skipping any - Phase 20 Part 9's own
# rule against a lifecycle shortcut.
_CREATION_WALK: tuple[FindingStatus, ...] = (
    FindingStatus.TRIAGED,
    FindingStatus.ENRICHED,
    FindingStatus.PRIORITISED,
    FindingStatus.AWAITING_VALIDATION,
    FindingStatus.VALIDATED,
)

# The walk a later authoritative PASS takes to reach a real, database-supported
# "resolved" state. finding_lifecycle.py has no direct VALIDATED -> CLOSED
# transition (it models a human remediation workflow: plan, apply, retest,
# confirm, close) - CLOSED is the only state CLOSED -> REOPENED is itself
# available *from*, so resolution is walked all the way through rather than
# stopped at REMEDIATED, so a later re-failure can use the one real reopen path
# Section 21's "preserve one authoritative lifecycle" rule leaves available. Every
# hop is genuinely, individually validated - never a fabricated shortcut.
_RESOLUTION_WALK: dict[FindingStatus, tuple[FindingStatus, ...]] = {
    FindingStatus.VALIDATED: (
        FindingStatus.REMEDIATION_PLANNED,
        FindingStatus.REMEDIATION_IN_PROGRESS,
        FindingStatus.AWAITING_RETEST,
        FindingStatus.REMEDIATED,
        FindingStatus.CLOSED,
    ),
    FindingStatus.REMEDIATION_PLANNED: (
        FindingStatus.REMEDIATION_IN_PROGRESS,
        FindingStatus.AWAITING_RETEST,
        FindingStatus.REMEDIATED,
        FindingStatus.CLOSED,
    ),
    FindingStatus.REMEDIATION_IN_PROGRESS: (
        FindingStatus.AWAITING_RETEST,
        FindingStatus.REMEDIATED,
        FindingStatus.CLOSED,
    ),
    FindingStatus.AWAITING_RETEST: (FindingStatus.REMEDIATED, FindingStatus.CLOSED),
    FindingStatus.RETEST_FAILED: (
        FindingStatus.REMEDIATION_PLANNED,
        FindingStatus.REMEDIATION_IN_PROGRESS,
        FindingStatus.AWAITING_RETEST,
        FindingStatus.REMEDIATED,
        FindingStatus.CLOSED,
    ),
}

_REOPEN_WALK: tuple[FindingStatus, ...] = (FindingStatus.REOPENED, *_CREATION_WALK)

_RESOLVED_STATUSES = frozenset({FindingStatus.REMEDIATED.value, FindingStatus.CLOSED.value})

_MAX_FACTS_BYTES = 4_000


def _bounded_facts(facts: dict[str, object]) -> dict[str, object]:
    try:
        serialized = json.dumps(facts, default=str)
    except (TypeError, ValueError):
        return {"_truncated": True, "_reason": "facts were not JSON-serializable"}
    if len(serialized.encode("utf-8")) <= _MAX_FACTS_BYTES:
        return facts
    return {"_truncated": True, "_reason": "facts exceeded the evidence size bound"}


async def _walk_status(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    finding: Finding,
    steps: tuple[FindingStatus, ...],
    evaluation_run_id: uuid.UUID,
    evaluation_record_id: uuid.UUID,
    reopen_reason: str | None = None,
) -> None:
    for step in steps:
        previous = finding.status
        reason = reopen_reason if step == FindingStatus.REOPENED else None
        validate_finding_transition(previous, step.value, reopen_reason=reason)
        finding.status = step.value
        db.add(
            CloudFindingStatusHistory(
                tenant_id=tenant_id,
                finding_id=finding.id,
                previous_status=previous,
                new_status=step.value,
                reason=reason,
                evaluation_run_id=evaluation_run_id,
                evaluation_record_id=evaluation_record_id,
            )
        )
    await db.flush()


async def _create_finding(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    environment_id: uuid.UUID,
    provider: str,
    record: CloudPolicyEvaluation,
    policy: PolicyDefinition,
    run: CloudPostureEvaluationRun,
    user_id: uuid.UUID,
) -> None:
    now = datetime.now(UTC)
    finding = Finding(
        tenant_id=tenant_id,
        source="cspm",
        external_id=record.policy_id,
        title=policy.name,
        description=record.explanation,
        severity=policy.severity.value,
        risk_class=policy.severity.value,
        status=FindingStatus.OBSERVED.value,
        raw_data={
            "policy_id": record.policy_id,
            "policy_version": record.policy_version,
            "facts": _bounded_facts(dict(record.facts)),
        },
        recommended_remediation=(
            policy.remediation_guidance.objective if policy.remediation_guidance else None
        ),
    )
    db.add(finding)
    await db.flush()
    # Section 19's own schema-ready CloudPolicyEvaluation.finding_id column
    # (declared in sub-phase 22.2.3, "always null until [Finding correlation]
    # exists") - a real, disclosed gap left over from before sub-phase 22.2.4
    # ever built Finding correlation: it was never actually backfilled once
    # that correlation went live. Fixed here, the real moment a Finding first
    # exists for this evaluation record.
    record.finding_id = finding.id
    db.add(
        CloudFindingStatusHistory(
            tenant_id=tenant_id,
            finding_id=finding.id,
            previous_status="",
            new_status=FindingStatus.OBSERVED.value,
            evaluation_run_id=run.id,
            evaluation_record_id=record.id,
        )
    )
    await _walk_status(
        db,
        tenant_id=tenant_id,
        finding=finding,
        steps=_CREATION_WALK,
        evaluation_run_id=run.id,
        evaluation_record_id=record.id,
    )

    evidence_summary = {
        "finding_id": str(finding.id),
        "policy_id": record.policy_id,
        "policy_version": record.policy_version,
        "environment_id": str(environment_id),
        "asset_id": str(record.asset_id) if record.asset_id else None,
        "evaluation_run_id": str(run.id),
        "evaluation_record_id": str(record.id),
        "evaluation_time": record.evaluation_time.isoformat() if record.evaluation_time else None,
        "explanation": record.explanation,
        "facts": _bounded_facts(dict(record.facts)),
    }
    evidence = await create_evidence(
        db,
        tenant_id=tenant_id,
        user_id=user_id,
        subject_type="cloud_finding",
        subject_id=str(finding.id),
        content=json.dumps(evidence_summary, default=str).encode(),
        content_type="application/json",
        filename=f"cloud-finding-{finding.id}.json",
    )

    context = CloudFindingContext(
        tenant_id=tenant_id,
        finding_id=finding.id,
        cloud_environment_id=environment_id,
        cloud_asset_id=record.asset_id,
        provider=provider,
        policy_id=record.policy_id,
        policy_version=record.policy_version,
        first_detected_at=now,
        last_detected_at=now,
        last_evaluated_at=now,
        last_evaluation_run_id=run.id,
        last_evaluation_record_id=record.id,
        evidence_id=evidence.id,
    )
    db.add(context)
    await db.flush()
    run.findings_created += 1
    await record_audit_event(
        db,
        tenant_id=tenant_id,
        user_id=user_id,
        action="cloud.posture_finding_created",
        detail={
            "finding_id": str(finding.id),
            "policy_id": record.policy_id,
            "environment_id": str(environment_id),
        },
    )


async def _handle_fail(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    environment_id: uuid.UUID,
    provider: str,
    record: CloudPolicyEvaluation,
    policy: PolicyDefinition,
    context: CloudFindingContext | None,
    run: CloudPostureEvaluationRun,
    user_id: uuid.UUID,
) -> None:
    if context is None:
        await _create_finding(
            db,
            tenant_id=tenant_id,
            environment_id=environment_id,
            provider=provider,
            record=record,
            policy=policy,
            run=run,
            user_id=user_id,
        )
        return

    finding = await db.get(Finding, context.finding_id)
    assert finding is not None
    record.finding_id = finding.id
    now = datetime.now(UTC)

    if finding.status in _RESOLVED_STATUSES:
        await _walk_status(
            db,
            tenant_id=tenant_id,
            finding=finding,
            steps=_REOPEN_WALK,
            evaluation_run_id=run.id,
            evaluation_record_id=record.id,
            reopen_reason=(
                f"Cloud posture evaluation run {run.id} found policy "
                f"'{record.policy_id}' failing again after a prior resolution."
            ),
        )
        context.last_detected_at = now
        context.last_evaluated_at = now
        context.last_evaluation_run_id = run.id
        context.last_evaluation_record_id = record.id
        context.policy_version = record.policy_version
        context.resolution_time = None
        await db.flush()
        run.findings_updated += 1
        await record_audit_event(
            db,
            tenant_id=tenant_id,
            user_id=user_id,
            action="cloud.posture_finding_reopened",
            detail={
                "finding_id": str(finding.id),
                "policy_id": record.policy_id,
                "evaluation_run_id": str(run.id),
            },
        )
        return

    # Still open/active - a re-detection, not a new finding and not a status
    # change (Section 22's own "repeated failures update the existing finding").
    context.last_detected_at = now
    context.last_evaluated_at = now
    context.last_evaluation_run_id = run.id
    context.last_evaluation_record_id = record.id
    context.policy_version = record.policy_version
    await db.flush()
    run.findings_unchanged += 1


async def _handle_pass(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    record: CloudPolicyEvaluation,
    context: CloudFindingContext | None,
    run: CloudPostureEvaluationRun,
    user_id: uuid.UUID,
) -> None:
    if context is None:
        return  # nothing to resolve - this asset/policy has never failed

    finding = await db.get(Finding, context.finding_id)
    assert finding is not None
    record.finding_id = finding.id
    now = datetime.now(UTC)

    if finding.status in _RESOLVED_STATUSES:
        context.last_evaluated_at = now
        await db.flush()
        return  # already resolved - a real re-confirming PASS, not a new event

    steps = _RESOLUTION_WALK.get(FindingStatus(finding.status))
    if steps is None:
        # A status this walk has no real resolution path from (e.g. still
        # OBSERVED/TRIAGED mid-creation-walk in the same transaction, or a
        # governed state a future suppression sub-phase owns) - never guess a
        # transition finding_lifecycle.py doesn't itself support.
        context.last_evaluated_at = now
        await db.flush()
        return

    await _walk_status(
        db,
        tenant_id=tenant_id,
        finding=finding,
        steps=steps,
        evaluation_run_id=run.id,
        evaluation_record_id=record.id,
    )
    context.last_evaluated_at = now
    context.resolution_time = now
    context.last_evaluation_run_id = run.id
    context.last_evaluation_record_id = record.id
    await db.flush()
    run.findings_resolved += 1
    await record_audit_event(
        db,
        tenant_id=tenant_id,
        user_id=user_id,
        action="cloud.posture_finding_resolved",
        detail={
            "finding_id": str(finding.id),
            "policy_id": record.policy_id,
            "evaluation_run_id": str(run.id),
        },
    )


async def correlate_findings(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    environment_id: uuid.UUID,
    provider: str,
    run: CloudPostureEvaluationRun,
    user_id: uuid.UUID,
) -> None:
    """The real correlation pass - only ever called after
    `run_environment_evaluation()` has fully, successfully completed. Iterates
    every PASS/FAIL `CloudPolicyEvaluation` row this run just created; every
    other result (NOT_APPLICABLE/UNSUPPORTED/SKIPPED/ERROR/INDETERMINATE) is
    Section 71's own explicit "never resolve, never create, never fail a finding
    from" list and is skipped entirely."""
    result = await db.execute(
        select(CloudPolicyEvaluation).where(
            CloudPolicyEvaluation.evaluation_run_id == run.id,
            CloudPolicyEvaluation.result.in_(("pass", "fail")),
        )
    )
    for record in result.scalars().all():
        policy = get_policy(record.policy_id)
        if policy is None or policy.severity.value == "informational":
            # Section 21's own rule (ADR 0051 Decision D6): an INFORMATIONAL
            # policy's FAIL is an observed fact, never a platform Finding - there
            # is no risk to approve, suppress, or remediate.
            continue

        context_result = await db.execute(
            select(CloudFindingContext).where(
                CloudFindingContext.tenant_id == tenant_id,
                CloudFindingContext.cloud_environment_id == environment_id,
                CloudFindingContext.policy_id == record.policy_id,
                CloudFindingContext.cloud_asset_id == record.asset_id,
            )
        )
        context = context_result.scalars().first()

        if record.result == "fail":
            await _handle_fail(
                db,
                tenant_id=tenant_id,
                environment_id=environment_id,
                provider=provider,
                record=record,
                policy=policy,
                context=context,
                run=run,
                user_id=user_id,
            )
        else:
            await _handle_pass(
                db, tenant_id=tenant_id, record=record, context=context, run=run, user_id=user_id
            )
    await db.flush()


class CloudFindingNotFound(Exception):
    pass


async def get_cloud_finding_context(
    db: AsyncSession, *, tenant_id: uuid.UUID, finding_id: uuid.UUID
) -> tuple[Finding, CloudFindingContext]:
    """The real join a `/cloud/findings/{id}` endpoint needs - `Finding` plus its
    1:1 `CloudFindingContext` row. 404s (via the caller) if either half is
    missing or belongs to a different tenant, never returns a partial result."""
    finding = await db.get(Finding, finding_id)
    if finding is None or finding.tenant_id != tenant_id or finding.source != "cspm":
        raise CloudFindingNotFound(f"Cloud finding {finding_id} not found")
    context = (
        await db.execute(
            select(CloudFindingContext).where(CloudFindingContext.finding_id == finding_id)
        )
    ).scalars().first()
    if context is None:
        raise CloudFindingNotFound(f"Cloud finding {finding_id} has no cloud context recorded")
    return finding, context


async def list_cloud_findings(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    environment_id: uuid.UUID | None = None,
    asset_id: uuid.UUID | None = None,
    policy_id: str | None = None,
    severity: str | None = None,
    status_filter: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[tuple[Finding, CloudFindingContext]]:
    """Real, paginated join over `Finding`(source="cspm") + `CloudFindingContext` -
    the same offset/limit convention every other list endpoint in this codebase
    uses (`gds_api.cloud_api`'s own list functions)."""
    limit = max(1, min(limit, 200))
    query = (
        select(Finding, CloudFindingContext)
        .join(CloudFindingContext, CloudFindingContext.finding_id == Finding.id)
        .where(Finding.tenant_id == tenant_id, Finding.source == "cspm")
    )
    if environment_id is not None:
        query = query.where(CloudFindingContext.cloud_environment_id == environment_id)
    if asset_id is not None:
        query = query.where(CloudFindingContext.cloud_asset_id == asset_id)
    if policy_id is not None:
        query = query.where(CloudFindingContext.policy_id == policy_id)
    if severity is not None:
        query = query.where(Finding.severity == severity)
    if status_filter is not None:
        query = query.where(Finding.status == status_filter)
    query = query.order_by(Finding.created_at.desc()).limit(limit).offset(offset)
    result = await db.execute(query)
    return [(row[0], row[1]) for row in result.all()]


async def list_finding_status_history(
    db: AsyncSession, *, tenant_id: uuid.UUID, finding_id: uuid.UUID
) -> list[CloudFindingStatusHistory]:
    result = await db.execute(
        select(CloudFindingStatusHistory)
        .where(
            CloudFindingStatusHistory.tenant_id == tenant_id,
            CloudFindingStatusHistory.finding_id == finding_id,
        )
        .order_by(CloudFindingStatusHistory.created_at.asc())
    )
    return list(result.scalars().all())
