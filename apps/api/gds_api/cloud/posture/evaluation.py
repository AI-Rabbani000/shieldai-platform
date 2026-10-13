"""EDP-009 Part 2, Sections 18-20: Cloud Posture Evaluation Runs, Evaluation
Records, and Incremental Evaluation - the service layer that actually executes
`gds_api.cloud.posture.registry.POLICY_REGISTRY` policies against real,
already-persisted `CloudAsset`/`CloudAssetRelationship` inventory.

Execution model mirrors `gds_api.cloud.discovery.start_discovery` exactly (ADR
0051 Decision D7): a lightweight, human-triggered "browsing Mission" (never the
full Temporal MissionWorkflow), the same Capability Broker evaluate/execute
pipeline, synchronous-within-one-request completion, and startup-time stale-run
reconciliation - because policy evaluation is deterministic rule-matching, not an
LLM reasoning loop.

Section 20 (Incremental Evaluation): this sub-phase deliberately implements full,
bounded evaluation only (every enabled policy against every current asset) rather
than a change-triggered incremental engine - Section 20's own permission ("Do not
introduce a complex incremental engine if a full bounded evaluation is more
reliable at current scale. Measure before optimizing.") and the real, measured
Part 1 scale (~2,000 assets, sub-phase 22.1.12) both support this. The one real
incremental behaviour built: `requested_policy_ids` lets a caller scope a run to
specific policies (e.g. re-evaluate just the policies whose version changed)
without a full environment-wide run.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.audit import record_audit_event
from gds_api.cloud.assets import _bounded_metadata
from gds_api.cloud.environments import CloudEnvironmentNotFound
from gds_api.cloud.environments import get_environment as get_environment_service
from gds_api.cloud.posture.evaluator import EVALUATOR_VERSION, evaluate_policy
from gds_api.cloud.posture.registry import (
    POLICY_REGISTRY,
    PolicyDefinition,
    list_policies,
)
from gds_api.cloud.posture.taxonomy import ApplicabilityState, EvaluationResult, EvaluationType
from gds_api.cloud.posture.types import ApplicabilityResult, EvaluationContext, EvaluationOutcome
from gds_api.events import publish_mission_event
from gds_api.logging_config import get_logger
from gds_api.metrics import cloud_posture_evaluation_runs_total
from gds_api.mission_taxonomy import (
    MissionType,
    MissionTypeIneligible,
    validate_mission_type_eligibility,
)
from gds_api.models import (
    CloudAsset,
    CloudAssetRelationship,
    CloudEnvironment,
    CloudInventorySnapshot,
    CloudPolicyEvaluation,
    CloudPostureEvaluationRun,
    Mission,
)

_logger = get_logger("gds_api.cloud.posture.evaluation")


class CloudPostureEvaluationRunNotFound(Exception):
    pass


class CloudPostureEvaluationStartError(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)

# Section 9's own definitions, applied here: a policy that never became APPLICABLE
# still needs a real, persisted EvaluationResult - this is the one place that
# mapping happens, so it can never silently drift from Section 8/9's own taxonomy.
_APPLICABILITY_TO_RESULT: dict[ApplicabilityState, EvaluationResult] = {
    ApplicabilityState.NOT_APPLICABLE: EvaluationResult.NOT_APPLICABLE,
    ApplicabilityState.UNSUPPORTED: EvaluationResult.UNSUPPORTED,
    ApplicabilityState.SKIPPED: EvaluationResult.SKIPPED,
    ApplicabilityState.BLOCKED_BY_MISSING_DATA: EvaluationResult.INDETERMINATE,
}

_RESULT_TO_RUN_COUNTER: dict[EvaluationResult, str] = {
    EvaluationResult.PASS: "passed_count",
    EvaluationResult.FAIL: "failed_count",
    EvaluationResult.NOT_APPLICABLE: "not_applicable_count",
    EvaluationResult.UNSUPPORTED: "unsupported_count",
    EvaluationResult.SKIPPED: "skipped_count",
    EvaluationResult.ERROR: "error_count",
    EvaluationResult.INDETERMINATE: "indeterminate_count",
}


async def latest_snapshot(
    db: AsyncSession, *, tenant_id: uuid.UUID, environment_id: uuid.UUID
) -> CloudInventorySnapshot | None:
    result = await db.execute(
        select(CloudInventorySnapshot)
        .where(
            CloudInventorySnapshot.tenant_id == tenant_id,
            CloudInventorySnapshot.environment_id == environment_id,
        )
        .order_by(CloudInventorySnapshot.created_at.desc())
        .limit(1)
    )
    return result.scalars().first()


async def _environment_assets(
    db: AsyncSession, *, tenant_id: uuid.UUID, environment_id: uuid.UUID
) -> list[CloudAsset]:
    result = await db.execute(
        select(CloudAsset).where(
            CloudAsset.tenant_id == tenant_id, CloudAsset.environment_id == environment_id
        )
    )
    return list(result.scalars().all())


async def _relationships_for_asset(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    asset_id: uuid.UUID,
    relationship_types: tuple[str, ...],
) -> tuple[tuple[CloudAssetRelationship, ...], tuple[CloudAsset, ...]]:
    """Real relationships whose source is `asset_id` and whose type is one of the
    policy's own `required_relationships`, with the target asset for each fetched
    alongside it. Section 17's own "do not require Neo4j to evaluate every
    policy" rule: relational Postgres rows are the authoritative source here,
    the graph is never consulted."""
    if not relationship_types:
        return (), ()
    result = await db.execute(
        select(CloudAssetRelationship, CloudAsset)
        .join(CloudAsset, CloudAsset.id == CloudAssetRelationship.target_asset_id)
        .where(
            CloudAssetRelationship.tenant_id == tenant_id,
            CloudAssetRelationship.source_asset_id == asset_id,
            CloudAssetRelationship.relationship_type.in_(relationship_types),
        )
    )
    rows = result.all()
    return tuple(row[0] for row in rows), tuple(row[1] for row in rows)


def _safe_evaluate(
    policy: PolicyDefinition, context: EvaluationContext
) -> tuple[ApplicabilityResult, EvaluationOutcome | None]:
    """Section 9's own ERROR state: "The evaluator attempted execution but failed
    unexpectedly." A bug in one policy's evaluator function must never crash the
    whole run - caught here and turned into a real, honest ERROR result instead."""
    try:
        return evaluate_policy(policy, context)
    except Exception as exc:  # noqa: BLE001 - deliberately broad, see docstring
        _logger.warning(
            "cloud.posture.evaluator_error", policy_id=policy.policy_id, error=str(exc)
        )
        applicability = ApplicabilityResult(
            ApplicabilityState.APPLICABLE, "Applicability was not the failure point"
        )
        outcome = EvaluationOutcome(
            result=EvaluationResult.ERROR,
            explanation=(
                f"The evaluator for policy '{policy.policy_id}' raised an unexpected "
                "error during execution."
            ),
            error_category=type(exc).__name__,
            data_state="missing",
        )
        return applicability, outcome


def _result_for(
    applicability: ApplicabilityResult, outcome: EvaluationOutcome | None
) -> EvaluationResult:
    if outcome is not None:
        return outcome.result
    return _APPLICABILITY_TO_RESULT[applicability.state]


async def run_environment_evaluation(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    environment: CloudEnvironment,
    run: CloudPostureEvaluationRun,
    policy_ids: tuple[str, ...] = (),
) -> None:
    """The real evaluation core - iterates every applicable (policy, target) pair
    and persists a real CloudPolicyEvaluation row for each, updating `run`'s own
    counters in place. Never commits itself - the caller controls the transaction
    boundary, matching every other Part 1 tool's own convention."""
    policies = (
        [POLICY_REGISTRY[pid] for pid in policy_ids if pid in POLICY_REGISTRY]
        if policy_ids
        else list_policies(provider=environment.provider, enabled=True)
    )
    assets = await _environment_assets(db, tenant_id=tenant_id, environment_id=environment.id)
    snapshot = await latest_snapshot(db, tenant_id=tenant_id, environment_id=environment.id)

    run.assets_considered = len(assets)
    run.policies_considered = len(policies)

    for policy in policies:
        if policy.evaluation_type == EvaluationType.ENVIRONMENT_LEVEL:
            targets: list[CloudAsset | None] = [None]
        elif policy.asset_categories:
            targets = [a for a in assets if a.provider_category in policy.asset_categories]
        else:
            targets = []

        for asset in targets:
            start = datetime.now(UTC)
            relationships: tuple[CloudAssetRelationship, ...] = ()
            related_assets: tuple[CloudAsset, ...] = ()
            if policy.evaluation_type == EvaluationType.RELATIONSHIP_BASED and asset is not None:
                relationships, related_assets = await _relationships_for_asset(
                    db,
                    tenant_id=tenant_id,
                    asset_id=asset.id,
                    relationship_types=policy.required_relationships,
                )

            context = EvaluationContext(
                tenant_id=tenant_id,
                environment=environment,
                asset=asset,
                relationships=relationships,
                related_assets=related_assets,
                all_environment_assets=(
                    tuple(assets)
                    if policy.evaluation_type == EvaluationType.ENVIRONMENT_LEVEL
                    else ()
                ),
                snapshot=snapshot,
            )
            applicability, outcome = _safe_evaluate(policy, context)
            duration_ms = (datetime.now(UTC) - start).total_seconds() * 1000

            result = _result_for(applicability, outcome)
            run.evaluations_attempted += 1
            counter_name = _RESULT_TO_RUN_COUNTER[result]
            setattr(run, counter_name, getattr(run, counter_name) + 1)

            explanation = outcome.explanation if outcome is not None else applicability.reason
            facts = _bounded_metadata(dict(outcome.facts)) if outcome is not None else {}
            data_state = outcome.data_state if outcome is not None else "missing"
            error_category = outcome.error_category if outcome is not None else None

            record = CloudPolicyEvaluation(
                tenant_id=tenant_id,
                evaluation_run_id=run.id,
                environment_id=environment.id,
                asset_id=asset.id if asset is not None else None,
                policy_id=policy.policy_id,
                policy_version=policy.version,
                result=result.value,
                severity=policy.severity.value,
                applicability_state=applicability.state.value,
                applicability_reason=applicability.reason,
                facts=facts,
                explanation=explanation,
                duration_ms=duration_ms,
                evaluator_version=EVALUATOR_VERSION,
                data_state=data_state,
                snapshot_id=snapshot.id if snapshot is not None else None,
                error_category=error_category,
            )
            db.add(record)
    await db.flush()


async def start_evaluation(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    environment_id: uuid.UUID,
    policy_ids: list[str] | None = None,
) -> CloudPostureEvaluationRun:
    """Mirrors `gds_api.cloud.discovery.start_discovery` exactly: duplicate-run
    guard, mission-type eligibility, a lightweight "browsing Mission", and the
    same Capability Broker evaluate/execute pipeline every other real capability
    in this platform uses - never a second execution path. The actual
    CloudPostureEvaluationRun row is created by the capability's backing tool
    (`gds_api.tool_gateway._evaluate_cloud_posture`), not here - creating it
    before the broker's ALLOW/DENY decision would make that decision irrelevant.

    The Capability Broker imports are deliberately deferred (function-local, not
    module-level): `gds_api.capabilities.broker`/`gateway` both import
    `gds_api.tool_gateway.TOOL_REGISTRY`, and `tool_gateway` itself imports this
    module's `run_environment_evaluation` for its own tool executor - a
    module-level import here would be a real circular import, caught the first
    time anything imports `gds_api.tool_gateway` at all."""
    from gds_api.capabilities.broker import evaluate_capability_request
    from gds_api.capabilities.gateway import CapabilityExecutionDenied, execute_capability_request

    try:
        environment = await get_environment_service(
            db, tenant_id=tenant_id, environment_id=environment_id
        )
    except CloudEnvironmentNotFound as exc:
        raise CloudPostureEvaluationStartError(str(exc)) from exc

    active = (
        await db.execute(
            select(CloudPostureEvaluationRun).where(
                CloudPostureEvaluationRun.tenant_id == tenant_id,
                CloudPostureEvaluationRun.environment_id == environment_id,
                CloudPostureEvaluationRun.status.in_(("queued", "starting", "running")),
            )
        )
    ).scalars().first()
    if active is not None:
        raise CloudPostureEvaluationStartError(
            f"A posture evaluation run ({active.id}) is already {active.status} for "
            "this environment - wait for it to finish or cancel it before starting "
            "another."
        )

    try:
        await validate_mission_type_eligibility(
            db, tenant_id=tenant_id, mission_type=MissionType.CLOUD_SECURITY_ASSESSMENT.value
        )
    except MissionTypeIneligible as exc:
        raise CloudPostureEvaluationStartError(str(exc)) from exc

    mission = Mission(
        tenant_id=tenant_id,
        requested_by_user_id=user_id,
        objective=(
            f"Cloud posture evaluation: {environment.name} [cloud-posture:{environment.id}]"
        ),
        status="running",
        mission_type=MissionType.CLOUD_SECURITY_ASSESSMENT.value,
    )
    db.add(mission)
    await db.flush()

    try:
        eval_result = await evaluate_capability_request(
            db,
            tenant_id=tenant_id,
            user_id=user_id,
            mission_id=mission.id,
            requesting_agent_id=None,
            supervising_agent_id=None,
            capability_key="cloud.posture.evaluate_environment",
            requested_tool_id="evaluate_cloud_posture",
            target_type=None,
            target_reference=None,
            target_scope=None,
            purpose=f"Evaluate cloud posture for environment {environment.name}",
            requested_parameters={
                "environment_id": str(environment_id),
                "policy_ids": policy_ids or [],
            },
        )
        if eval_result.decision != "ALLOW":
            mission.status = "failed"
            await db.flush()
            raise CloudPostureEvaluationStartError(
                eval_result.safe_message or f"Capability request was {eval_result.decision}"
            )
        await execute_capability_request(
            db,
            tenant_id=tenant_id,
            request_id=eval_result.request_id,
            tool_name="evaluate_cloud_posture",
            input_data={
                "environment_id": str(environment_id),
                "policy_ids": policy_ids or [],
            },
            user_id=user_id,
            mission_id=mission.id,
        )
    except CapabilityExecutionDenied as exc:
        mission.status = "failed"
        await db.flush()
        raise CloudPostureEvaluationStartError(str(exc)) from exc

    mission.status = "completed"
    mission.completed_at = datetime.now(UTC)
    await db.flush()

    run = (
        (
            await db.execute(
                select(CloudPostureEvaluationRun)
                .where(CloudPostureEvaluationRun.mission_id == mission.id)
                .order_by(CloudPostureEvaluationRun.created_at.desc())
            )
        )
        .scalars()
        .first()
    )
    if run is None:
        raise CloudPostureEvaluationStartError(
            "Capability executed but no CloudPostureEvaluationRun record was created - "
            "this is a real, unexpected internal inconsistency, not a normal "
            "evaluation failure."
        )
    return run


async def get_evaluation_run(
    db: AsyncSession, *, tenant_id: uuid.UUID, run_id: uuid.UUID
) -> CloudPostureEvaluationRun | None:
    run = await db.get(CloudPostureEvaluationRun, run_id)
    if run is None or run.tenant_id != tenant_id:
        return None
    return run


async def list_evaluation_runs(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    environment_id: uuid.UUID | None = None,
    status_filter: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[CloudPostureEvaluationRun]:
    limit = max(1, min(limit, 200))
    query = select(CloudPostureEvaluationRun).where(
        CloudPostureEvaluationRun.tenant_id == tenant_id
    )
    if environment_id:
        query = query.where(CloudPostureEvaluationRun.environment_id == environment_id)
    if status_filter:
        query = query.where(CloudPostureEvaluationRun.status == status_filter)
    query = query.order_by(CloudPostureEvaluationRun.created_at.desc()).limit(limit).offset(offset)
    result = await db.execute(query)
    return list(result.scalars().all())


async def list_policy_evaluations(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    evaluation_run_id: uuid.UUID | None = None,
    asset_id: uuid.UUID | None = None,
    policy_id: str | None = None,
    result_filter: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[CloudPolicyEvaluation]:
    limit = max(1, min(limit, 200))
    query = select(CloudPolicyEvaluation).where(CloudPolicyEvaluation.tenant_id == tenant_id)
    if evaluation_run_id:
        query = query.where(CloudPolicyEvaluation.evaluation_run_id == evaluation_run_id)
    if asset_id:
        query = query.where(CloudPolicyEvaluation.asset_id == asset_id)
    if policy_id:
        query = query.where(CloudPolicyEvaluation.policy_id == policy_id)
    if result_filter:
        query = query.where(CloudPolicyEvaluation.result == result_filter)
    query = query.order_by(CloudPolicyEvaluation.evaluation_time.desc()).limit(limit).offset(offset)
    result = await db.execute(query)
    return list(result.scalars().all())


async def cancel_evaluation_run(
    db: AsyncSession, *, tenant_id: uuid.UUID, run_id: uuid.UUID, user_id: uuid.UUID
) -> CloudPostureEvaluationRun:
    run = await get_evaluation_run(db, tenant_id=tenant_id, run_id=run_id)
    if run is None:
        raise CloudPostureEvaluationRunNotFound("Cloud posture evaluation run not found")
    if run.status not in ("queued", "starting", "running"):
        raise CloudPostureEvaluationStartError(
            f"Cannot cancel an evaluation run in status '{run.status}' - only "
            "queued/starting/running runs can be cancelled."
        )
    run.status = "cancelled"
    run.completed_at = datetime.now(UTC)
    await db.flush()
    cloud_posture_evaluation_runs_total.labels(provider=run.provider, status="cancelled").inc()

    await record_audit_event(
        db,
        tenant_id=tenant_id,
        user_id=user_id,
        action="cloud.posture_evaluation_cancelled",
        detail={"evaluation_run_id": str(run.id), "environment_id": str(run.environment_id)},
    )
    if run.mission_id is not None:
        await publish_mission_event(
            str(run.mission_id),
            "CloudPostureEvaluationCancelled",
            evaluation_run_id=str(run.id),
            environment_id=str(run.environment_id),
        )
    return run


# Same real, disclosed fixed threshold gds_api.cloud.discovery uses for
# CloudDiscoveryJob - evaluation runs synchronously within one HTTP request (no
# background worker to restart mid-run), so the only real way a run gets stuck
# non-terminal is the API process itself dying mid-request.
_STALE_RUN_THRESHOLD = timedelta(hours=1)


async def reconcile_stale_evaluation_runs(db: AsyncSession) -> int:
    """Called once at API startup (gds_api.main's lifespan hook), mirroring
    gds_api.cloud.discovery.reconcile_stale_discovery_jobs exactly."""
    cutoff = datetime.now(UTC) - _STALE_RUN_THRESHOLD
    stale_runs = (
        (
            await db.execute(
                select(CloudPostureEvaluationRun).where(
                    CloudPostureEvaluationRun.status.in_(("queued", "starting", "running")),
                    CloudPostureEvaluationRun.started_at < cutoff,
                )
            )
        )
        .scalars()
        .all()
    )
    for run in stale_runs:
        run.status = "failed"
        run.completed_at = datetime.now(UTC)
        run.errors = [
            *run.errors,
            "Reconciled as failed at API startup - this run was left non-terminal by "
            "a previous process instance (a real crash or unclean restart, not a "
            "normal outcome), not because it genuinely failed mid-run.",
        ]
    if stale_runs:
        await db.commit()
        _logger.warning("cloud.posture.stale_evaluation_runs_reconciled", count=len(stale_runs))
    return len(stale_runs)
