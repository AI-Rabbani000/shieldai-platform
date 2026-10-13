"""EDP-009 Part 2, Section 54: the real HTTP surface over the CSPM assessment
layer built in sub-phases 22.2.1-22.2.5 - the code-defined Policy/Benchmark
Registry (read-only), Cloud Posture Evaluation Runs (Section 18), individual
policy evaluation records (Section 19), CSPM findings (the real join of platform
`Finding` + `CloudFindingContext`, Section 21), finding status history (Section
24), governed suppression (Section 28), and the honest coverage model (Section
31).

Follows `gds_api.cloud_api`'s own established conventions exactly: offset/limit
pagination (capped at 200), a bare list response (no envelope), `_x_to_out()`
converters, RBAC via `require_permission`. Section 54's own endpoint list is
"examples, not mandates" - this router implements a real, defensible subset
(reports/broader exceptions endpoints are deferred to a later sub-phase, matching
`gds_api.cloud.posture.suppression`'s own disclosed Section 30 scope decision).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.cloud.posture.coverage import (
    compute_environment_coverage,
    compute_registry_coverage,
)
from gds_api.cloud.posture.evaluation import (
    CloudPostureEvaluationRunNotFound,
    CloudPostureEvaluationStartError,
    cancel_evaluation_run,
    get_evaluation_run,
    list_evaluation_runs,
    list_policy_evaluations,
    start_evaluation,
)
from gds_api.cloud.posture.findings import (
    CloudFindingNotFound,
    get_cloud_finding_context,
    list_cloud_findings,
    list_finding_status_history,
)
from gds_api.cloud.posture.registry import (
    BenchmarkDefinition,
    PolicyDefinition,
    benchmark_coverage,
    get_benchmark,
    get_policy,
    list_benchmarks,
    list_policies,
)
from gds_api.cloud.posture.suppression import (
    DuplicateActiveSuppression,
    InvalidSuppressionType,
    SuppressionNotFound,
    list_suppressions_for_finding,
    request_suppression,
)
from gds_api.cloud.posture.taxonomy import PolicyDomain, PolicySeverity
from gds_api.db import get_db
from gds_api.models import (
    CloudFindingContext,
    CloudFindingSuppression,
    CloudPolicyEvaluation,
    Finding,
)
from gds_api.models import CloudPostureEvaluationRun as CloudPostureEvaluationRunModel
from gds_api.schemas import (
    CloudBenchmarkOut,
    CloudEnvironmentCoverageOut,
    CloudFindingOut,
    CloudFindingStatusHistoryOut,
    CloudFindingSuppressionOut,
    CloudFindingSuppressionRequest,
    CloudPolicyEvaluationOut,
    CloudPolicyOut,
    CloudPostureEvaluationRunOut,
    CloudPostureEvaluationStartRequest,
    CloudRegistryCoverageOut,
    CloudRemediationGuidanceOut,
)
from gds_api.security import CurrentUser, require_permission

router = APIRouter(prefix="/cloud", tags=["cloud-posture"])


def _policy_to_out(policy: PolicyDefinition) -> CloudPolicyOut:
    return CloudPolicyOut(
        policy_id=policy.policy_id,
        version=policy.version,
        name=policy.name,
        description=policy.description,
        provider=policy.provider,
        severity=policy.severity.value,
        security_domain=policy.security_domain.value,
        policy_family=policy.policy_family,
        evaluation_type=policy.evaluation_type.value,
        environment_types=policy.environment_types,
        asset_categories=policy.asset_categories,
        native_resource_types=policy.native_resource_types,
        required_fields=policy.required_fields,
        required_relationships=policy.required_relationships,
        evidence_fields=policy.evidence_fields,
        remediation_guidance=(
            CloudRemediationGuidanceOut(
                objective=policy.remediation_guidance.objective,
                provider_specific_guidance=policy.remediation_guidance.provider_specific_guidance,
                validation_guidance=policy.remediation_guidance.validation_guidance,
                rollback_considerations=policy.remediation_guidance.rollback_considerations,
                required_approval_class=policy.remediation_guidance.required_approval_class,
                documentation_references=policy.remediation_guidance.documentation_references,
            )
            if policy.remediation_guidance is not None
            else None
        ),
        tags=policy.tags,
        enabled=policy.enabled,
        experimental=policy.experimental,
        deprecated=policy.deprecated,
        replacement_policy_id=policy.replacement_policy_id,
        documentation_reference=policy.documentation_reference,
        authoritative_source_reference=policy.authoritative_source_reference,
        data_quality_requirements=policy.data_quality_requirements,
        unsupported_conditions=policy.unsupported_conditions,
        skip_conditions=policy.skip_conditions,
    )


def _benchmark_to_out(benchmark: BenchmarkDefinition) -> CloudBenchmarkOut:
    coverage = benchmark_coverage(benchmark.benchmark_id)
    return CloudBenchmarkOut(
        benchmark_id=benchmark.benchmark_id,
        name=benchmark.name,
        version=benchmark.version,
        provider=benchmark.provider,
        publisher=benchmark.publisher,
        description=benchmark.description,
        documentation_reference=benchmark.documentation_reference,
        licensing_note=benchmark.licensing_note,
        coverage=coverage.__dict__,  # dataclass fields match CloudBenchmarkCoverageOut exactly
    )


def _run_to_out(run: CloudPostureEvaluationRunModel) -> CloudPostureEvaluationRunOut:
    return CloudPostureEvaluationRunOut(
        id=run.id,
        tenant_id=run.tenant_id,
        environment_id=run.environment_id,
        provider=run.provider,
        inventory_snapshot_id=run.inventory_snapshot_id,
        mission_id=run.mission_id,
        workflow_run_id=run.workflow_run_id,
        requested_policy_ids=run.requested_policy_ids,
        requested_benchmark_ids=run.requested_benchmark_ids,
        initiated_by_user_id=run.initiated_by_user_id,
        started_at=run.started_at,
        completed_at=run.completed_at,
        status=run.status,
        assets_considered=run.assets_considered,
        policies_considered=run.policies_considered,
        evaluations_attempted=run.evaluations_attempted,
        passed_count=run.passed_count,
        failed_count=run.failed_count,
        not_applicable_count=run.not_applicable_count,
        unsupported_count=run.unsupported_count,
        skipped_count=run.skipped_count,
        error_count=run.error_count,
        indeterminate_count=run.indeterminate_count,
        findings_created=run.findings_created,
        findings_updated=run.findings_updated,
        findings_resolved=run.findings_resolved,
        findings_unchanged=run.findings_unchanged,
        warnings=run.warnings,
        errors=run.errors,
        evidence_id=run.evidence_id,
        correlation_id=run.correlation_id,
        evaluator_version=run.evaluator_version,
        policy_registry_fingerprint=run.policy_registry_fingerprint,
        created_at=run.created_at,
        updated_at=run.updated_at,
    )


def _evaluation_record_to_out(record: CloudPolicyEvaluation) -> CloudPolicyEvaluationOut:
    return CloudPolicyEvaluationOut(
        id=record.id,
        tenant_id=record.tenant_id,
        evaluation_run_id=record.evaluation_run_id,
        environment_id=record.environment_id,
        asset_id=record.asset_id,
        policy_id=record.policy_id,
        policy_version=record.policy_version,
        result=record.result,
        severity=record.severity,
        applicability_state=record.applicability_state,
        applicability_reason=record.applicability_reason,
        facts=record.facts,
        explanation=record.explanation,
        evaluation_time=record.evaluation_time,
        duration_ms=record.duration_ms,
        evaluator_version=record.evaluator_version,
        data_state=record.data_state,
        snapshot_id=record.snapshot_id,
        error_category=record.error_category,
        finding_id=record.finding_id,
        created_at=record.created_at,
    )


def _finding_to_out(finding: Finding, context: CloudFindingContext) -> CloudFindingOut:
    return CloudFindingOut(
        id=finding.id,
        tenant_id=finding.tenant_id,
        title=finding.title,
        description=finding.description,
        severity=finding.severity,
        risk_class=finding.risk_class,
        status=finding.status,
        recommended_remediation=finding.recommended_remediation,
        created_at=finding.created_at,
        updated_at=finding.updated_at,
        cloud_environment_id=context.cloud_environment_id,
        cloud_asset_id=context.cloud_asset_id,
        provider=context.provider,
        policy_id=context.policy_id,
        policy_version=context.policy_version,
        first_detected_at=context.first_detected_at,
        last_detected_at=context.last_detected_at,
        last_evaluated_at=context.last_evaluated_at,
        last_evaluation_run_id=context.last_evaluation_run_id,
        last_evaluation_record_id=context.last_evaluation_record_id,
        resolution_time=context.resolution_time,
        evidence_id=context.evidence_id,
    )


def _suppression_to_out(suppression: CloudFindingSuppression) -> CloudFindingSuppressionOut:
    return CloudFindingSuppressionOut(
        id=suppression.id,
        tenant_id=suppression.tenant_id,
        finding_id=suppression.finding_id,
        suppression_type=suppression.suppression_type,
        reason=suppression.reason,
        requested_by_user_id=suppression.requested_by_user_id,
        approval_id=suppression.approval_id,
        start_time=suppression.start_time,
        expiry_time=suppression.expiry_time,
        status=suppression.status,
        review_date=suppression.review_date,
        evidence_id=suppression.evidence_id,
        created_at=suppression.created_at,
        updated_at=suppression.updated_at,
    )


# ---- Policy Registry (Section 1, read-only, code-defined) -----------------------


@router.get("/policies", response_model=list[CloudPolicyOut])
async def list_cloud_policies(
    provider: str | None = None,
    security_domain: str | None = None,
    severity: str | None = None,
    enabled: bool | None = None,
    experimental: bool | None = None,
    deprecated: bool | None = None,
    current_user: CurrentUser = Depends(require_permission("cloud:policies:read")),
) -> list[CloudPolicyOut]:
    domain = PolicyDomain(security_domain) if security_domain else None
    sev = PolicySeverity(severity) if severity else None
    policies = list_policies(
        provider=provider,
        security_domain=domain,
        severity=sev,
        enabled=enabled,
        experimental=experimental,
        deprecated=deprecated,
    )
    return [_policy_to_out(p) for p in policies]


@router.get("/policies/{policy_id}", response_model=CloudPolicyOut)
async def get_cloud_policy(
    policy_id: str,
    current_user: CurrentUser = Depends(require_permission("cloud:policies:read")),
) -> CloudPolicyOut:
    policy = get_policy(policy_id)
    if policy is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Policy '{policy_id}' not found")
    return _policy_to_out(policy)


# ---- Benchmark Registry (Section 4, read-only, code-defined) --------------------


@router.get("/benchmarks", response_model=list[CloudBenchmarkOut])
async def list_cloud_benchmarks(
    current_user: CurrentUser = Depends(require_permission("cloud:benchmarks:read")),
) -> list[CloudBenchmarkOut]:
    return [_benchmark_to_out(b) for b in list_benchmarks()]


@router.get("/benchmarks/{benchmark_id}", response_model=CloudBenchmarkOut)
async def get_cloud_benchmark(
    benchmark_id: str,
    current_user: CurrentUser = Depends(require_permission("cloud:benchmarks:read")),
) -> CloudBenchmarkOut:
    benchmark = get_benchmark(benchmark_id)
    if benchmark is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Benchmark '{benchmark_id}' not found")
    return _benchmark_to_out(benchmark)


# ---- Cloud Posture Evaluation Runs (Sections 18, 20) -----------------------------


@router.post("/posture/evaluations", response_model=CloudPostureEvaluationRunOut)
async def start_cloud_posture_evaluation(
    body: CloudPostureEvaluationStartRequest,
    current_user: CurrentUser = Depends(require_permission("cloud:posture:run")),
    db: AsyncSession = Depends(get_db),
) -> CloudPostureEvaluationRunOut:
    try:
        run = await start_evaluation(
            db,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
            environment_id=body.environment_id,
            policy_ids=body.policy_ids,
        )
    except CloudPostureEvaluationStartError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, exc.reason) from exc
    await db.commit()
    await db.refresh(run)
    return _run_to_out(run)


@router.get("/posture/evaluations", response_model=list[CloudPostureEvaluationRunOut])
async def list_cloud_posture_evaluations(
    environment_id: uuid.UUID | None = None,
    status_filter: str | None = None,
    limit: int = 50,
    offset: int = 0,
    current_user: CurrentUser = Depends(require_permission("cloud:posture:read")),
    db: AsyncSession = Depends(get_db),
) -> list[CloudPostureEvaluationRunOut]:
    runs = await list_evaluation_runs(
        db,
        tenant_id=current_user.tenant_id,
        environment_id=environment_id,
        status_filter=status_filter,
        limit=limit,
        offset=offset,
    )
    return [_run_to_out(r) for r in runs]


@router.get("/posture/evaluations/{run_id}", response_model=CloudPostureEvaluationRunOut)
async def get_cloud_posture_evaluation(
    run_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("cloud:posture:read")),
    db: AsyncSession = Depends(get_db),
) -> CloudPostureEvaluationRunOut:
    run = await get_evaluation_run(db, tenant_id=current_user.tenant_id, run_id=run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Cloud posture evaluation run not found")
    return _run_to_out(run)


@router.post(
    "/posture/evaluations/{run_id}/cancel", response_model=CloudPostureEvaluationRunOut
)
async def cancel_cloud_posture_evaluation(
    run_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("cloud:posture:cancel")),
    db: AsyncSession = Depends(get_db),
) -> CloudPostureEvaluationRunOut:
    try:
        run = await cancel_evaluation_run(
            db, tenant_id=current_user.tenant_id, run_id=run_id, user_id=current_user.user_id
        )
    except CloudPostureEvaluationRunNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    except CloudPostureEvaluationStartError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, exc.reason) from exc
    await db.commit()
    await db.refresh(run)
    return _run_to_out(run)


# ---- Evaluation Records (Section 19) --------------------------------------------


@router.get("/posture/results", response_model=list[CloudPolicyEvaluationOut])
async def list_cloud_posture_results(
    evaluation_run_id: uuid.UUID | None = None,
    asset_id: uuid.UUID | None = None,
    policy_id: str | None = None,
    result_filter: str | None = None,
    limit: int = 50,
    offset: int = 0,
    current_user: CurrentUser = Depends(require_permission("cloud:evaluations:read")),
    db: AsyncSession = Depends(get_db),
) -> list[CloudPolicyEvaluationOut]:
    records = await list_policy_evaluations(
        db,
        tenant_id=current_user.tenant_id,
        evaluation_run_id=evaluation_run_id,
        asset_id=asset_id,
        policy_id=policy_id,
        result_filter=result_filter,
        limit=limit,
        offset=offset,
    )
    return [_evaluation_record_to_out(r) for r in records]


# ---- Cloud Findings (Sections 21, 24, 28) ---------------------------------------


@router.get("/findings", response_model=list[CloudFindingOut])
async def list_cloud_posture_findings(
    environment_id: uuid.UUID | None = None,
    asset_id: uuid.UUID | None = None,
    policy_id: str | None = None,
    severity: str | None = None,
    status_filter: str | None = None,
    limit: int = 50,
    offset: int = 0,
    current_user: CurrentUser = Depends(require_permission("cloud:findings:read")),
    db: AsyncSession = Depends(get_db),
) -> list[CloudFindingOut]:
    pairs = await list_cloud_findings(
        db,
        tenant_id=current_user.tenant_id,
        environment_id=environment_id,
        asset_id=asset_id,
        policy_id=policy_id,
        severity=severity,
        status_filter=status_filter,
        limit=limit,
        offset=offset,
    )
    return [_finding_to_out(finding, context) for finding, context in pairs]


@router.get("/findings/{finding_id}", response_model=CloudFindingOut)
async def get_cloud_posture_finding(
    finding_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("cloud:findings:read")),
    db: AsyncSession = Depends(get_db),
) -> CloudFindingOut:
    try:
        finding, context = await get_cloud_finding_context(
            db, tenant_id=current_user.tenant_id, finding_id=finding_id
        )
    except CloudFindingNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    return _finding_to_out(finding, context)


@router.get("/findings/{finding_id}/history", response_model=list[CloudFindingStatusHistoryOut])
async def get_cloud_posture_finding_history(
    finding_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("cloud:findings:read")),
    db: AsyncSession = Depends(get_db),
) -> list[CloudFindingStatusHistoryOut]:
    history = await list_finding_status_history(
        db, tenant_id=current_user.tenant_id, finding_id=finding_id
    )
    return [
        CloudFindingStatusHistoryOut(
            id=h.id,
            finding_id=h.finding_id,
            previous_status=h.previous_status,
            new_status=h.new_status,
            reason=h.reason,
            evaluation_run_id=h.evaluation_run_id,
            evaluation_record_id=h.evaluation_record_id,
            actor_user_id=h.actor_user_id,
            created_at=h.created_at,
        )
        for h in history
    ]


# ---- Suppression and Accepted Risk (Sections 28-29) ------------------------------


@router.get(
    "/findings/{finding_id}/suppressions", response_model=list[CloudFindingSuppressionOut]
)
async def list_cloud_posture_finding_suppressions(
    finding_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("cloud:findings:read")),
    db: AsyncSession = Depends(get_db),
) -> list[CloudFindingSuppressionOut]:
    suppressions = await list_suppressions_for_finding(
        db, tenant_id=current_user.tenant_id, finding_id=finding_id
    )
    await db.commit()  # persist any live status refresh (expiry/approval decision)
    return [_suppression_to_out(s) for s in suppressions]


@router.post(
    "/findings/{finding_id}/suppressions", response_model=CloudFindingSuppressionOut
)
async def request_cloud_posture_finding_suppression(
    finding_id: uuid.UUID,
    body: CloudFindingSuppressionRequest,
    current_user: CurrentUser = Depends(require_permission("cloud:findings:suppress")),
    db: AsyncSession = Depends(get_db),
) -> CloudFindingSuppressionOut:
    try:
        suppression = await request_suppression(
            db,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
            finding_id=finding_id,
            suppression_type=body.suppression_type,
            reason=body.reason,
            expiry_time=body.expiry_time,
            review_date=body.review_date,
        )
    except SuppressionNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    except InvalidSuppressionType as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except DuplicateActiveSuppression as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    await db.commit()
    await db.refresh(suppression)
    return _suppression_to_out(suppression)


# ---- Coverage (Section 31) -------------------------------------------------------


@router.get("/posture/coverage/registry", response_model=CloudRegistryCoverageOut)
async def get_cloud_posture_registry_coverage(
    current_user: CurrentUser = Depends(require_permission("cloud:posture:read")),
) -> CloudRegistryCoverageOut:
    coverage = compute_registry_coverage()
    return CloudRegistryCoverageOut(**coverage.__dict__)


@router.get(
    "/posture/coverage/environments/{environment_id}", response_model=CloudEnvironmentCoverageOut
)
async def get_cloud_posture_environment_coverage(
    environment_id: uuid.UUID,
    provider: str,
    current_user: CurrentUser = Depends(require_permission("cloud:posture:read")),
    db: AsyncSession = Depends(get_db),
) -> CloudEnvironmentCoverageOut:
    coverage = await compute_environment_coverage(
        db, tenant_id=current_user.tenant_id, environment_id=environment_id, provider=provider
    )
    return CloudEnvironmentCoverageOut(**coverage.__dict__)
