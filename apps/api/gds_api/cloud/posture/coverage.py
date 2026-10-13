"""EDP-009 Part 2, Section 31: an honest CSPM coverage model - real counts with
defined numerators/denominators, never a single vague "compliance percentage"
(Section 31's own explicit rule). A pure query-time function, not a new table -
every number here is derived live from the code-defined registries
(gds_api.cloud.posture.registry) and the most recent real
CloudPostureEvaluationRun for the environment, so it can never drift out of sync
with either.

Section 32 (Posture Score) is deliberately NOT implemented - the prompt's own
explicit permission ("It is acceptable to omit a posture score entirely in
Part 2... Prefer transparent counts and coverage over opaque scoring") is taken
here. No score, weighted or otherwise, exists anywhere in this module.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.cloud.posture.registry import (
    BENCHMARK_REGISTRY,
    benchmark_coverage,
    list_policies,
)
from gds_api.models import CloudPostureEvaluationRun


@dataclass(frozen=True)
class EnvironmentCoverage:
    """Every field here has an explicit, single definition - Section 31's own
    "if a percentage is shown, define numerator/denominator/exclusions" rule is
    satisfied by never computing a percentage at all; a caller wanting one can
    always divide two of these real integers itself, with full knowledge of what
    each side means."""

    environment_id: uuid.UUID
    provider: str
    # Real policies whose provider matches this environment and are enabled -
    # the denominator "could theoretically run here", before applicability
    # narrows it further per-asset at evaluation time.
    policies_applicable_by_provider: int
    # From the most recent real CloudPostureEvaluationRun for this environment,
    # or None if this environment has never been evaluated at all (Section 34's
    # own "do not show a provider as secure merely because no evaluation has
    # run" rule - the caller must check has_been_evaluated before drawing any
    # conclusion from the counts below).
    has_been_evaluated: bool
    last_evaluation_run_id: uuid.UUID | None
    policies_considered: int
    evaluations_attempted: int
    passed_count: int
    failed_count: int
    not_applicable_count: int
    unsupported_count: int
    skipped_count: int
    error_count: int
    indeterminate_count: int
    findings_created: int
    findings_resolved: int


async def compute_environment_coverage(
    db: AsyncSession, *, tenant_id: uuid.UUID, environment_id: uuid.UUID, provider: str
) -> EnvironmentCoverage:
    applicable = len(list_policies(provider=provider, enabled=True))

    result = await db.execute(
        select(CloudPostureEvaluationRun)
        .where(
            CloudPostureEvaluationRun.tenant_id == tenant_id,
            CloudPostureEvaluationRun.environment_id == environment_id,
            CloudPostureEvaluationRun.status.in_(("completed", "partially_completed")),
        )
        .order_by(CloudPostureEvaluationRun.completed_at.desc())
        .limit(1)
    )
    run = result.scalars().first()

    if run is None:
        return EnvironmentCoverage(
            environment_id=environment_id,
            provider=provider,
            policies_applicable_by_provider=applicable,
            has_been_evaluated=False,
            last_evaluation_run_id=None,
            policies_considered=0,
            evaluations_attempted=0,
            passed_count=0,
            failed_count=0,
            not_applicable_count=0,
            unsupported_count=0,
            skipped_count=0,
            error_count=0,
            indeterminate_count=0,
            findings_created=0,
            findings_resolved=0,
        )

    return EnvironmentCoverage(
        environment_id=environment_id,
        provider=provider,
        policies_applicable_by_provider=applicable,
        has_been_evaluated=True,
        last_evaluation_run_id=run.id,
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
        findings_resolved=run.findings_resolved,
    )


@dataclass(frozen=True)
class RegistryCoverage:
    """Tenant-independent, code-defined-registry-only counts - Section 31's own
    "policies implemented/enabled/unsupported" and "benchmark controls mapped"
    dimensions, computed with zero database access at all (registry state is the
    same for every tenant in this deployment)."""

    total_policies: int
    enabled_policies: int
    disabled_policies: int
    experimental_policies: int
    deprecated_policies: int
    policies_by_provider: dict[str, int]
    total_benchmarks: int
    benchmark_mapped_control_counts: dict[str, int]


def compute_registry_coverage() -> RegistryCoverage:
    all_policies = list_policies()
    by_provider: dict[str, int] = {}
    for policy in all_policies:
        by_provider[policy.provider] = by_provider.get(policy.provider, 0) + 1
    return RegistryCoverage(
        total_policies=len(all_policies),
        enabled_policies=len(list_policies(enabled=True)),
        disabled_policies=len(list_policies(enabled=False)),
        experimental_policies=len(list_policies(experimental=True)),
        deprecated_policies=len(list_policies(deprecated=True)),
        policies_by_provider=by_provider,
        total_benchmarks=len(BENCHMARK_REGISTRY),
        benchmark_mapped_control_counts={
            benchmark_id: benchmark_coverage(benchmark_id).mapped_control_count
            for benchmark_id in BENCHMARK_REGISTRY
        },
    )
