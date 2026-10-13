"""EDP-009 Part 2, Section 8: the Applicability Engine. Decides, before a policy's
evaluator function is ever invoked, whether that policy is APPLICABLE to a given
target - never runs every policy against every asset (Section 8's own explicit rule).

Deliberately coarse: provider/category/environment-type/relationship-vocabulary
selection only. Fine-grained "is this specific field present on this specific asset"
determination is the evaluator function's own job (it returns EvaluationResult.
UNSUPPORTED/INDETERMINATE for that) - duplicating per-field knowledge into this engine
as a second, parallel spec would let the two silently drift apart.
"""

from __future__ import annotations

from gds_api.cloud.graph import _KNOWN_RELATIONSHIP_TYPES
from gds_api.cloud.posture.registry import PolicyDefinition
from gds_api.cloud.posture.taxonomy import ApplicabilityState, EvaluationType
from gds_api.cloud.posture.types import ApplicabilityResult, EvaluationContext, EvaluationOutcome
from gds_api.models import CloudAsset, CloudEnvironment

# Bumped only on a real behavioural change to the Applicability Engine or the
# Evaluator contract (EvaluationContext/EvaluationOutcome shape) - persisted on
# every CloudPostureEvaluationRun/CloudPolicyEvaluation so a historical result can
# always be traced back to the evaluator logic that actually produced it.
EVALUATOR_VERSION = "1.0.0"


def determine_applicability(
    policy: PolicyDefinition,
    *,
    environment: CloudEnvironment,
    asset: CloudAsset | None,
) -> ApplicabilityResult:
    if not policy.enabled:
        return ApplicabilityResult(ApplicabilityState.SKIPPED, "Policy is disabled")
    if policy.deprecated:
        replacement = (
            f" - see replacement policy {policy.replacement_policy_id}"
            if policy.replacement_policy_id
            else ""
        )
        return ApplicabilityResult(
            ApplicabilityState.SKIPPED, f"Policy is deprecated{replacement}"
        )

    target_provider = asset.provider if asset is not None else environment.provider
    if policy.provider != "multi" and policy.provider != target_provider:
        return ApplicabilityResult(
            ApplicabilityState.NOT_APPLICABLE,
            f"Policy targets provider '{policy.provider}', target is '{target_provider}'",
        )

    if policy.environment_types and environment.environment_type not in policy.environment_types:
        return ApplicabilityResult(
            ApplicabilityState.NOT_APPLICABLE,
            f"Policy applies to environment types {sorted(policy.environment_types)}, "
            f"this environment is '{environment.environment_type}'",
        )

    if policy.evaluation_type == EvaluationType.ENVIRONMENT_LEVEL:
        if asset is not None:
            return ApplicabilityResult(
                ApplicabilityState.NOT_APPLICABLE,
                "Environment-level policy was given a specific target asset",
            )
        return ApplicabilityResult(ApplicabilityState.APPLICABLE, "Environment-level policy")

    # RESOURCE_LEVEL and RELATIONSHIP_BASED both require a real target asset.
    if asset is None:
        return ApplicabilityResult(
            ApplicabilityState.NOT_APPLICABLE,
            f"{policy.evaluation_type.value} policy requires a target asset",
        )
    if policy.asset_categories and asset.provider_category not in policy.asset_categories:
        return ApplicabilityResult(
            ApplicabilityState.NOT_APPLICABLE,
            f"Policy applies to asset categories {sorted(policy.asset_categories)}, "
            f"this asset is '{asset.provider_category}'",
        )
    if (
        policy.native_resource_types
        and asset.native_resource_type not in policy.native_resource_types
    ):
        return ApplicabilityResult(
            ApplicabilityState.NOT_APPLICABLE,
            f"Policy applies to native resource types {sorted(policy.native_resource_types)}, "
            f"this asset is '{asset.native_resource_type}'",
        )

    if policy.evaluation_type == EvaluationType.RELATIONSHIP_BASED:
        unknown_types = [
            rel_type
            for rel_type in policy.required_relationships
            if rel_type not in _KNOWN_RELATIONSHIP_TYPES
        ]
        if unknown_types:
            return ApplicabilityResult(
                ApplicabilityState.BLOCKED_BY_MISSING_DATA,
                f"Policy requires relationship type(s) {unknown_types} not part of the "
                "supported CloudAssetRelationship vocabulary",
            )

    return ApplicabilityResult(ApplicabilityState.APPLICABLE, "Policy is applicable")


def evaluate_policy(
    policy: PolicyDefinition, context: EvaluationContext
) -> tuple[ApplicabilityResult, EvaluationOutcome | None]:
    """Runs the Applicability Engine first; only invokes the policy's own evaluator
    function when APPLICABLE. Returns a tuple of (ApplicabilityResult, EvaluationOutcome
    | None) - the caller (the evaluation-run service, a later sub-phase) is
    responsible for turning a non-APPLICABLE result into the matching
    EvaluationResult (NOT_APPLICABLE/UNSUPPORTED/SKIPPED all have a direct
    EvaluationResult counterpart; BLOCKED_BY_MISSING_DATA maps to INDETERMINATE) when
    persisting a CloudPolicyEvaluation record - kept as a plain, easily-unit-tested
    function distinct from any database or Mission concern."""
    applicability = determine_applicability(
        policy, environment=context.environment, asset=context.asset
    )
    if applicability.state != ApplicabilityState.APPLICABLE:
        return applicability, None
    outcome = policy.evaluator(context)
    return applicability, outcome
