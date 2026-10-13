"""EDP-009 Part 2, Section 15: the initial Kubernetes policy set. This is the
smallest real policy set of any provider - the field-availability audit
(docs/reviews/phase-22-part2-policy-feasibility-matrix.md) found the real
`KubernetesProviderAdapter` (6 of 20 registry categories) discovers no RBAC objects
of any kind (`ClusterRole`, `ClusterRoleBinding`, `RoleBinding`, `Role`,
`ServiceAccount`), no `NetworkPolicy`, and reads no container `securityContext`
fields or image references from pod/deployment specs at all - the provider
registry's own `known_limitations` text already discloses this: "Full container/
Kubernetes security analysis is explicitly out of scope for this Part (belongs to
EDP-009 Part 4)."

Only one real, evaluable signal exists:
`service.internet_exposure_known = (spec.type == "LoadBalancer")`. It is registered
as INFORMATIONAL severity (mirroring Section 15's own "Secret objects discovered,
informational only" precedent) - a LoadBalancer Service is not itself a
misconfiguration, so this policy's FAIL result is an observed fact, not a risk
(ADR 0051 Decision D6: an INFORMATIONAL-severity policy's FAIL never creates a
platform Finding row).

The rest of Section 15's example list is registered anyway, each with an evaluator
that always and honestly returns UNSUPPORTED, so they are visible in the
Unsupported Controls view (Section 39) rather than silently missing - the same
pattern `CSPM.AWS.STORAGE.S3_PUBLIC_ACCESS_INDICATED` established.
"""

from __future__ import annotations

from gds_api.cloud.posture.registry import PolicyDefinition, RemediationGuidance, register_policy
from gds_api.cloud.posture.taxonomy import (
    EvaluationResult,
    EvaluationType,
    PolicyDomain,
    PolicySeverity,
)
from gds_api.cloud.posture.types import EvaluationContext, EvaluationOutcome

_FEASIBILITY_DOC = "docs/reviews/phase-22-part2-policy-feasibility-matrix.md"
_NOT_EVALUABLE_GUIDANCE = RemediationGuidance(
    objective="Not evaluable until a future Part extends Kubernetes discovery coverage.",
    provider_specific_guidance=(
        "No remediation guidance is offered while this policy is UNSUPPORTED."
    ),
    validation_guidance="N/A",
    rollback_considerations="N/A",
    required_approval_class="high",
)


def _service_load_balancer_exposure(context: EvaluationContext) -> EvaluationOutcome:
    asset = context.asset
    assert asset is not None
    if asset.internet_exposure_known is True:
        return EvaluationOutcome(
            result=EvaluationResult.FAIL,
            explanation=f"Service '{asset.name}' is of type LoadBalancer.",
            facts={"type": "LoadBalancer"},
        )
    return EvaluationOutcome(
        result=EvaluationResult.PASS,
        explanation=f"Service '{asset.name}' is not of type LoadBalancer.",
    )


def _rbac_not_collected(context: EvaluationContext) -> EvaluationOutcome:
    return EvaluationOutcome(
        result=EvaluationResult.UNSUPPORTED,
        explanation=(
            "No Kubernetes RBAC objects (ClusterRole, ClusterRoleBinding, "
            "RoleBinding, Role, ServiceAccount) are discovered by the current "
            f"adapter. See {_FEASIBILITY_DOC}."
        ),
        data_state="missing",
    )


def _container_security_context_not_collected(context: EvaluationContext) -> EvaluationOutcome:
    return EvaluationOutcome(
        result=EvaluationResult.UNSUPPORTED,
        explanation=(
            "No container securityContext fields (privileged, "
            "allowPrivilegeEscalation, runAsNonRoot, hostPID, hostIPC) are read "
            f"from pod or deployment specs by the current adapter. See {_FEASIBILITY_DOC}."
        ),
        data_state="missing",
    )


def _network_policy_not_collected(context: EvaluationContext) -> EvaluationOutcome:
    return EvaluationOutcome(
        result=EvaluationResult.UNSUPPORTED,
        explanation=(
            "NetworkPolicy objects are not a discovered category in the current "
            f"adapter - namespace-level default-deny coverage cannot be evaluated. "
            f"See {_FEASIBILITY_DOC}."
        ),
        data_state="missing",
    )


register_policy(
    PolicyDefinition(
        policy_id="CSPM.KUBERNETES.NETWORKING.SERVICE_LOAD_BALANCER_EXPOSURE",
        version=1,
        name="Service of type LoadBalancer exists",
        description=(
            "Informational: observes whether a Service is of type LoadBalancer. Not "
            "itself a misconfiguration - a FAIL result is an observed fact, never a "
            "platform Finding (informational-severity policies never create one)."
        ),
        provider="kubernetes",
        severity=PolicySeverity.INFORMATIONAL,
        security_domain=PolicyDomain.NETWORKING,
        policy_family="exposure_observation",
        evaluation_type=EvaluationType.RESOURCE_LEVEL,
        evaluator=_service_load_balancer_exposure,
        asset_categories=("service",),
        required_fields=("internet_exposure_known",),
        remediation_guidance=RemediationGuidance(
            objective="N/A - informational observation only.",
            provider_specific_guidance=(
                "Review whether external exposure via this Service is intended."
            ),
            validation_guidance="N/A",
            rollback_considerations="N/A",
            required_approval_class="low",
        ),
    )
)

register_policy(
    PolicyDefinition(
        policy_id="CSPM.KUBERNETES.RBAC.CLUSTER_ADMIN_BINDING",
        version=1,
        name="ClusterRoleBinding grants cluster-admin",
        description="Always UNSUPPORTED in this environment - see unsupported_conditions.",
        provider="kubernetes",
        severity=PolicySeverity.CRITICAL,
        security_domain=PolicyDomain.PRIVILEGED_ACCESS,
        policy_family="rbac",
        evaluation_type=EvaluationType.ENVIRONMENT_LEVEL,
        evaluator=_rbac_not_collected,
        unsupported_conditions=(
            "No ClusterRoleBinding, ClusterRole, RoleBinding, Role, or "
            "ServiceAccount objects are discovered by the current Kubernetes "
            f"adapter (6 of 20 registry categories implemented). See {_FEASIBILITY_DOC}.",
        ),
        documentation_reference=_FEASIBILITY_DOC,
        remediation_guidance=_NOT_EVALUABLE_GUIDANCE,
    )
)

register_policy(
    PolicyDefinition(
        policy_id="CSPM.KUBERNETES.CONTAINERS.PRIVILEGED_CONTAINER",
        version=1,
        name="Container runs privileged",
        description="Always UNSUPPORTED in this environment - see unsupported_conditions.",
        provider="kubernetes",
        severity=PolicySeverity.CRITICAL,
        security_domain=PolicyDomain.CONTAINERS,
        policy_family="workload_hardening",
        evaluation_type=EvaluationType.RESOURCE_LEVEL,
        evaluator=_container_security_context_not_collected,
        asset_categories=("pod",),
        unsupported_conditions=(
            "No container securityContext fields are read from pod specs by the "
            f"current Kubernetes adapter. See {_FEASIBILITY_DOC}.",
        ),
        documentation_reference=_FEASIBILITY_DOC,
        remediation_guidance=_NOT_EVALUABLE_GUIDANCE,
    )
)

register_policy(
    PolicyDefinition(
        policy_id="CSPM.KUBERNETES.NETWORKING.NAMESPACE_MISSING_NETWORK_POLICY",
        version=1,
        name="Namespace contains workloads but no NetworkPolicy",
        description="Always UNSUPPORTED in this environment - see unsupported_conditions.",
        provider="kubernetes",
        severity=PolicySeverity.MEDIUM,
        security_domain=PolicyDomain.NETWORKING,
        policy_family="network_segmentation",
        evaluation_type=EvaluationType.ENVIRONMENT_LEVEL,
        evaluator=_network_policy_not_collected,
        unsupported_conditions=(
            "NetworkPolicy is not a discovered category in the current "
            f"Kubernetes adapter. See {_FEASIBILITY_DOC}.",
        ),
        documentation_reference=_FEASIBILITY_DOC,
        remediation_guidance=_NOT_EVALUABLE_GUIDANCE,
    )
)
