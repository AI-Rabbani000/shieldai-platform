"""EDP-009 Part 2, Section 14: the initial GCP policy set. The real
`GCPProviderAdapter` (6 of 19 registry categories - see
docs/reviews/phase-22-part2-policy-feasibility-matrix.md) preserves almost no raw
metadata for any category (`raw_metadata` is `{"self_link": ...}` or empty for
every implemented category, confirmed directly against `gcp_discovery.py`) - the
only genuinely usable security signal for `firewall_rule` and `compute_instance` is
the adapter's own normalized `internet_exposure_known` boolean
(`gcp_discovery.py:135-137,195-197`), which is always a real bool (never `None` -
computed via `bool(...)`, so there is no UNSUPPORTED path from a missing normalized
field for these two categories specifically). No Cloud Storage bucket, Cloud SQL,
or KMS policy exists here - those categories either collect no raw_metadata at all
(`cloud_storage_bucket`) or are not discovered at all (`cloud_sql`,
`kms_key_metadata`, `security_command_center_enablement_metadata`) in this Part.
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

_RERUN_GUIDANCE = (
    "Re-run cloud posture evaluation after the change; this policy should return PASS."
)


def _firewall_rule_open_ingress(context: EvaluationContext) -> EvaluationOutcome:
    asset = context.asset
    assert asset is not None
    if asset.lifecycle_state == "DISABLED":
        return EvaluationOutcome(
            result=EvaluationResult.NOT_APPLICABLE,
            explanation=f"Firewall rule '{asset.name}' is disabled and not enforced.",
        )
    if asset.internet_exposure_known is True:
        return EvaluationOutcome(
            result=EvaluationResult.FAIL,
            explanation=(
                f"Firewall rule '{asset.name}' allows ingress from 0.0.0.0/0. "
                "Note: the specific port/protocol this rule covers is not "
                "collected by the current GCP adapter - only exposure presence "
                "is evaluated."
            ),
            facts={"source_ranges_include_world": True},
            data_state="partial",
        )
    return EvaluationOutcome(
        result=EvaluationResult.PASS,
        explanation=f"Firewall rule '{asset.name}' does not allow ingress from 0.0.0.0/0.",
    )


def _compute_instance_has_external_ip(context: EvaluationContext) -> EvaluationOutcome:
    asset = context.asset
    assert asset is not None
    if asset.internet_exposure_known is True:
        return EvaluationOutcome(
            result=EvaluationResult.FAIL,
            explanation=f"Compute instance '{asset.name}' has an external IP address configured.",
            facts={"has_external_ip": True},
        )
    return EvaluationOutcome(
        result=EvaluationResult.PASS,
        explanation=f"Compute instance '{asset.name}' has no external IP address configured.",
    )


register_policy(
    PolicyDefinition(
        policy_id="CSPM.GCP.NETWORKING.FIREWALL_RULE_OPEN_INGRESS",
        version=1,
        name="Firewall rule allows unrestricted ingress",
        description=(
            "Fails when an enabled firewall rule's source_ranges include 0.0.0.0/0. "
            "Port/protocol-level detail is not evaluated - not collected by the "
            "current GCP adapter."
        ),
        provider="gcp",
        severity=PolicySeverity.HIGH,
        security_domain=PolicyDomain.NETWORKING,
        policy_family="network_exposure",
        evaluation_type=EvaluationType.RESOURCE_LEVEL,
        evaluator=_firewall_rule_open_ingress,
        asset_categories=("firewall_rule",),
        required_fields=("internet_exposure_known",),
        data_quality_requirements=(
            "Only rule-level internet exposure is evaluated - the current GCP "
            "adapter does not persist source_ranges, allowed protocols/ports, "
            "target_tags, or target_service_accounts, so a PASS/FAIL result "
            "always carries data_state='partial' on FAIL.",
        ),
        remediation_guidance=RemediationGuidance(
            objective="Restrict the firewall rule's source ranges to known, necessary CIDRs.",
            provider_specific_guidance=(
                "Update the rule's source ranges via the VPC firewall console or "
                "`gcloud compute firewall-rules update`."
            ),
            validation_guidance=_RERUN_GUIDANCE,
            rollback_considerations="Confirm the real required source ranges before narrowing.",
            required_approval_class="high",
        ),
    )
)

register_policy(
    PolicyDefinition(
        policy_id="CSPM.GCP.COMPUTE.INSTANCE_HAS_EXTERNAL_IP",
        version=1,
        name="Compute instance has an external IP address",
        description=(
            "Fails when a compute instance has an access config (external IP) "
            "on any interface."
        ),
        provider="gcp",
        severity=PolicySeverity.MEDIUM,
        security_domain=PolicyDomain.INTERNET_EXPOSURE,
        policy_family="internet_exposure",
        evaluation_type=EvaluationType.RESOURCE_LEVEL,
        evaluator=_compute_instance_has_external_ip,
        asset_categories=("compute_instance",),
        required_fields=("internet_exposure_known",),
        remediation_guidance=RemediationGuidance(
            objective="Remove the external IP address unless genuinely required.",
            provider_specific_guidance=(
                "Remove the instance's access config via the Compute Engine "
                "console or `gcloud compute instances delete-access-config`, "
                "using Cloud NAT or IAP for outbound/administrative access instead."
            ),
            validation_guidance=_RERUN_GUIDANCE,
            rollback_considerations=(
                "Confirm no legitimate client depends on direct external connectivity."
            ),
            required_approval_class="medium",
        ),
    )
)
