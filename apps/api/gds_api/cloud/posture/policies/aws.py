"""EDP-009 Part 2, Section 12: the initial AWS policy set. Only policies whose
required data is genuinely collected by the real Part 1 `AWSProviderAdapter` are
given a real pass/fail evaluator - see
docs/reviews/phase-22-part2-policy-feasibility-matrix.md for the field-by-field audit
this module is built against. `CSPM.AWS.STORAGE.S3_PUBLIC_ACCESS_INDICATED` is
registered anyway, with an evaluator that always and honestly returns UNSUPPORTED,
so it is visible in the Unsupported Controls view (Section 39) rather than silently
missing from the catalogue.

Each `register_policy()` call here runs at import time (mirrors
`gds_api.cloud.adapters`' own import-side-effect registration pattern) - importing
`gds_api.cloud.posture` is enough to make every policy in this module available.
"""

from __future__ import annotations

from gds_api.cloud.posture.policies._helpers import (
    environment_level_absence_outcome,
    is_truncated_metadata,
    security_group_open_ip_permissions,
)
from gds_api.cloud.posture.registry import PolicyDefinition, RemediationGuidance, register_policy
from gds_api.cloud.posture.taxonomy import (
    EvaluationResult,
    EvaluationType,
    PolicyDomain,
    PolicySeverity,
)
from gds_api.cloud.posture.types import EvaluationContext, EvaluationOutcome, Evaluator

_FEASIBILITY_DOC = "docs/reviews/phase-22-part2-policy-feasibility-matrix.md"


def _security_group_open_ingress(context: EvaluationContext) -> EvaluationOutcome:
    asset = context.asset
    assert asset is not None
    raw = asset.raw_metadata
    if is_truncated_metadata(raw):
        return EvaluationOutcome(
            result=EvaluationResult.INDETERMINATE,
            explanation=(
                "This security group's metadata exceeded the collection size bound "
                "and was truncated - ingress rules cannot be evaluated with confidence."
            ),
            data_state="missing",
        )
    if "IpPermissions" not in raw:
        return EvaluationOutcome(
            result=EvaluationResult.UNSUPPORTED,
            explanation="This security group asset has no IpPermissions data recorded.",
            data_state="missing",
        )
    matches = security_group_open_ip_permissions(raw)
    if matches:
        ports = sorted(
            {f"{m.get('IpProtocol')}:{m.get('FromPort')}-{m.get('ToPort')}" for m in matches}
        )
        return EvaluationOutcome(
            result=EvaluationResult.FAIL,
            explanation=(
                f"Security group '{asset.name}' allows inbound access from 0.0.0.0/0 "
                f"or ::/0 on: {', '.join(ports)}."
            ),
            facts={"open_rules": matches[:10], "rule_count": len(matches)},
        )
    return EvaluationOutcome(
        result=EvaluationResult.PASS,
        explanation=(
            f"Security group '{asset.name}' has no inbound rule allowing 0.0.0.0/0 or ::/0."
        ),
    )


def _make_security_group_port_evaluator(port: int, port_label: str) -> Evaluator:
    def _evaluator(context: EvaluationContext) -> EvaluationOutcome:
        asset = context.asset
        assert asset is not None
        raw = asset.raw_metadata
        if is_truncated_metadata(raw):
            return EvaluationOutcome(
                result=EvaluationResult.INDETERMINATE,
                explanation=(
                    "This security group's metadata exceeded the collection size "
                    "bound and was truncated - ingress rules cannot be evaluated "
                    "with confidence."
                ),
                data_state="missing",
            )
        if "IpPermissions" not in raw:
            return EvaluationOutcome(
                result=EvaluationResult.UNSUPPORTED,
                explanation="This security group asset has no IpPermissions data recorded.",
                data_state="missing",
            )
        matches = security_group_open_ip_permissions(raw, port=port)
        if matches:
            return EvaluationOutcome(
                result=EvaluationResult.FAIL,
                explanation=(
                    f"Security group '{asset.name}' allows inbound {port_label} "
                    f"(port {port}) from 0.0.0.0/0 or ::/0."
                ),
                facts={"open_rules": matches[:10]},
            )
        return EvaluationOutcome(
            result=EvaluationResult.PASS,
            explanation=(
                f"Security group '{asset.name}' does not allow inbound {port_label} "
                "from 0.0.0.0/0 or ::/0."
            ),
        )

    return _evaluator


def _rds_publicly_accessible(context: EvaluationContext) -> EvaluationOutcome:
    asset = context.asset
    assert asset is not None
    raw = asset.raw_metadata
    if is_truncated_metadata(raw):
        return EvaluationOutcome(
            result=EvaluationResult.INDETERMINATE,
            explanation=(
                "This RDS instance's metadata was truncated - public accessibility "
                "cannot be evaluated with confidence."
            ),
            data_state="missing",
        )
    if "PubliclyAccessible" not in raw:
        return EvaluationOutcome(
            result=EvaluationResult.UNSUPPORTED,
            explanation="This RDS instance asset has no PubliclyAccessible data recorded.",
            data_state="missing",
        )
    if raw["PubliclyAccessible"] is True:
        return EvaluationOutcome(
            result=EvaluationResult.FAIL,
            explanation=f"RDS instance '{asset.name}' is configured as publicly accessible.",
            facts={"PubliclyAccessible": True},
        )
    return EvaluationOutcome(
        result=EvaluationResult.PASS,
        explanation=f"RDS instance '{asset.name}' is not configured as publicly accessible.",
    )


def _rds_storage_encryption_disabled(context: EvaluationContext) -> EvaluationOutcome:
    asset = context.asset
    assert asset is not None
    raw = asset.raw_metadata
    if is_truncated_metadata(raw):
        return EvaluationOutcome(
            result=EvaluationResult.INDETERMINATE,
            explanation=(
                "This RDS instance's metadata was truncated - storage encryption "
                "cannot be evaluated with confidence."
            ),
            data_state="missing",
        )
    if "StorageEncrypted" not in raw:
        return EvaluationOutcome(
            result=EvaluationResult.UNSUPPORTED,
            explanation="This RDS instance asset has no StorageEncrypted data recorded.",
            data_state="missing",
        )
    if raw["StorageEncrypted"] is False:
        return EvaluationOutcome(
            result=EvaluationResult.FAIL,
            explanation=f"RDS instance '{asset.name}' does not have storage encryption enabled.",
            facts={"StorageEncrypted": False},
        )
    return EvaluationOutcome(
        result=EvaluationResult.PASS,
        explanation=f"RDS instance '{asset.name}' has storage encryption enabled.",
    )


def _cloudtrail_enabled(context: EvaluationContext) -> EvaluationOutcome:
    absence = environment_level_absence_outcome(
        context, category="cloudtrail_trail_metadata", resource_label="CloudTrail trail"
    )
    if absence is not None:
        return absence
    return EvaluationOutcome(
        result=EvaluationResult.PASS,
        explanation="At least one CloudTrail trail was discovered in this environment.",
    )


def _guardduty_enabled(context: EvaluationContext) -> EvaluationOutcome:
    absence = environment_level_absence_outcome(
        context, category="guardduty_detector_metadata", resource_label="GuardDuty detector"
    )
    if absence is not None:
        return absence
    detectors = [
        a
        for a in context.all_environment_assets
        if a.provider_category == "guardduty_detector_metadata"
    ]
    disabled = [d for d in detectors if d.lifecycle_state == "DISABLED"]
    if disabled:
        return EvaluationOutcome(
            result=EvaluationResult.FAIL,
            explanation="A GuardDuty detector exists in this environment but is disabled.",
            facts={"disabled_detector_count": len(disabled)},
        )
    unknown_state = [d for d in detectors if not d.lifecycle_state]
    if unknown_state and len(unknown_state) == len(detectors):
        return EvaluationOutcome(
            result=EvaluationResult.INDETERMINATE,
            explanation=(
                "A GuardDuty detector exists but its enablement status was not recorded."
            ),
            data_state="partial",
        )
    return EvaluationOutcome(
        result=EvaluationResult.PASS,
        explanation="A GuardDuty detector is present and not recorded as disabled.",
    )


def _config_recorder_enabled(context: EvaluationContext) -> EvaluationOutcome:
    absence = environment_level_absence_outcome(
        context, category="config_recorder_metadata", resource_label="AWS Config recorder"
    )
    if absence is not None:
        return absence
    return EvaluationOutcome(
        result=EvaluationResult.PASS,
        explanation=(
            "An AWS Config recorder is registered in this environment. Note: recorder "
            "presence only is checked - active recording status is not collected by "
            "the current adapter."
        ),
        data_state="partial",
    )


def _cloudwatch_log_retention_configured(context: EvaluationContext) -> EvaluationOutcome:
    asset = context.asset
    assert asset is not None
    raw = asset.raw_metadata
    if is_truncated_metadata(raw):
        return EvaluationOutcome(
            result=EvaluationResult.INDETERMINATE,
            explanation=(
                "This log group's metadata was truncated - retention configuration "
                "cannot be evaluated with confidence."
            ),
            data_state="missing",
        )
    retention = raw.get("retentionInDays")
    if retention is None:
        return EvaluationOutcome(
            result=EvaluationResult.FAIL,
            explanation=(
                f"CloudWatch log group '{asset.name}' has no retention period "
                "configured (logs are retained indefinitely by default)."
            ),
            facts={"retentionInDays": None},
        )
    return EvaluationOutcome(
        result=EvaluationResult.PASS,
        explanation=(
            f"CloudWatch log group '{asset.name}' has a retention period of "
            f"{retention} day(s) configured."
        ),
        facts={"retentionInDays": retention},
    )


def _eks_public_endpoint_access(context: EvaluationContext) -> EvaluationOutcome:
    asset = context.asset
    assert asset is not None
    raw = asset.raw_metadata
    if is_truncated_metadata(raw):
        return EvaluationOutcome(
            result=EvaluationResult.INDETERMINATE,
            explanation=(
                "This EKS cluster's metadata was truncated - endpoint access "
                "cannot be evaluated with confidence."
            ),
            data_state="missing",
        )
    vpc_config = raw.get("resourcesVpcConfig")
    if not isinstance(vpc_config, dict) or "endpointPublicAccess" not in vpc_config:
        return EvaluationOutcome(
            result=EvaluationResult.UNSUPPORTED,
            explanation=(
                "This EKS cluster asset has no resourcesVpcConfig.endpointPublicAccess "
                "data recorded."
            ),
            data_state="missing",
        )
    if vpc_config["endpointPublicAccess"] is True:
        return EvaluationOutcome(
            result=EvaluationResult.FAIL,
            explanation=(
                f"EKS cluster '{asset.name}' has a publicly accessible Kubernetes API "
                "server endpoint."
            ),
            facts={"endpointPublicAccess": True, "publicAccessCidrs": vpc_config.get(
                "publicAccessCidrs"
            )},
        )
    return EvaluationOutcome(
        result=EvaluationResult.PASS,
        explanation=f"EKS cluster '{asset.name}' does not have a public API server endpoint.",
    )


def _instance_protected_by_open_security_group(context: EvaluationContext) -> EvaluationOutcome:
    """Section 17's own relationship-based category: uses the real, adapter-emitted
    `ec2_instance PROTECTED_BY security_group` relationship (Sections 8's real
    AWS relationship list) - never inferred from shared tags or region alone."""
    asset = context.asset
    assert asset is not None
    if not context.relationships:
        return EvaluationOutcome(
            result=EvaluationResult.UNSUPPORTED,
            explanation=(
                f"No PROTECTED_BY relationship data is available for instance "
                f"'{asset.name}'."
            ),
            data_state="missing",
        )
    open_group_names: list[str] = []
    unsupported_group_names: list[str] = []
    for relationship, related in zip(context.relationships, context.related_assets, strict=False):
        if relationship.relationship_type != "PROTECTED_BY":
            continue
        raw = related.raw_metadata
        if is_truncated_metadata(raw) or "IpPermissions" not in raw:
            unsupported_group_names.append(related.name)
            continue
        if security_group_open_ip_permissions(raw):
            open_group_names.append(related.name)
    if open_group_names:
        return EvaluationOutcome(
            result=EvaluationResult.FAIL,
            explanation=(
                f"Instance '{asset.name}' is protected by security group(s) with "
                f"unrestricted inbound rules: {', '.join(open_group_names)}."
            ),
            facts={"open_security_groups": open_group_names},
        )
    if unsupported_group_names:
        return EvaluationOutcome(
            result=EvaluationResult.INDETERMINATE,
            explanation=(
                f"Instance '{asset.name}' has associated security group(s) with no "
                "ingress-rule data recorded - full protection status cannot be "
                "confirmed."
            ),
            data_state="partial",
        )
    return EvaluationOutcome(
        result=EvaluationResult.PASS,
        explanation=(
            f"Instance '{asset.name}' is not protected by any security group with "
            "unrestricted inbound rules."
        ),
    )


def _s3_public_access_unsupported(context: EvaluationContext) -> EvaluationOutcome:
    return EvaluationOutcome(
        result=EvaluationResult.UNSUPPORTED,
        explanation=(
            "S3 bucket public-access metadata (ACL, public access block "
            "configuration, bucket policy status) is not collected by the current "
            "AWS discovery adapter - only Name and CreationDate are captured for "
            f"s3_bucket assets. See {_FEASIBILITY_DOC}."
        ),
        data_state="missing",
    )


register_policy(
    PolicyDefinition(
        policy_id="CSPM.AWS.NETWORKING.SECURITY_GROUP_OPEN_INGRESS",
        version=1,
        name="Security group allows unrestricted inbound access",
        description=(
            "Fails when a security group has an inbound rule permitting traffic "
            "from 0.0.0.0/0 or ::/0 on any port/protocol."
        ),
        provider="aws",
        severity=PolicySeverity.HIGH,
        security_domain=PolicyDomain.NETWORKING,
        policy_family="network_exposure",
        evaluation_type=EvaluationType.RESOURCE_LEVEL,
        evaluator=_security_group_open_ingress,
        asset_categories=("security_group",),
        required_fields=("IpPermissions",),
        evidence_fields=("open_rules", "rule_count"),
        remediation_guidance=RemediationGuidance(
            objective="Restrict inbound security group rules to known, necessary CIDR ranges.",
            provider_specific_guidance=(
                "Review the security group's inbound rules in the EC2 console or via "
                "`aws ec2 describe-security-groups`; remove or narrow any rule whose "
                "source is 0.0.0.0/0 or ::/0 to a specific, justified CIDR range."
            ),
            validation_guidance=(
                "Re-run cloud posture evaluation after the change; this policy "
                "should return PASS."
            ),
            rollback_considerations=(
                "Removing an overly broad rule may break legitimate access from "
                "unlisted sources - confirm the real required source ranges before "
                "narrowing."
            ),
            required_approval_class="high",
        ),
    )
)

register_policy(
    PolicyDefinition(
        policy_id="CSPM.AWS.NETWORKING.SECURITY_GROUP_SSH_EXPOSED_TO_INTERNET",
        version=1,
        name="Security group exposes SSH to the internet",
        description=(
            "Fails when a security group allows inbound TCP port 22 from "
            "0.0.0.0/0 or ::/0."
        ),
        provider="aws",
        severity=PolicySeverity.CRITICAL,
        security_domain=PolicyDomain.INTERNET_EXPOSURE,
        policy_family="network_exposure",
        evaluation_type=EvaluationType.RESOURCE_LEVEL,
        evaluator=_make_security_group_port_evaluator(22, "SSH"),
        asset_categories=("security_group",),
        required_fields=("IpPermissions",),
        remediation_guidance=RemediationGuidance(
            objective="Remove unrestricted internet access to SSH.",
            provider_specific_guidance=(
                "Restrict port 22 to a bastion host, VPN CIDR, or Session Manager "
                "access instead of 0.0.0.0/0."
            ),
            validation_guidance=(
                "Re-run cloud posture evaluation after the change; this policy "
                "should return PASS."
            ),
            rollback_considerations=(
                "Confirm an alternative administrative access path exists before "
                "removing the open rule."
            ),
            required_approval_class="critical",
        ),
    )
)

register_policy(
    PolicyDefinition(
        policy_id="CSPM.AWS.NETWORKING.SECURITY_GROUP_RDP_EXPOSED_TO_INTERNET",
        version=1,
        name="Security group exposes RDP to the internet",
        description=(
            "Fails when a security group allows inbound TCP port 3389 from "
            "0.0.0.0/0 or ::/0."
        ),
        provider="aws",
        severity=PolicySeverity.CRITICAL,
        security_domain=PolicyDomain.INTERNET_EXPOSURE,
        policy_family="network_exposure",
        evaluation_type=EvaluationType.RESOURCE_LEVEL,
        evaluator=_make_security_group_port_evaluator(3389, "RDP"),
        asset_categories=("security_group",),
        required_fields=("IpPermissions",),
        remediation_guidance=RemediationGuidance(
            objective="Remove unrestricted internet access to RDP.",
            provider_specific_guidance=(
                "Restrict port 3389 to a bastion host or VPN CIDR instead of "
                "0.0.0.0/0."
            ),
            validation_guidance=(
                "Re-run cloud posture evaluation after the change; this policy "
                "should return PASS."
            ),
            rollback_considerations=(
                "Confirm an alternative administrative access path exists before "
                "removing the open rule."
            ),
            required_approval_class="critical",
        ),
    )
)

register_policy(
    PolicyDefinition(
        policy_id="CSPM.AWS.DATABASE.RDS_PUBLICLY_ACCESSIBLE",
        version=1,
        name="RDS instance is publicly accessible",
        description="Fails when an RDS instance's PubliclyAccessible flag is true.",
        provider="aws",
        severity=PolicySeverity.HIGH,
        security_domain=PolicyDomain.DATABASE,
        policy_family="internet_exposure",
        evaluation_type=EvaluationType.RESOURCE_LEVEL,
        evaluator=_rds_publicly_accessible,
        asset_categories=("rds_instance",),
        required_fields=("PubliclyAccessible",),
        remediation_guidance=RemediationGuidance(
            objective="Remove public accessibility from the database instance.",
            provider_specific_guidance=(
                "Set PubliclyAccessible to false via the RDS console or "
                "`aws rds modify-db-instance --no-publicly-accessible`."
            ),
            validation_guidance=(
                "Re-run cloud posture evaluation after the change; this policy "
                "should return PASS."
            ),
            rollback_considerations=(
                "Confirm no legitimate client depends on direct public "
                "connectivity before disabling."
            ),
            required_approval_class="high",
        ),
    )
)

register_policy(
    PolicyDefinition(
        policy_id="CSPM.AWS.DATABASE.RDS_STORAGE_ENCRYPTION_DISABLED",
        version=1,
        name="RDS instance storage encryption is disabled",
        description="Fails when an RDS instance's StorageEncrypted flag is false.",
        provider="aws",
        severity=PolicySeverity.MEDIUM,
        security_domain=PolicyDomain.ENCRYPTION,
        policy_family="data_protection",
        evaluation_type=EvaluationType.RESOURCE_LEVEL,
        evaluator=_rds_storage_encryption_disabled,
        asset_categories=("rds_instance",),
        required_fields=("StorageEncrypted",),
        remediation_guidance=RemediationGuidance(
            objective="Enable storage encryption for the database instance.",
            provider_specific_guidance=(
                "RDS storage encryption cannot be enabled on an existing "
                "unencrypted instance - create an encrypted snapshot copy and "
                "restore from it."
            ),
            validation_guidance=(
                "Re-run cloud posture evaluation against the replacement instance; "
                "this policy should return PASS."
            ),
            rollback_considerations=(
                "Requires a maintenance window and instance replacement - plan a "
                "cutover, not an in-place change."
            ),
            required_approval_class="medium",
        ),
    )
)

register_policy(
    PolicyDefinition(
        policy_id="CSPM.AWS.LOGGING.CLOUDTRAIL_ENABLED",
        version=1,
        name="CloudTrail trail present in environment",
        description=(
            "Fails when no CloudTrail trail asset is discovered anywhere in the "
            "environment."
        ),
        provider="aws",
        severity=PolicySeverity.HIGH,
        security_domain=PolicyDomain.LOGGING,
        policy_family="logging_coverage",
        evaluation_type=EvaluationType.ENVIRONMENT_LEVEL,
        evaluator=_cloudtrail_enabled,
        data_quality_requirements=(
            "Requires the environment's most recent CloudInventorySnapshot to have "
            "completeness_status == 'complete' for a genuine absence to be reported "
            "as FAIL rather than INDETERMINATE.",
        ),
        remediation_guidance=RemediationGuidance(
            objective="Ensure CloudTrail logging is enabled for the account.",
            provider_specific_guidance=(
                "Create a CloudTrail trail covering all regions via the CloudTrail "
                "console or `aws cloudtrail create-trail`."
            ),
            validation_guidance=(
                "Re-run cloud posture evaluation after the change; this policy "
                "should return PASS."
            ),
            rollback_considerations="None - enabling logging has no meaningful rollback risk.",
            required_approval_class="low",
        ),
    )
)

register_policy(
    PolicyDefinition(
        policy_id="CSPM.AWS.SECURITY_SERVICES.GUARDDUTY_ENABLED",
        version=1,
        name="GuardDuty detector present and enabled",
        description=(
            "Fails when no GuardDuty detector is discovered, or a discovered "
            "detector is disabled."
        ),
        provider="aws",
        severity=PolicySeverity.MEDIUM,
        security_domain=PolicyDomain.SECURITY_SERVICES,
        policy_family="threat_detection_coverage",
        evaluation_type=EvaluationType.ENVIRONMENT_LEVEL,
        evaluator=_guardduty_enabled,
        data_quality_requirements=(
            "Requires the environment's most recent CloudInventorySnapshot to have "
            "completeness_status == 'complete' for a genuine absence to be reported "
            "as FAIL rather than INDETERMINATE.",
        ),
        remediation_guidance=RemediationGuidance(
            objective="Enable GuardDuty threat detection for the account.",
            provider_specific_guidance=(
                "Enable GuardDuty via the GuardDuty console or "
                "`aws guardduty create-detector --enable`."
            ),
            validation_guidance=(
                "Re-run cloud posture evaluation after the change; this policy "
                "should return PASS."
            ),
            rollback_considerations=(
                "None - enabling threat detection has no meaningful rollback risk."
            ),
            required_approval_class="low",
        ),
    )
)

register_policy(
    PolicyDefinition(
        policy_id="CSPM.AWS.MONITORING.CONFIG_RECORDER_ENABLED",
        version=1,
        name="AWS Config recorder present",
        description=(
            "Fails when no AWS Config configuration recorder is discovered in "
            "the environment."
        ),
        provider="aws",
        severity=PolicySeverity.MEDIUM,
        security_domain=PolicyDomain.MONITORING,
        policy_family="configuration_management",
        evaluation_type=EvaluationType.ENVIRONMENT_LEVEL,
        evaluator=_config_recorder_enabled,
        data_quality_requirements=(
            "Checks recorder presence only - active recording status is not "
            "collected by the current adapter, so a PASS result carries "
            "data_state='partial'.",
        ),
        remediation_guidance=RemediationGuidance(
            objective="Register an AWS Config recorder for the account.",
            provider_specific_guidance=(
                "Create a configuration recorder via the AWS Config console or "
                "`aws configservice put-configuration-recorder`."
            ),
            validation_guidance=(
                "Re-run cloud posture evaluation after the change; this policy "
                "should return PASS."
            ),
            rollback_considerations=(
                "None - enabling configuration recording has no meaningful "
                "rollback risk."
            ),
            required_approval_class="low",
        ),
    )
)

register_policy(
    PolicyDefinition(
        policy_id="CSPM.AWS.LOGGING.CLOUDWATCH_LOG_RETENTION_CONFIGURED",
        version=1,
        name="CloudWatch log group has a defined retention period",
        description=(
            "Fails when a CloudWatch log group has no retentionInDays configured "
            "(logs retained indefinitely)."
        ),
        provider="aws",
        severity=PolicySeverity.LOW,
        security_domain=PolicyDomain.LOGGING,
        policy_family="logging_hygiene",
        evaluation_type=EvaluationType.RESOURCE_LEVEL,
        evaluator=_cloudwatch_log_retention_configured,
        asset_categories=("cloudwatch_log_group_metadata",),
        required_fields=("retentionInDays",),
        remediation_guidance=RemediationGuidance(
            objective="Define an explicit retention period for the log group.",
            provider_specific_guidance=(
                "Set a retention period via the CloudWatch Logs console or "
                "`aws logs put-retention-policy`."
            ),
            validation_guidance=(
                "Re-run cloud posture evaluation after the change; this policy "
                "should return PASS."
            ),
            rollback_considerations=(
                "Confirm the chosen retention period meets any real compliance "
                "or investigative requirement before applying it."
            ),
            required_approval_class="low",
        ),
    )
)

register_policy(
    PolicyDefinition(
        policy_id="CSPM.AWS.CONTAINERS.EKS_PUBLIC_ENDPOINT_ACCESS",
        version=1,
        name="EKS cluster API server endpoint is publicly accessible",
        description=(
            "Fails when an EKS cluster's resourcesVpcConfig.endpointPublicAccess is true."
        ),
        provider="aws",
        severity=PolicySeverity.HIGH,
        security_domain=PolicyDomain.KUBERNETES,
        policy_family="internet_exposure",
        evaluation_type=EvaluationType.RESOURCE_LEVEL,
        evaluator=_eks_public_endpoint_access,
        asset_categories=("eks_cluster",),
        required_fields=("resourcesVpcConfig.endpointPublicAccess",),
        remediation_guidance=RemediationGuidance(
            objective="Restrict the EKS API server endpoint to private access only.",
            provider_specific_guidance=(
                "Disable public endpoint access or restrict publicAccessCidrs via "
                "the EKS console or `aws eks update-cluster-config`."
            ),
            validation_guidance=(
                "Re-run cloud posture evaluation after the change; this policy "
                "should return PASS."
            ),
            rollback_considerations=(
                "Confirm private/VPN access to the cluster API exists before "
                "disabling the public endpoint."
            ),
            required_approval_class="high",
        ),
    )
)

register_policy(
    PolicyDefinition(
        policy_id="CSPM.AWS.NETWORKING.INSTANCE_PROTECTED_BY_OPEN_SECURITY_GROUP",
        version=1,
        name="Compute instance protected only by an unrestricted security group",
        description=(
            "Fails when an EC2 instance's associated security group(s), via the "
            "real PROTECTED_BY relationship, permit unrestricted inbound access."
        ),
        provider="aws",
        severity=PolicySeverity.HIGH,
        security_domain=PolicyDomain.NETWORKING,
        policy_family="network_exposure",
        evaluation_type=EvaluationType.RELATIONSHIP_BASED,
        evaluator=_instance_protected_by_open_security_group,
        asset_categories=("ec2_instance",),
        required_relationships=("PROTECTED_BY",),
        required_fields=("IpPermissions",),
        remediation_guidance=RemediationGuidance(
            objective="Restrict the instance's associated security group rules.",
            provider_specific_guidance=(
                "Review and narrow the inbound rules of every security group "
                "attached to this instance - see "
                "CSPM.AWS.NETWORKING.SECURITY_GROUP_OPEN_INGRESS for the same "
                "check applied directly to the security group."
            ),
            validation_guidance=(
                "Re-run cloud posture evaluation after the change; this policy "
                "should return PASS."
            ),
            rollback_considerations=(
                "Removing an overly broad rule may break legitimate access from "
                "unlisted sources - confirm the real required source ranges "
                "before narrowing."
            ),
            required_approval_class="high",
        ),
    )
)

register_policy(
    PolicyDefinition(
        policy_id="CSPM.AWS.STORAGE.S3_PUBLIC_ACCESS_INDICATED",
        version=1,
        name="S3 bucket public-access metadata indicates exposure",
        description="Always UNSUPPORTED in this environment - see unsupported_conditions.",
        provider="aws",
        severity=PolicySeverity.HIGH,
        security_domain=PolicyDomain.STORAGE,
        policy_family="internet_exposure",
        evaluation_type=EvaluationType.RESOURCE_LEVEL,
        evaluator=_s3_public_access_unsupported,
        asset_categories=("s3_bucket",),
        unsupported_conditions=(
            "The AWS discovery adapter only calls list_buckets/get_bucket_location "
            "for s3_bucket assets - no get_bucket_acl, get_public_access_block, or "
            "get_bucket_policy_status call is ever made, so this policy can never "
            f"reach a real PASS or FAIL in this deployment. See {_FEASIBILITY_DOC}.",
        ),
        documentation_reference=_FEASIBILITY_DOC,
        remediation_guidance=RemediationGuidance(
            objective=(
                "Not evaluable until the AWS adapter collects bucket "
                "ACL/public-access-block/policy-status data."
            ),
            provider_specific_guidance=(
                "No remediation guidance is offered while this policy is UNSUPPORTED."
            ),
            validation_guidance="N/A",
            rollback_considerations="N/A",
            required_approval_class="high",
        ),
    )
)
