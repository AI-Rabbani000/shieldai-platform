"""EDP-009 Part 2, Section 13: the initial Azure policy set. Only policies whose
required data is genuinely collected by the real Part 1 `AzureProviderAdapter` (7 of
19 registry categories - see
docs/reviews/phase-22-part2-policy-feasibility-matrix.md) are given a real
pass/fail evaluator. Azure's `network_security_group`, `sql_resource`, and
`defender_for_cloud_status_metadata` categories are not discovered at all in this
Part, so no NSG/SQL/Defender policy exists here - not a placeholder omission, a
direct consequence of the feasibility matrix.

Field paths below were confirmed directly against the real Azure SDK model classes
(azure.mgmt.storage.models.StorageAccountProperties,
azure.mgmt.keyvault.models.VaultProperties) and their real `.as_dict()` output -
note that `.as_dict()` serialises to the REST wire format (camelCase, nested under
"properties"), which does NOT always match the Python attribute's own snake_case
name (e.g. `enable_https_traffic_only` serialises to `supportsHttpsTrafficOnly`,
`network_rule_set` serialises to `networkAcls` - real API-versioning legacy naming,
not a typo here).
"""

from __future__ import annotations

from gds_api.cloud.posture.policies._helpers import get_nested, is_missing, is_truncated_metadata
from gds_api.cloud.posture.registry import PolicyDefinition, RemediationGuidance, register_policy
from gds_api.cloud.posture.taxonomy import (
    EvaluationResult,
    EvaluationType,
    PolicyDomain,
    PolicySeverity,
)
from gds_api.cloud.posture.types import EvaluationContext, EvaluationOutcome


def _storage_account_public_network_access(context: EvaluationContext) -> EvaluationOutcome:
    asset = context.asset
    assert asset is not None
    # internet_exposure_known is real, adapter-normalized from public_network_access
    # (azure_discovery.py:192-196) - None means the field itself was absent on the
    # SDK model, not "not exposed".
    if asset.internet_exposure_known is None:
        return EvaluationOutcome(
            result=EvaluationResult.UNSUPPORTED,
            explanation="This storage account has no public_network_access data recorded.",
            data_state="missing",
        )
    if asset.internet_exposure_known is True:
        return EvaluationOutcome(
            result=EvaluationResult.FAIL,
            explanation=f"Storage account '{asset.name}' has public network access enabled.",
            facts={"public_network_access": "Enabled"},
        )
    return EvaluationOutcome(
        result=EvaluationResult.PASS,
        explanation=f"Storage account '{asset.name}' does not have public network access enabled.",
    )


def _storage_account_allows_blob_public_access(context: EvaluationContext) -> EvaluationOutcome:
    asset = context.asset
    assert asset is not None
    raw = asset.raw_metadata
    if is_truncated_metadata(raw):
        return EvaluationOutcome(
            result=EvaluationResult.INDETERMINATE,
            explanation=(
                "This storage account's metadata was truncated - blob public "
                "access cannot be evaluated."
            ),
            data_state="missing",
        )
    value = get_nested(raw, "properties", "allowBlobPublicAccess")
    if is_missing(value):
        return EvaluationOutcome(
            result=EvaluationResult.UNSUPPORTED,
            explanation="This storage account has no allowBlobPublicAccess data recorded.",
            data_state="missing",
        )
    if value is True:
        return EvaluationOutcome(
            result=EvaluationResult.FAIL,
            explanation=f"Storage account '{asset.name}' allows anonymous blob public access.",
            facts={"allowBlobPublicAccess": True},
        )
    return EvaluationOutcome(
        result=EvaluationResult.PASS,
        explanation=f"Storage account '{asset.name}' does not allow anonymous blob public access.",
    )


def _storage_account_https_only_disabled(context: EvaluationContext) -> EvaluationOutcome:
    asset = context.asset
    assert asset is not None
    raw = asset.raw_metadata
    if is_truncated_metadata(raw):
        return EvaluationOutcome(
            result=EvaluationResult.INDETERMINATE,
            explanation=(
                "This storage account's metadata was truncated - transport "
                "security cannot be evaluated."
            ),
            data_state="missing",
        )
    # Real API-versioning quirk: StorageAccountProperties.enable_https_traffic_only
    # serialises to the wire key "supportsHttpsTrafficOnly", confirmed directly
    # against the real SDK model's own as_dict() output.
    value = get_nested(raw, "properties", "supportsHttpsTrafficOnly")
    if is_missing(value):
        return EvaluationOutcome(
            result=EvaluationResult.UNSUPPORTED,
            explanation="This storage account has no supportsHttpsTrafficOnly data recorded.",
            data_state="missing",
        )
    if value is False:
        return EvaluationOutcome(
            result=EvaluationResult.FAIL,
            explanation=f"Storage account '{asset.name}' does not require HTTPS-only traffic.",
            facts={"supportsHttpsTrafficOnly": False},
        )
    return EvaluationOutcome(
        result=EvaluationResult.PASS,
        explanation=f"Storage account '{asset.name}' requires HTTPS-only traffic.",
    )


def _storage_account_default_network_action_allow(
    context: EvaluationContext,
) -> EvaluationOutcome:
    asset = context.asset
    assert asset is not None
    raw = asset.raw_metadata
    if is_truncated_metadata(raw):
        return EvaluationOutcome(
            result=EvaluationResult.INDETERMINATE,
            explanation=(
                "This storage account's metadata was truncated - network rules "
                "cannot be evaluated."
            ),
            data_state="missing",
        )
    # Real API-versioning quirk: StorageAccountProperties.network_rule_set
    # serialises to the wire key "networkAcls", confirmed directly against the
    # real SDK model's own as_dict() output.
    value = get_nested(raw, "properties", "networkAcls", "defaultAction")
    if is_missing(value):
        return EvaluationOutcome(
            result=EvaluationResult.UNSUPPORTED,
            explanation="This storage account has no networkAcls.defaultAction data recorded.",
            data_state="missing",
        )
    if value == "Allow":
        return EvaluationOutcome(
            result=EvaluationResult.FAIL,
            explanation=(
                f"Storage account '{asset.name}' has a default network action of "
                "'Allow' - no IP/VNet restriction is enforced by default."
            ),
            facts={"defaultAction": "Allow"},
        )
    return EvaluationOutcome(
        result=EvaluationResult.PASS,
        explanation=f"Storage account '{asset.name}' has a default network action of '{value}'.",
    )


def _key_vault_soft_delete_disabled(context: EvaluationContext) -> EvaluationOutcome:
    asset = context.asset
    assert asset is not None
    raw = asset.raw_metadata
    if is_truncated_metadata(raw):
        return EvaluationOutcome(
            result=EvaluationResult.INDETERMINATE,
            explanation=(
                "This Key Vault's metadata was truncated - soft-delete cannot "
                "be evaluated."
            ),
            data_state="missing",
        )
    value = get_nested(raw, "properties", "enableSoftDelete")
    if is_missing(value):
        return EvaluationOutcome(
            result=EvaluationResult.UNSUPPORTED,
            explanation="This Key Vault has no enableSoftDelete data recorded.",
            data_state="missing",
        )
    if value is False:
        return EvaluationOutcome(
            result=EvaluationResult.FAIL,
            explanation=f"Key Vault '{asset.name}' does not have soft-delete enabled.",
            facts={"enableSoftDelete": False},
        )
    return EvaluationOutcome(
        result=EvaluationResult.PASS,
        explanation=f"Key Vault '{asset.name}' has soft-delete enabled.",
    )


def _key_vault_purge_protection_disabled(context: EvaluationContext) -> EvaluationOutcome:
    asset = context.asset
    assert asset is not None
    raw = asset.raw_metadata
    if is_truncated_metadata(raw):
        return EvaluationOutcome(
            result=EvaluationResult.INDETERMINATE,
            explanation=(
                "This Key Vault's metadata was truncated - purge protection "
                "cannot be evaluated."
            ),
            data_state="missing",
        )
    value = get_nested(raw, "properties", "enablePurgeProtection")
    if is_missing(value):
        return EvaluationOutcome(
            result=EvaluationResult.UNSUPPORTED,
            explanation="This Key Vault has no enablePurgeProtection data recorded.",
            data_state="missing",
        )
    if value is not True:
        return EvaluationOutcome(
            result=EvaluationResult.FAIL,
            explanation=f"Key Vault '{asset.name}' does not have purge protection enabled.",
            facts={"enablePurgeProtection": value},
        )
    return EvaluationOutcome(
        result=EvaluationResult.PASS,
        explanation=f"Key Vault '{asset.name}' has purge protection enabled.",
    )


_RERUN_GUIDANCE = (
    "Re-run cloud posture evaluation after the change; this policy should return PASS."
)

register_policy(
    PolicyDefinition(
        policy_id="CSPM.AZURE.STORAGE.STORAGE_ACCOUNT_PUBLIC_NETWORK_ACCESS",
        version=1,
        name="Storage account has public network access enabled",
        description="Fails when a storage account's public_network_access is Enabled.",
        provider="azure",
        severity=PolicySeverity.HIGH,
        security_domain=PolicyDomain.INTERNET_EXPOSURE,
        policy_family="internet_exposure",
        evaluation_type=EvaluationType.RESOURCE_LEVEL,
        evaluator=_storage_account_public_network_access,
        asset_categories=("storage_account",),
        required_fields=("public_network_access",),
        remediation_guidance=RemediationGuidance(
            objective="Disable public network access to the storage account.",
            provider_specific_guidance=(
                "Set Public network access to Disabled via the Storage Account "
                "Networking blade or `az storage account update "
                "--public-network-access Disabled`."
            ),
            validation_guidance=_RERUN_GUIDANCE,
            rollback_considerations=(
                "Confirm private endpoints or VNet rules provide the access "
                "clients actually need before disabling public access."
            ),
            required_approval_class="high",
        ),
    )
)

register_policy(
    PolicyDefinition(
        policy_id="CSPM.AZURE.STORAGE.STORAGE_ACCOUNT_ALLOWS_BLOB_PUBLIC_ACCESS",
        version=1,
        name="Storage account allows anonymous blob public access",
        description="Fails when a storage account's allowBlobPublicAccess is true.",
        provider="azure",
        severity=PolicySeverity.HIGH,
        security_domain=PolicyDomain.STORAGE,
        policy_family="internet_exposure",
        evaluation_type=EvaluationType.RESOURCE_LEVEL,
        evaluator=_storage_account_allows_blob_public_access,
        asset_categories=("storage_account",),
        required_fields=("properties.allowBlobPublicAccess",),
        remediation_guidance=RemediationGuidance(
            objective="Disable anonymous blob public access at the account level.",
            provider_specific_guidance=(
                "Set Allow Blob public access to Disabled via the Storage Account "
                "Configuration blade or `az storage account update "
                "--allow-blob-public-access false`."
            ),
            validation_guidance=_RERUN_GUIDANCE,
            rollback_considerations=(
                "Confirm no container relies on anonymous read access before disabling."
            ),
            required_approval_class="high",
        ),
    )
)

register_policy(
    PolicyDefinition(
        policy_id="CSPM.AZURE.ENCRYPTION.STORAGE_ACCOUNT_HTTPS_ONLY_DISABLED",
        version=1,
        name="Storage account does not require HTTPS-only traffic",
        description="Fails when a storage account's supportsHttpsTrafficOnly is false.",
        provider="azure",
        severity=PolicySeverity.MEDIUM,
        security_domain=PolicyDomain.ENCRYPTION,
        policy_family="transport_encryption",
        evaluation_type=EvaluationType.RESOURCE_LEVEL,
        evaluator=_storage_account_https_only_disabled,
        asset_categories=("storage_account",),
        required_fields=("properties.supportsHttpsTrafficOnly",),
        remediation_guidance=RemediationGuidance(
            objective="Require HTTPS-only traffic to the storage account.",
            provider_specific_guidance=(
                "Set Secure transfer required to Enabled via the Storage Account "
                "Configuration blade or `az storage account update --https-only true`."
            ),
            validation_guidance=_RERUN_GUIDANCE,
            rollback_considerations="None - all Azure Storage REST/SDK clients support HTTPS.",
            required_approval_class="low",
        ),
    )
)

register_policy(
    PolicyDefinition(
        policy_id="CSPM.AZURE.NETWORKING.STORAGE_ACCOUNT_DEFAULT_NETWORK_ACTION_ALLOW",
        version=1,
        name="Storage account default network action is Allow",
        description="Fails when a storage account's network rule set defaultAction is Allow.",
        provider="azure",
        severity=PolicySeverity.MEDIUM,
        security_domain=PolicyDomain.NETWORKING,
        policy_family="network_exposure",
        evaluation_type=EvaluationType.RESOURCE_LEVEL,
        evaluator=_storage_account_default_network_action_allow,
        asset_categories=("storage_account",),
        required_fields=("properties.networkAcls.defaultAction",),
        remediation_guidance=RemediationGuidance(
            objective="Restrict the storage account's default network access.",
            provider_specific_guidance=(
                "Set the default action to Deny and add explicit IP/VNet rules via "
                "the Storage Account Networking blade or `az storage account "
                "update --default-action Deny`."
            ),
            validation_guidance=_RERUN_GUIDANCE,
            rollback_considerations=(
                "Add explicit allow rules for real required clients before "
                "switching to Deny."
            ),
            required_approval_class="medium",
        ),
    )
)

register_policy(
    PolicyDefinition(
        policy_id="CSPM.AZURE.KEY_MANAGEMENT.KEY_VAULT_SOFT_DELETE_DISABLED",
        version=1,
        name="Key Vault does not have soft-delete enabled",
        description="Fails when a Key Vault's enableSoftDelete is false.",
        provider="azure",
        severity=PolicySeverity.MEDIUM,
        security_domain=PolicyDomain.KEY_MANAGEMENT,
        policy_family="data_protection",
        evaluation_type=EvaluationType.RESOURCE_LEVEL,
        evaluator=_key_vault_soft_delete_disabled,
        asset_categories=("key_vault_metadata",),
        required_fields=("properties.enableSoftDelete",),
        remediation_guidance=RemediationGuidance(
            objective="Enable soft-delete on the Key Vault.",
            provider_specific_guidance=(
                "Soft-delete cannot be disabled once enabled and, on current API "
                "versions, cannot be re-enabled after vault creation without "
                "recreating the vault - enable it at creation time going forward "
                "via `az keyvault create --enable-soft-delete true`."
            ),
            validation_guidance=_RERUN_GUIDANCE,
            rollback_considerations="None - soft-delete has no meaningful rollback risk.",
            required_approval_class="low",
        ),
    )
)

register_policy(
    PolicyDefinition(
        policy_id="CSPM.AZURE.KEY_MANAGEMENT.KEY_VAULT_PURGE_PROTECTION_DISABLED",
        version=1,
        name="Key Vault does not have purge protection enabled",
        description="Fails when a Key Vault's enablePurgeProtection is not true.",
        provider="azure",
        severity=PolicySeverity.MEDIUM,
        security_domain=PolicyDomain.KEY_MANAGEMENT,
        policy_family="data_protection",
        evaluation_type=EvaluationType.RESOURCE_LEVEL,
        evaluator=_key_vault_purge_protection_disabled,
        asset_categories=("key_vault_metadata",),
        required_fields=("properties.enablePurgeProtection",),
        remediation_guidance=RemediationGuidance(
            objective="Enable purge protection on the Key Vault.",
            provider_specific_guidance=(
                "Enable purge protection via the Key Vault Properties blade or "
                "`az keyvault update --enable-purge-protection true` - "
                "irreversible once enabled."
            ),
            validation_guidance=_RERUN_GUIDANCE,
            rollback_considerations=(
                "Purge protection cannot be disabled once enabled - confirm this "
                "is intended before applying."
            ),
            required_approval_class="medium",
        ),
    )
)
