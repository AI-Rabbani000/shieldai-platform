"""EDP-009 Part 1, Section 1: the Cloud Provider Registry - a code-defined,
immutable catalogue of what cloud providers this platform knows about and what each
one can actually do today, mirroring gds_api.capabilities.definitions'
CapabilityDefinition/CAPABILITY_REGISTRY precedent (ADR 0015) and
gds_api.agents.registry's AGENT_REGISTRY/PLANNED_AGENTS precedent (ADR 0012) - a
provider's real capability state lives in code, never fabricated by a database row.

Real, decisive finding from this Part's own pre-build audit
(docs/reviews/phase-22-cloud-foundation-pre-build-audit.md): no AWS/Azure/GCP/
Kubernetes credentials exist anywhere in this environment (.env, ~/.aws, ~/.kube,
env vars all confirmed empty). Every provider therefore starts this Part at
NOT_YET_IMPLEMENTED (no adapter code exists yet - Sections 6-11 build it across
later sub-phases of this same Part) and, even once a real, fixture-tested adapter
exists, can only ever reach FOUNDATION_ONLY in this environment - SUPPORTED
requires real live verification against a real account, which no available
credential set makes possible here. This is not a placeholder status; it is the
honest, current, code-verified truth, and the enum values below deliberately
support the full mode:

Do not upgrade a provider's status field without a real, corresponding capability
existing in code - matching this Part's own Section 49 "Honest Implementation
Rules" ("Do not mark a provider as supported when only an interface or
placeholder exists").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class CloudProviderStatus(StrEnum):
    """Deliberately more granular than Section 1's own example list ("Supported,
    Foundation only, Experimental, Disabled, Unavailable") - NOT_YET_IMPLEMENTED is
    added because this Part is built incrementally across sub-phases, and
    "Foundation only" needs to mean one specific, stable thing (a real,
    fixture-tested adapter that has never been live-verified) rather than also
    covering "no adapter code exists at all yet", which would make the same status
    value mean two different things depending on when you read it."""

    NOT_YET_IMPLEMENTED = "NOT_YET_IMPLEMENTED"
    FOUNDATION_ONLY = "FOUNDATION_ONLY"
    EXPERIMENTAL = "EXPERIMENTAL"
    SUPPORTED = "SUPPORTED"
    DISABLED = "DISABLED"
    UNAVAILABLE = "UNAVAILABLE"


class DiscoveryScope(StrEnum):
    """What level of cloud hierarchy a discovery run can target - matches Section
    2's real per-provider environment-type lists (organisation/account/subscription/
    project/resource-group/cluster), not a fabricated common hierarchy."""

    ORGANISATION = "ORGANISATION"
    ACCOUNT_OR_SUBSCRIPTION_OR_PROJECT = "ACCOUNT_OR_SUBSCRIPTION_OR_PROJECT"
    RESOURCE_GROUP_OR_FOLDER = "RESOURCE_GROUP_OR_FOLDER"
    CLUSTER = "CLUSTER"
    NAMESPACE = "NAMESPACE"


@dataclass(frozen=True)
class CloudProviderDefinition:
    provider_id: str
    display_name: str
    supported_authentication_mechanisms: tuple[str, ...]
    supported_discovery_scopes: tuple[DiscoveryScope, ...]
    supported_resource_categories: tuple[str, ...]
    regional: bool
    status: CloudProviderStatus = CloudProviderStatus.NOT_YET_IMPLEMENTED
    adapter_available: bool = False
    connection_test_capability: bool = False
    inventory_capability: bool = False
    known_limitations: tuple[str, ...] = field(default_factory=tuple)


CLOUD_PROVIDER_REGISTRY: dict[str, CloudProviderDefinition] = {
    "aws": CloudProviderDefinition(
        provider_id="aws",
        display_name="Amazon Web Services",
        supported_authentication_mechanisms=(
            "assume_role",
            "external_id_sts",
            "short_lived_sts_credentials",
        ),
        supported_discovery_scopes=(
            DiscoveryScope.ORGANISATION,
            DiscoveryScope.ACCOUNT_OR_SUBSCRIPTION_OR_PROJECT,
        ),
        supported_resource_categories=(
            "organisation",
            "account",
            "iam_identity_summary",
            "region",
            "ec2_instance",
            "vpc",
            "subnet",
            "security_group",
            "network_acl",
            "internet_gateway",
            "nat_gateway",
            "elastic_ip",
            "load_balancer",
            "s3_bucket",
            "rds_instance",
            "lambda_function",
            "ecs_cluster",
            "eks_cluster",
            "ecr_repository",
            "kms_key",
            "secrets_manager_secret_metadata",
            "cloudtrail_trail_metadata",
            "guardduty_detector_metadata",
            "config_recorder_metadata",
            "cloudwatch_log_group_metadata",
        ),
        regional=True,
        status=CloudProviderStatus.FOUNDATION_ONLY,
        adapter_available=True,
        connection_test_capability=True,
        inventory_capability=True,
        known_limitations=(
            "A real, fixture-tested AWSProviderAdapter exists (EDP-009 Part 1, "
            "Section 8) but has never been live-verified - no live AWS credentials "
            "exist anywhere in this deployment environment. Every real call this "
            "adapter makes will genuinely, honestly fail until real credentials are "
            "configured; it is not a placeholder, but it is not production-supported "
            "either. See docs/adr/0050-provider-neutral-cloud-foundation.md.",
        ),
    ),
    "azure": CloudProviderDefinition(
        provider_id="azure",
        display_name="Microsoft Azure",
        supported_authentication_mechanisms=(
            "service_principal",
            "managed_identity",
            "workload_identity_federation",
        ),
        supported_discovery_scopes=(
            DiscoveryScope.ORGANISATION,
            DiscoveryScope.ACCOUNT_OR_SUBSCRIPTION_OR_PROJECT,
            DiscoveryScope.RESOURCE_GROUP_OR_FOLDER,
        ),
        supported_resource_categories=(
            "tenant_identity",
            "management_group",
            "subscription",
            "resource_group",
            "virtual_machine",
            "virtual_network",
            "subnet",
            "network_security_group",
            "public_ip_address",
            "load_balancer",
            "storage_account",
            "sql_resource",
            "key_vault_metadata",
            "function_app",
            "app_service",
            "container_registry",
            "aks_cluster",
            "log_analytics_workspace",
            "defender_for_cloud_status_metadata",
        ),
        regional=True,
        status=CloudProviderStatus.FOUNDATION_ONLY,
        adapter_available=True,
        connection_test_capability=True,
        inventory_capability=True,
        known_limitations=(
            "A real, fixture-tested AzureProviderAdapter exists (EDP-009 Part 1, "
            "Section 9) but has never been live-verified - no live Azure "
            "credentials exist anywhere in this deployment environment. It covers "
            "only 7 of the 19 categories listed above (subscription, "
            "resource_group, virtual_machine, virtual_network, subnet, "
            "storage_account, key_vault_metadata) - a real, disclosed bound, per "
            "Section 9's own permission to keep this scope bounded when no live "
            "credentials exist. See docs/guides/azure-adapter.md.",
        ),
    ),
    "gcp": CloudProviderDefinition(
        provider_id="gcp",
        display_name="Google Cloud Platform",
        supported_authentication_mechanisms=(
            "service_account_impersonation",
            "workload_identity_federation",
            "short_lived_credentials",
        ),
        supported_discovery_scopes=(
            DiscoveryScope.ORGANISATION,
            DiscoveryScope.RESOURCE_GROUP_OR_FOLDER,
            DiscoveryScope.ACCOUNT_OR_SUBSCRIPTION_OR_PROJECT,
        ),
        supported_resource_categories=(
            "organisation",
            "folder",
            "project",
            "compute_instance",
            "network",
            "subnetwork",
            "firewall_rule",
            "external_ip_address",
            "load_balancer",
            "cloud_storage_bucket",
            "cloud_sql",
            "kms_key_metadata",
            "secret_manager_metadata",
            "cloud_function",
            "cloud_run",
            "gke_cluster",
            "artifact_registry",
            "logging_sink",
            "security_command_center_enablement_metadata",
        ),
        regional=True,
        status=CloudProviderStatus.FOUNDATION_ONLY,
        adapter_available=True,
        connection_test_capability=True,
        inventory_capability=True,
        known_limitations=(
            "A real, fixture-tested GCPProviderAdapter exists (EDP-009 Part 1, "
            "Section 10) but has never been live-verified - no live GCP "
            "credentials exist anywhere in this deployment environment. It "
            "covers only 6 of the 19 categories listed above (project, "
            "compute_instance, network, subnetwork, firewall_rule, "
            "cloud_storage_bucket) - a real, disclosed bound, per Section 10's "
            "own permission to keep this scope bounded when no live credentials "
            "exist. See docs/guides/gcp-adapter.md.",
        ),
    ),
    "kubernetes": CloudProviderDefinition(
        provider_id="kubernetes",
        display_name="Kubernetes",
        supported_authentication_mechanisms=(
            "service_account_or_workload_identity_reference",
            "restricted_kubeconfig_secret_reference",
        ),
        supported_discovery_scopes=(
            DiscoveryScope.CLUSTER,
            DiscoveryScope.NAMESPACE,
        ),
        supported_resource_categories=(
            "cluster_identity",
            "node",
            "namespace",
            "deployment",
            "statefulset",
            "daemonset",
            "replicaset",
            "pod",
            "service",
            "ingress",
            "network_policy",
            "role",
            "cluster_role",
            "role_binding",
            "cluster_role_binding",
            "service_account",
            "configmap_metadata",
            "secret_metadata",
            "persistent_volume",
            "persistent_volume_claim",
        ),
        regional=False,
        status=CloudProviderStatus.FOUNDATION_ONLY,
        adapter_available=True,
        connection_test_capability=True,
        inventory_capability=True,
        known_limitations=(
            "A real, fixture-tested KubernetesProviderAdapter exists (EDP-009 "
            "Part 1, Section 11) but has never been live-verified - no kubeconfig "
            "or cluster credentials exist in this deployment environment. It "
            "covers only 6 of the 20 categories listed above (cluster_identity, "
            "node, namespace, pod, deployment, service) - a real, disclosed "
            "bound. Full container/Kubernetes security analysis is explicitly "
            "out of scope for this Part (belongs to EDP-009 Part 4). See "
            "docs/guides/kubernetes-adapter.md.",
        ),
    ),
}


def get_provider(provider_id: str) -> CloudProviderDefinition | None:
    return CLOUD_PROVIDER_REGISTRY.get(provider_id)


def list_providers() -> list[CloudProviderDefinition]:
    return list(CLOUD_PROVIDER_REGISTRY.values())
