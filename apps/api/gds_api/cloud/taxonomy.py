"""EDP-009 Part 1, Section 13: the controlled, provider-neutral asset taxonomy.

Distinct from each adapter's own, more granular `normalized_category` (e.g.
AWS's `ec2_instance`, GCP's `compute_instance`, Azure's `virtual_machine`,
Kubernetes' `node`) - that per-adapter value is real and already established
(Section 1's own provider registry, Sections 8-11's real discovery code) and
is preserved on every persisted `CloudAsset` as `provider_category`, never
discarded. This module maps each of those real, adapter-emitted category
strings onto Section 13's own cross-provider taxonomy, so a security analyst
can ask "show me every virtual machine across all four providers" without
needing to know each provider's own vocabulary.

Section 13's own rule: "Do not misuse 'unknown' to conceal failed
normalization." `UNKNOWN_OR_PROVIDER_SPECIFIC` is therefore only ever reached
for a `provider_category` this module genuinely has no real mapping for -
`taxonomy_category_for()` never silently drops a category into it by
omission; every category any of the four real adapters (Sections 8-11)
currently emits has an explicit, real entry below, checked by
`tests/test_cloud_taxonomy.py`'s own completeness test against the live
provider registry.
"""

from __future__ import annotations

# Section 13's own example list, verbatim.
NORMALIZED_ASSET_CATEGORIES: frozenset[str] = frozenset(
    {
        "organisation",
        "account",
        "subscription",
        "project",
        "resource_group",
        "region",
        "availability_zone",
        "identity",
        "role",
        "policy",
        "virtual_machine",
        "container_cluster",
        "container_workload",
        "container_image",
        "network",
        "subnet",
        "firewall",
        "security_group",
        "public_ip",
        "load_balancer",
        "gateway",
        "dns_resource",
        "object_storage",
        "database",
        "function",
        "application_service",
        "queue_or_messaging_service",
        "encryption_key",
        "secret_metadata",
        "logging_resource",
        "monitoring_resource",
        "security_service",
        "repository",
        "infrastructure_template",
        "unknown_or_provider_specific",
    }
)

UNKNOWN_OR_PROVIDER_SPECIFIC = "unknown_or_provider_specific"

# provider_category (each adapter's own real, already-tested normalized_category
# value - Sections 8-11) -> Section 13's canonical taxonomy value. Every key here
# is a category one of the four real adapters actually emits today - not the
# provider registry's full aspirational list, which includes categories no
# adapter implements yet and therefore cannot honestly be pre-mapped.
_PROVIDER_CATEGORY_TO_TAXONOMY: dict[str, str] = {
    # AWS (gds_api/cloud/adapters/aws_discovery.py)
    "organisation": "organisation",
    "account": "account",
    "iam_identity_summary": "identity",
    "region": "region",
    "ec2_instance": "virtual_machine",
    "vpc": "network",
    "subnet": "subnet",
    "security_group": "security_group",
    "network_acl": "firewall",
    "internet_gateway": "gateway",
    "nat_gateway": "gateway",
    "elastic_ip": "public_ip",
    "load_balancer": "load_balancer",
    "s3_bucket": "object_storage",
    "rds_instance": "database",
    "lambda_function": "function",
    # Both ECS clusters and ECS services are emitted with provider_category
    # "ecs_cluster" by the AWS adapter (native_resource_type still distinguishes
    # "ecs.Cluster" from "ecs.Service") - a real, disclosed imprecision (see
    # docs/guides/aws-adapter.md), not corrected here by inventing a category the
    # adapter doesn't actually produce.
    "ecs_cluster": "container_cluster",
    "eks_cluster": "container_cluster",
    "ecr_repository": "repository",
    "kms_key": "encryption_key",
    "secrets_manager_secret_metadata": "secret_metadata",
    "cloudtrail_trail_metadata": "logging_resource",
    "guardduty_detector_metadata": "security_service",
    "config_recorder_metadata": "monitoring_resource",
    "cloudwatch_log_group_metadata": "logging_resource",
    # Azure (gds_api/cloud/adapters/azure_discovery.py)
    "subscription": "subscription",
    "resource_group": "resource_group",
    "virtual_machine": "virtual_machine",
    "virtual_network": "network",
    "storage_account": "object_storage",
    # A Key Vault stores keys, secrets, and certificates - no single Section 13
    # category fits perfectly; encryption_key chosen for consistency with AWS
    # KMS's own mapping, a reasonable but imperfect fit, not a precise one.
    "key_vault_metadata": "encryption_key",
    # GCP (gds_api/cloud/adapters/gcp_discovery.py)
    "project": "project",
    "compute_instance": "virtual_machine",
    "network": "network",
    "subnetwork": "subnet",
    "firewall_rule": "firewall",
    "cloud_storage_bucket": "object_storage",
    # Kubernetes (gds_api/cloud/adapters/k8s_discovery.py)
    "cluster_identity": "container_cluster",
    "node": "virtual_machine",
    "namespace": "resource_group",
    "pod": "container_workload",
    "deployment": "container_workload",
    "service": "gateway",
}


def taxonomy_category_for(provider_category: str) -> str:
    """Real mapping only - `UNKNOWN_OR_PROVIDER_SPECIFIC` for anything genuinely
    unmapped, never a guessed or fabricated taxonomy value."""
    return _PROVIDER_CATEGORY_TO_TAXONOMY.get(provider_category, UNKNOWN_OR_PROVIDER_SPECIFIC)
