"""EDP-009 Part 1, Section 12 (forward reference): the normalized, provider-neutral
shapes a real ProviderAdapter's discovery methods return. Defined now (sub-phase 2)
so gds_api.cloud.adapter's SupportsDiscovery Protocol can be properly typed against
something real, rather than the placeholder `object` return type sub-phase 1 used -
these are the same fields Section 12/15's own real CloudAsset/CloudAssetRelationship
DB models will persist in a later sub-phase; this module is the adapter-facing
contract, not the storage layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class NormalizedCloudAsset:
    provider: str
    native_id: str
    native_resource_type: str
    normalized_category: str
    name: str
    region_or_location: str | None = None
    availability_zone: str | None = None
    parent_native_id: str | None = None
    account_or_subscription_or_project: str | None = None
    lifecycle_state: str | None = None
    created_at_provider: datetime | None = None
    tags: dict[str, str] = field(default_factory=dict)
    internet_exposure_known: bool | None = None
    managed_service: bool | None = None
    # Redacted/size-bounded before persistence by the discovery service, never
    # persisted raw and unbounded - see Section 14's own real requirements. The
    # adapter's job is only to return what the provider actually said.
    raw_metadata: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class NormalizedCloudRelationship:
    source_native_id: str
    target_native_id: str
    # CONTAINS|BELONGS_TO|LOCATED_IN|ATTACHED_TO|CONNECTED_TO|ROUTES_TO|EXPOSED_BY|
    # PROTECTED_BY|USES|ASSUMES|CAN_ACCESS|ENCRYPTED_BY|LOGS_TO|MONITORED_BY|
    # DEPLOYED_FROM|RUNS_ON|LOAD_BALANCES|RESOLVES_TO|MEMBER_OF|PEERS_WITH
    relationship_type: str
    # True only when the provider API directly stated this relationship (e.g. an
    # attachment API field) - False when the adapter inferred it from separate
    # facts. Section 15's own rule: a derived relationship must say so and explain
    # its rule, never presented identically to a direct, provider-stated one.
    is_direct: bool
    derivation_rule: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)
