"""EDP-009 Part 1, Section 7: the Provider Adapter Contract - a strict interface
every real provider adapter (AWS, Azure, GCP, Kubernetes - built in later
sub-phases of this same Part) must implement. Defined now, alongside Connection
Validation (Section 5), because validation is the first real capability that needs
it - Section 5 cannot do anything real without a way to call into a provider.

No raw SDK client is ever exposed outside an adapter's own module - every method
below returns a typed, provider-neutral result. `ADAPTER_REGISTRY` starts empty in
this sub-phase (no adapter code exists yet); later sub-phases register a real
instance per provider as each is built, never a placeholder.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from gds_api.cloud.schemas import NormalizedCloudAsset, NormalizedCloudRelationship

if TYPE_CHECKING:
    from gds_api.models import CloudConnectionProfile


class ProviderErrorCategory(StrEnum):
    """A sanitized, provider-neutral classification of what went wrong - never a
    raw SDK exception (which can embed request IDs, internal hostnames, or other
    detail this codebase's own established discipline keeps out of user-facing
    errors and audit/evidence records)."""

    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    SCOPE_NOT_FOUND = "SCOPE_NOT_FOUND"
    RATE_LIMITED = "RATE_LIMITED"
    TIMEOUT = "TIMEOUT"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    SERVICE_UNSUPPORTED = "SERVICE_UNSUPPORTED"
    NETWORK_ERROR = "NETWORK_ERROR"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ProviderError:
    category: ProviderErrorCategory
    sanitized_message: str
    retryable: bool


@dataclass(frozen=True)
class ScopeIdentity:
    """What `identify_scope` confirms - the real, provider-native identity the
    connection profile authenticates as, never fabricated ahead of a real call."""

    native_id: str
    display_name: str
    environment_type: str
    organisational_path: str | None = None


@dataclass(frozen=True)
class ConnectionValidationOutcome:
    success: bool
    provider_identity: str | None
    scope_identity: ScopeIdentity | None
    capability_availability: dict[str, bool]
    latency_ms: float
    error: ProviderError | None = None


@dataclass(frozen=True)
class ChildEnvironmentRef:
    native_id: str
    display_name: str
    environment_type: str
    parent_native_id: str | None


@dataclass(frozen=True)
class CapabilityMatrix:
    """Section 7's `return_capability_matrix` - what this adapter can honestly do
    right now, checked by callers before assuming a capability exists rather than
    discovering that mid-operation."""

    provider_id: str
    can_validate_connection: bool
    can_enumerate_child_environments: bool
    can_list_regions: bool
    can_discover_assets: bool
    can_discover_relationships: bool
    supported_resource_categories: tuple[str, ...] = field(default_factory=tuple)


class ProviderAdapter(ABC):
    """Every method is async except the two pure, synchronous classification/
    capability queries. Real adapters (AWS/Azure/GCP/Kubernetes) implement this in
    full; this Part's own honesty rule (Section 49) means a method that cannot do
    anything real in this environment (no live credentials) must say so through its
    real return value (e.g. a ConnectionValidationOutcome with success=False and a
    real ProviderError), never through a fabricated success.

    `discover_assets`/`discover_relationships` were originally a separate
    `SupportsDiscovery` Protocol (sub-phase 1), reasoned as "not every real
    capability needs a real adapter to support discovery" - folded into this ABC
    directly in sub-phase 5 once all four real adapters (Sections 8-11) turned
    out to implement both anyway, and `gds_api.cloud.assets`'s real persistence
    layer needs `get_adapter()`'s return type to statically guarantee both
    methods exist, not just duck-type them. Both are async generators, not a
    materialized list, so a real adapter can stream results for a large scope
    rather than buffering an entire account's inventory in memory before the
    caller sees anything (Section 41's own performance requirement at
    10,000-100,000+ assets)."""

    provider_id: str

    @abstractmethod
    async def validate_connection(
        self, profile: CloudConnectionProfile
    ) -> ConnectionValidationOutcome: ...

    @abstractmethod
    async def identify_scope(self, profile: CloudConnectionProfile) -> ScopeIdentity: ...

    @abstractmethod
    async def enumerate_child_environments(
        self, profile: CloudConnectionProfile
    ) -> list[ChildEnvironmentRef]: ...

    @abstractmethod
    async def list_regions_or_locations(self, profile: CloudConnectionProfile) -> list[str]: ...

    @abstractmethod
    def classify_provider_error(self, exc: Exception) -> ProviderError: ...

    @abstractmethod
    def capability_matrix(self) -> CapabilityMatrix: ...

    @abstractmethod
    def discover_assets(
        self, profile: CloudConnectionProfile, scope_native_id: str
    ) -> AsyncIterator[NormalizedCloudAsset]: ...

    @abstractmethod
    def discover_relationships(
        self, profile: CloudConnectionProfile, scope_native_id: str
    ) -> AsyncIterator[NormalizedCloudRelationship]: ...


# Empty until a real adapter registers itself (see gds_api/cloud/adapters/ - all
# four declared providers register a real instance at import time, triggered by
# gds_api/cloud/__init__.py). A provider's absence here is the real, honest
# reason gds_api.cloud.connections' validation path returns "no adapter
# available" rather than attempting a call.
ADAPTER_REGISTRY: dict[str, ProviderAdapter] = {}


def get_adapter(provider_id: str) -> ProviderAdapter | None:
    return ADAPTER_REGISTRY.get(provider_id)


def register_adapter(adapter: ProviderAdapter) -> None:
    ADAPTER_REGISTRY[adapter.provider_id] = adapter
