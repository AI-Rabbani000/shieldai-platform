"""EDP-009 Part 1, Section 9: the real Azure foundation adapter.

Unlike AWS (Section 8's own mandatory 25-category list), Section 9 explicitly
permits a bounded scope when live credentials are unavailable: "Implement and
test the adapter contract... mark Azure as 'foundation only' or 'unverified'."
No live Azure credentials exist anywhere in this deployment environment (same
Phase 22 pre-build audit finding as AWS/GCP/Kubernetes), so this adapter
implements the full `ProviderAdapter` contract plus a real, honestly-bounded
discovery scope (7 of the 19 categories `CLOUD_PROVIDER_REGISTRY["azure"]`
declares) rather than repeating AWS's full-category depth against SDKs and API
shapes that can never be live-verified here either. See
`docs/guides/azure-adapter.md` for the exact coverage table and the disclosed
gap for every deferred category.

Every Azure SDK call here is real and read-only (`list`/`get` only - the same
Section 8 discipline Section 9 inherits). The Azure SDK for Python is also
synchronous (like boto3) - every call is wrapped in `asyncio.to_thread`,
matching this codebase's established convention.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterable, Iterator
from typing import TYPE_CHECKING, Any

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
from azure.identity import DefaultAzureCredential
from azure.mgmt.subscription import SubscriptionClient

from gds_api.cloud.adapter import (
    CapabilityMatrix,
    ChildEnvironmentRef,
    ConnectionValidationOutcome,
    ProviderAdapter,
    ProviderError,
    ProviderErrorCategory,
    ScopeIdentity,
    register_adapter,
)
from gds_api.cloud.providers import get_provider
from gds_api.cloud.schemas import NormalizedCloudAsset, NormalizedCloudRelationship

if TYPE_CHECKING:
    from gds_api.models import CloudConnectionProfile

# The 7 categories this sub-phase actually implements, out of the 19 the
# provider registry declares - see the module docstring and
# docs/guides/azure-adapter.md for why this is a real, disclosed bound, not a
# fabricated "supports everything" claim.
_IMPLEMENTED_CATEGORIES = (
    "subscription",
    "resource_group",
    "virtual_machine",
    "virtual_network",
    "subnet",
    "storage_account",
    "key_vault_metadata",
)

_ERROR_CODE_CATEGORY: dict[str, ProviderErrorCategory] = {
    "AuthorizationFailed": ProviderErrorCategory.PERMISSION_DENIED,
    "InvalidAuthenticationTokenTenant": ProviderErrorCategory.AUTHENTICATION_FAILED,
    "ExpiredAuthenticationToken": ProviderErrorCategory.AUTHENTICATION_FAILED,
    "InvalidAuthenticationToken": ProviderErrorCategory.AUTHENTICATION_FAILED,
    "TooManyRequests": ProviderErrorCategory.RATE_LIMITED,
    "SubscriptionNotFound": ProviderErrorCategory.SCOPE_NOT_FOUND,
    "ResourceGroupNotFound": ProviderErrorCategory.SCOPE_NOT_FOUND,
    "ResourceNotFound": ProviderErrorCategory.SCOPE_NOT_FOUND,
}


def _classify(exc: Exception) -> ProviderError:
    if isinstance(exc, ClientAuthenticationError):
        return ProviderError(
            category=ProviderErrorCategory.AUTHENTICATION_FAILED,
            sanitized_message="Azure: no usable credentials for this connection profile.",
            retryable=False,
        )
    if isinstance(exc, HttpResponseError):
        code = str(getattr(exc.error, "code", "Unknown")) if exc.error else "Unknown"
        message = str(getattr(exc.error, "message", str(exc))) if exc.error else str(exc)
        status = exc.status_code
        category = _ERROR_CODE_CATEGORY.get(code)
        if category is None:
            if status == 401:
                category = ProviderErrorCategory.AUTHENTICATION_FAILED
            elif status == 403:
                category = ProviderErrorCategory.PERMISSION_DENIED
            elif status == 404:
                category = ProviderErrorCategory.SCOPE_NOT_FOUND
            elif status == 429:
                category = ProviderErrorCategory.RATE_LIMITED
            elif status is not None and status >= 500:
                category = ProviderErrorCategory.SERVICE_UNAVAILABLE
            else:
                category = ProviderErrorCategory.UNKNOWN
        retryable = category in (
            ProviderErrorCategory.RATE_LIMITED,
            ProviderErrorCategory.SERVICE_UNAVAILABLE,
            ProviderErrorCategory.TIMEOUT,
            ProviderErrorCategory.NETWORK_ERROR,
        )
        return ProviderError(
            category=category,
            sanitized_message=f"Azure {code}: {message}"[:500],
            retryable=retryable,
        )
    return ProviderError(
        category=ProviderErrorCategory.UNKNOWN,
        sanitized_message=f"Unexpected error calling Azure: {exc}"[:500],
        retryable=False,
    )


def _build_credential(profile: CloudConnectionProfile) -> DefaultAzureCredential:
    """No secret value is ever resolved from `credential_reference` (it is always
    an opaque pointer - see `CloudConnectionProfile`'s own docstring), so a real
    `ClientSecretCredential` cannot honestly be constructed from what this platform
    stores. `DefaultAzureCredential` is the real, honest equivalent of AWS's
    default-credential-chain fallback: a real credential object that genuinely,
    correctly fails the first time a token is actually requested in an environment
    with no managed identity, CLI login, or environment-variable credentials -
    which this deployment environment has none of (Phase 22 pre-build audit)."""
    return DefaultAzureCredential()


def _next_page(iterator: Iterator[Any]) -> Any:
    _SENTINEL = object()
    result = next(iterator, _SENTINEL)
    return None if result is _SENTINEL else result


async def _stream_paged(paged: Iterable[Any]) -> AsyncIterator[Any]:
    """Azure SDK `ItemPaged` results are already a lazy, page-fetching iterator
    (the SDK's own equivalent of a boto3 paginator) - each `next()` call may
    trigger a real HTTP call, so each is wrapped in its own `asyncio.to_thread`
    call for real page-at-a-time streaming, matching the AWS adapter's own
    `_paginate` pattern."""
    iterator = iter(paged)
    while True:
        item = await asyncio.to_thread(_next_page, iterator)
        if item is None:
            return
        yield item


class AzureProviderAdapter(ProviderAdapter):
    provider_id = "azure"

    async def validate_connection(
        self, profile: CloudConnectionProfile
    ) -> ConnectionValidationOutcome:
        import time

        start = time.perf_counter()
        try:
            credential = _build_credential(profile)
            sub_client = SubscriptionClient(credential)
            subscriptions = [sub async for sub in _stream_paged(sub_client.subscriptions.list())]
        except Exception as exc:  # noqa: BLE001 - classified below, never re-raised raw
            error = _classify(exc)
            latency_ms = (time.perf_counter() - start) * 1000
            return ConnectionValidationOutcome(
                success=False,
                provider_identity=None,
                scope_identity=None,
                capability_availability={},
                latency_ms=round(latency_ms, 1),
                error=error,
            )
        latency_ms = (time.perf_counter() - start) * 1000
        first = subscriptions[0] if subscriptions else None
        scope = (
            ScopeIdentity(
                native_id=str(first.subscription_id),
                display_name=str(first.display_name),
                environment_type="account",
            )
            if first is not None
            else None
        )
        return ConnectionValidationOutcome(
            success=True,
            provider_identity=str(first.subscription_id) if first else None,
            scope_identity=scope,
            capability_availability={"subscriptions.list": True},
            latency_ms=round(latency_ms, 1),
        )

    async def identify_scope(self, profile: CloudConnectionProfile) -> ScopeIdentity:
        credential = _build_credential(profile)
        sub_client = SubscriptionClient(credential)
        try:
            subscriptions = [sub async for sub in _stream_paged(sub_client.subscriptions.list())]
        except Exception as exc:  # noqa: BLE001
            error = _classify(exc)
            raise RuntimeError(error.sanitized_message) from exc
        if not subscriptions:
            raise RuntimeError("Azure: no subscriptions visible to this connection profile.")
        first = subscriptions[0]
        return ScopeIdentity(
            native_id=str(first.subscription_id),
            display_name=str(first.display_name),
            environment_type="account",
        )

    async def enumerate_child_environments(
        self, profile: CloudConnectionProfile
    ) -> list[ChildEnvironmentRef]:
        credential = _build_credential(profile)
        sub_client = SubscriptionClient(credential)
        refs: list[ChildEnvironmentRef] = []
        try:
            async for sub in _stream_paged(sub_client.subscriptions.list()):
                refs.append(
                    ChildEnvironmentRef(
                        native_id=str(sub.subscription_id),
                        display_name=str(sub.display_name),
                        environment_type="account",
                        parent_native_id=str(sub.tenant_id) if sub.tenant_id else None,
                    )
                )
        except Exception as exc:  # noqa: BLE001
            error = _classify(exc)
            raise RuntimeError(error.sanitized_message) from exc
        return refs

    async def list_regions_or_locations(self, profile: CloudConnectionProfile) -> list[str]:
        credential = _build_credential(profile)
        sub_client = SubscriptionClient(credential)
        try:
            subscriptions = [sub async for sub in _stream_paged(sub_client.subscriptions.list())]
            if not subscriptions:
                return []
            locations = [
                loc
                async for loc in _stream_paged(
                    sub_client.subscriptions.list_locations(subscriptions[0].subscription_id)
                )
            ]
        except Exception as exc:  # noqa: BLE001
            error = _classify(exc)
            raise RuntimeError(error.sanitized_message) from exc
        return sorted({str(loc.name) for loc in locations})

    def classify_provider_error(self, exc: Exception) -> ProviderError:
        return _classify(exc)

    def capability_matrix(self) -> CapabilityMatrix:
        provider_def = get_provider("azure")
        declared = provider_def.supported_resource_categories if provider_def else ()
        return CapabilityMatrix(
            provider_id="azure",
            can_validate_connection=True,
            can_enumerate_child_environments=True,
            can_list_regions=True,
            can_discover_assets=True,
            can_discover_relationships=True,
            # Honestly narrower than the registry's full declared list (Section
            # 49's own rule - never claim a capability that isn't real) - see
            # docs/guides/azure-adapter.md for the full disclosed gap.
            supported_resource_categories=tuple(
                c for c in declared if c in _IMPLEMENTED_CATEGORIES
            ),
        )

    async def discover_assets(
        self, profile: CloudConnectionProfile, scope_native_id: str
    ) -> AsyncIterator[NormalizedCloudAsset]:
        from gds_api.cloud.adapters.azure_discovery import discover_assets as _discover

        async for asset in _discover(profile, scope_native_id):
            yield asset

    async def discover_relationships(
        self, profile: CloudConnectionProfile, scope_native_id: str
    ) -> AsyncIterator[NormalizedCloudRelationship]:
        from gds_api.cloud.adapters.azure_discovery import discover_relationships as _discover

        async for relationship in _discover(profile, scope_native_id):
            yield relationship


register_adapter(AzureProviderAdapter())
