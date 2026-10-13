"""EDP-009 Part 1, Section 10: the real GCP foundation adapter.

Same real, honestly-bounded scope discipline as the Azure adapter (Section 9):
no live GCP credentials exist anywhere in this deployment environment (Phase
22 pre-build audit), and Section 10 explicitly permits a bounded scope in that
case ("Implement provider contracts and fixtures... mark support honestly").
This adapter implements the full `ProviderAdapter` contract plus 6 of the 19
categories `CLOUD_PROVIDER_REGISTRY["gcp"]` declares - see
`docs/guides/gcp-adapter.md` for the coverage table and disclosed gap.

The `google-cloud-*` client libraries used here are synchronous (like boto3
and the Azure SDK) - every call is wrapped in `asyncio.to_thread`, matching
this codebase's established convention.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Iterable, Iterator
from typing import TYPE_CHECKING, Any

import google.auth
from google.api_core import exceptions as gexc
from google.auth.exceptions import DefaultCredentialsError, GoogleAuthError
from google.cloud import compute_v1, resourcemanager_v3

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

_IMPLEMENTED_CATEGORIES = (
    "project",
    "compute_instance",
    "network",
    "subnetwork",
    "firewall_rule",
    "cloud_storage_bucket",
)


def _classify(exc: Exception) -> ProviderError:
    if isinstance(exc, (DefaultCredentialsError, GoogleAuthError)):
        return ProviderError(
            category=ProviderErrorCategory.AUTHENTICATION_FAILED,
            sanitized_message="GCP: no usable credentials for this connection profile.",
            retryable=False,
        )
    if isinstance(exc, gexc.GoogleAPICallError):
        message = str(exc.message or str(exc))
        if isinstance(exc, gexc.PermissionDenied):
            category = ProviderErrorCategory.PERMISSION_DENIED
        elif isinstance(exc, gexc.Unauthenticated):
            category = ProviderErrorCategory.AUTHENTICATION_FAILED
        elif isinstance(exc, gexc.NotFound):
            category = ProviderErrorCategory.SCOPE_NOT_FOUND
        elif isinstance(exc, (gexc.TooManyRequests, gexc.ResourceExhausted)):
            category = ProviderErrorCategory.RATE_LIMITED
        elif isinstance(exc, gexc.ServiceUnavailable):
            category = ProviderErrorCategory.SERVICE_UNAVAILABLE
        elif isinstance(exc, gexc.DeadlineExceeded):
            category = ProviderErrorCategory.TIMEOUT
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
            sanitized_message=f"GCP {type(exc).__name__}: {message}"[:500],
            retryable=retryable,
        )
    return ProviderError(
        category=ProviderErrorCategory.UNKNOWN,
        sanitized_message=f"Unexpected error calling GCP: {exc}"[:500],
        retryable=False,
    )


def _build_credentials(profile: CloudConnectionProfile) -> Any:
    """No secret value is ever resolved from `credential_reference` (always an
    opaque pointer), so a real service-account-key credential cannot honestly be
    constructed from what this platform stores. `google.auth.default()` is the
    real, honest equivalent of AWS/Azure's own default-credential-chain fallback -
    a real call that genuinely fails in this environment (no GOOGLE_APPLICATION_
    CREDENTIALS, no gcloud ADC file, no metadata server - Phase 22 pre-build
    audit)."""
    credentials, _project = google.auth.default()
    return credentials


def _next_page(iterator: Iterator[Any]) -> Any:
    _SENTINEL = object()
    result = next(iterator, _SENTINEL)
    return None if result is _SENTINEL else result


async def _stream_paged(paged: Iterable[Any]) -> AsyncIterator[Any]:
    iterator = iter(paged)
    while True:
        item = await asyncio.to_thread(_next_page, iterator)
        if item is None:
            return
        yield item


class GCPProviderAdapter(ProviderAdapter):
    provider_id = "gcp"

    async def validate_connection(
        self, profile: CloudConnectionProfile
    ) -> ConnectionValidationOutcome:
        start = time.perf_counter()
        try:
            credentials = await asyncio.to_thread(_build_credentials, profile)
            client = resourcemanager_v3.ProjectsClient(credentials=credentials)
            projects = [
                p
                async for p in _stream_paged(client.search_projects())
            ]
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
        first = projects[0] if projects else None
        scope = (
            ScopeIdentity(
                native_id=str(first.project_id),
                display_name=str(first.display_name),
                environment_type="project",
            )
            if first is not None
            else None
        )
        return ConnectionValidationOutcome(
            success=True,
            provider_identity=str(first.project_id) if first else None,
            scope_identity=scope,
            capability_availability={"projects.search": True},
            latency_ms=round(latency_ms, 1),
        )

    async def identify_scope(self, profile: CloudConnectionProfile) -> ScopeIdentity:
        credentials = await asyncio.to_thread(_build_credentials, profile)
        client = resourcemanager_v3.ProjectsClient(credentials=credentials)
        try:
            projects = [p async for p in _stream_paged(client.search_projects())]
        except Exception as exc:  # noqa: BLE001
            error = _classify(exc)
            raise RuntimeError(error.sanitized_message) from exc
        if not projects:
            raise RuntimeError("GCP: no projects visible to this connection profile.")
        first = projects[0]
        return ScopeIdentity(
            native_id=str(first.project_id),
            display_name=str(first.display_name),
            environment_type="project",
        )

    async def enumerate_child_environments(
        self, profile: CloudConnectionProfile
    ) -> list[ChildEnvironmentRef]:
        credentials = await asyncio.to_thread(_build_credentials, profile)
        client = resourcemanager_v3.ProjectsClient(credentials=credentials)
        refs: list[ChildEnvironmentRef] = []
        try:
            async for project in _stream_paged(client.search_projects()):
                refs.append(
                    ChildEnvironmentRef(
                        native_id=str(project.project_id),
                        display_name=str(project.display_name),
                        environment_type="project",
                        parent_native_id=str(project.parent) if project.parent else None,
                    )
                )
        except Exception as exc:  # noqa: BLE001
            error = _classify(exc)
            raise RuntimeError(error.sanitized_message) from exc
        return refs

    async def list_regions_or_locations(self, profile: CloudConnectionProfile) -> list[str]:
        credentials = await asyncio.to_thread(_build_credentials, profile)
        client = resourcemanager_v3.ProjectsClient(credentials=credentials)
        try:
            projects = [p async for p in _stream_paged(client.search_projects())]
            if not projects:
                return []
            regions_client = compute_v1.RegionsClient(credentials=credentials)
            regions = [
                r
                async for r in _stream_paged(regions_client.list(project=projects[0].project_id))
            ]
        except Exception as exc:  # noqa: BLE001
            error = _classify(exc)
            raise RuntimeError(error.sanitized_message) from exc
        return sorted(str(r.name) for r in regions)

    def classify_provider_error(self, exc: Exception) -> ProviderError:
        return _classify(exc)

    def capability_matrix(self) -> CapabilityMatrix:
        provider_def = get_provider("gcp")
        declared = provider_def.supported_resource_categories if provider_def else ()
        return CapabilityMatrix(
            provider_id="gcp",
            can_validate_connection=True,
            can_enumerate_child_environments=True,
            can_list_regions=True,
            can_discover_assets=True,
            can_discover_relationships=True,
            supported_resource_categories=tuple(
                c for c in declared if c in _IMPLEMENTED_CATEGORIES
            ),
        )

    async def discover_assets(
        self, profile: CloudConnectionProfile, scope_native_id: str
    ) -> AsyncIterator[NormalizedCloudAsset]:
        from gds_api.cloud.adapters.gcp_discovery import discover_assets as _discover

        async for asset in _discover(profile, scope_native_id):
            yield asset

    async def discover_relationships(
        self, profile: CloudConnectionProfile, scope_native_id: str
    ) -> AsyncIterator[NormalizedCloudRelationship]:
        from gds_api.cloud.adapters.gcp_discovery import discover_relationships as _discover

        async for relationship in _discover(profile, scope_native_id):
            yield relationship


register_adapter(GCPProviderAdapter())
