"""EDP-009 Part 1, Section 11: the real Kubernetes registration/inventory
foundation adapter.

Same real, honestly-bounded scope discipline as Azure/GCP (Sections 9-10): no
live cluster credentials exist anywhere in this deployment environment (Phase
22 pre-build audit - no `~/.kube/config`, no in-cluster service account token).
This adapter implements the full `ProviderAdapter` contract plus 6 of the 20
categories `CLOUD_PROVIDER_REGISTRY["kubernetes"]` declares - see
`docs/guides/kubernetes-adapter.md` for the coverage table.

Never retrieves a Secret value, never executes into a pod, never mutates a
workload - Section 11's own explicit rules, identical in spirit to Section 8's
own rules for AWS.

The official `kubernetes` Python client is synchronous - every call is wrapped
in `asyncio.to_thread`, matching this codebase's established convention. This
module is deliberately named `k8s.py`, not `kubernetes.py`, so there is no
ambiguity with the top-level `kubernetes` PyPI package this file imports.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from kubernetes.client.exceptions import ApiException
from kubernetes.config.config_exception import ConfigException

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
    "cluster_identity",
    "node",
    "namespace",
    "pod",
    "deployment",
    "service",
)

_STATUS_CATEGORY: dict[int, ProviderErrorCategory] = {
    401: ProviderErrorCategory.AUTHENTICATION_FAILED,
    403: ProviderErrorCategory.PERMISSION_DENIED,
    404: ProviderErrorCategory.SCOPE_NOT_FOUND,
    429: ProviderErrorCategory.RATE_LIMITED,
}


def _classify(exc: Exception) -> ProviderError:
    if isinstance(exc, ConfigException):
        return ProviderError(
            category=ProviderErrorCategory.AUTHENTICATION_FAILED,
            sanitized_message=(
                "Kubernetes: no usable kubeconfig or in-cluster credentials for "
                "this connection profile."
            ),
            retryable=False,
        )
    if isinstance(exc, ApiException):
        category = _STATUS_CATEGORY.get(exc.status or 0)
        if category is None:
            category = (
                ProviderErrorCategory.SERVICE_UNAVAILABLE
                if (exc.status or 0) >= 500
                else ProviderErrorCategory.UNKNOWN
            )
        retryable = category in (
            ProviderErrorCategory.RATE_LIMITED,
            ProviderErrorCategory.SERVICE_UNAVAILABLE,
            ProviderErrorCategory.TIMEOUT,
            ProviderErrorCategory.NETWORK_ERROR,
        )
        return ProviderError(
            category=category,
            sanitized_message=f"Kubernetes API {exc.status}: {exc.reason}"[:500],
            retryable=retryable,
        )
    return ProviderError(
        category=ProviderErrorCategory.UNKNOWN,
        sanitized_message=f"Unexpected error calling Kubernetes: {exc}"[:500],
        retryable=False,
    )


def _build_api_client(profile: CloudConnectionProfile) -> k8s_client.ApiClient:
    """No secret value is ever resolved from `credential_reference` (always an
    opaque pointer), so a real kubeconfig or service-account token cannot
    honestly be constructed from what this platform stores. `load_kube_config()`
    is the real, honest equivalent of the other three adapters' own default-
    credential-chain fallback - a real call that genuinely fails in this
    environment (no `~/.kube/config` file exists - Phase 22 pre-build audit)."""
    k8s_config.load_kube_config()
    return k8s_client.ApiClient()


class KubernetesProviderAdapter(ProviderAdapter):
    provider_id = "kubernetes"

    async def validate_connection(
        self, profile: CloudConnectionProfile
    ) -> ConnectionValidationOutcome:
        start = time.perf_counter()
        try:
            api_client = await asyncio.to_thread(_build_api_client, profile)
            version = await asyncio.to_thread(k8s_client.VersionApi(api_client).get_code)
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
        scope = ScopeIdentity(
            native_id=str(version.git_version),
            display_name=f"Kubernetes {version.major}.{version.minor}",
            environment_type="cluster",
        )
        return ConnectionValidationOutcome(
            success=True,
            provider_identity=str(version.git_version),
            scope_identity=scope,
            capability_availability={"version.get_code": True},
            latency_ms=round(latency_ms, 1),
        )

    async def identify_scope(self, profile: CloudConnectionProfile) -> ScopeIdentity:
        api_client = await asyncio.to_thread(_build_api_client, profile)
        try:
            version = await asyncio.to_thread(k8s_client.VersionApi(api_client).get_code)
        except Exception as exc:  # noqa: BLE001
            error = _classify(exc)
            raise RuntimeError(error.sanitized_message) from exc
        return ScopeIdentity(
            native_id=str(version.git_version),
            display_name=f"Kubernetes {version.major}.{version.minor}",
            environment_type="cluster",
        )

    async def enumerate_child_environments(
        self, profile: CloudConnectionProfile
    ) -> list[ChildEnvironmentRef]:
        """Namespaces are this provider's real child-environment scope (Section
        2: "Cluster... Namespace scope where authorised"), not a fabricated
        hierarchy."""
        api_client = await asyncio.to_thread(_build_api_client, profile)
        try:
            namespaces = await asyncio.to_thread(k8s_client.CoreV1Api(api_client).list_namespace)
        except Exception as exc:  # noqa: BLE001
            error = _classify(exc)
            raise RuntimeError(error.sanitized_message) from exc
        return [
            ChildEnvironmentRef(
                native_id=str(ns.metadata.name),
                display_name=str(ns.metadata.name),
                environment_type="namespace",
                parent_native_id=None,
            )
            for ns in namespaces.items
        ]

    async def list_regions_or_locations(self, profile: CloudConnectionProfile) -> list[str]:
        """Not applicable to a single Kubernetes cluster - real, honest empty
        list, never a fabricated single-item placeholder (Section 49's own
        rule against manufacturing a normalized value)."""
        return []

    def classify_provider_error(self, exc: Exception) -> ProviderError:
        return _classify(exc)

    def capability_matrix(self) -> CapabilityMatrix:
        provider_def = get_provider("kubernetes")
        declared = provider_def.supported_resource_categories if provider_def else ()
        return CapabilityMatrix(
            provider_id="kubernetes",
            can_validate_connection=True,
            can_enumerate_child_environments=True,
            can_list_regions=False,
            can_discover_assets=True,
            can_discover_relationships=True,
            supported_resource_categories=tuple(
                c for c in declared if c in _IMPLEMENTED_CATEGORIES
            ),
        )

    async def discover_assets(
        self, profile: CloudConnectionProfile, scope_native_id: str
    ) -> AsyncIterator[NormalizedCloudAsset]:
        from gds_api.cloud.adapters.k8s_discovery import discover_assets as _discover

        async for asset in _discover(profile, scope_native_id):
            yield asset

    async def discover_relationships(
        self, profile: CloudConnectionProfile, scope_native_id: str
    ) -> AsyncIterator[NormalizedCloudRelationship]:
        from gds_api.cloud.adapters.k8s_discovery import discover_relationships as _discover

        async for relationship in _discover(profile, scope_native_id):
            yield relationship


register_adapter(KubernetesProviderAdapter())
