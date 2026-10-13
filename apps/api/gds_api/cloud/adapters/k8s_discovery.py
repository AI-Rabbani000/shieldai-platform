"""EDP-009 Part 1, Section 11: the real, per-category Kubernetes discovery
implementations `gds_api.cloud.adapters.k8s.KubernetesProviderAdapter` composes.
Bounded to the 6 categories `_IMPLEMENTED_CATEGORIES` (k8s.py) declares - a
real, disclosed subset of the 20 the provider registry lists for Kubernetes.

Never retrieves a Secret value (`configmap_metadata`/`secret_metadata` are
explicitly deferred, not attempted with a redacted read - the whole category is
out of scope this sub-phase, a more honest signal than a half-real read).
Never executes into a pod. Never mutates a workload.

Known, disclosed limitation: each category here is a single, unpaginated list
call (`CoreV1Api.list_node`, etc.), not a continuation-token loop - real for
any cluster within one API response page, but not verified against a cluster
large enough to need continuation tokens (no live cluster exists in this
environment to test that against). See docs/guides/kubernetes-adapter.md.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any

from kubernetes import client as k8s_client

from gds_api.cloud.adapters.k8s import _build_api_client, _classify
from gds_api.cloud.schemas import NormalizedCloudAsset, NormalizedCloudRelationship
from gds_api.logging_config import get_logger

if TYPE_CHECKING:
    from gds_api.models import CloudConnectionProfile

_logger = get_logger("gds_api.cloud.adapters.k8s")


async def _safe_assets(
    agen: AsyncIterator[NormalizedCloudAsset], category: str
) -> AsyncIterator[NormalizedCloudAsset]:
    try:
        async for item in agen:
            yield item
    except Exception as exc:  # noqa: BLE001 - contained per-category, never aborts the stream
        error = _classify(exc)
        _logger.warning(
            "cloud.k8s_discovery_category_failed",
            category=category,
            error_category=error.category.value,
            message=error.sanitized_message,
        )


async def _safe_relationships(
    agen: AsyncIterator[NormalizedCloudRelationship], category: str
) -> AsyncIterator[NormalizedCloudRelationship]:
    try:
        async for item in agen:
            yield item
    except Exception as exc:  # noqa: BLE001
        error = _classify(exc)
        _logger.warning(
            "cloud.k8s_discovery_relationship_category_failed",
            category=category,
            error_category=error.category.value,
            message=error.sanitized_message,
        )


async def _discover_cluster_identity(
    api_client: Any, cluster_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    version = await asyncio.to_thread(k8s_client.VersionApi(api_client).get_code)
    yield NormalizedCloudAsset(
        provider="kubernetes",
        native_id=cluster_id,
        native_resource_type="Cluster",
        normalized_category="cluster_identity",
        name=cluster_id,
        raw_metadata={"git_version": version.git_version, "platform": version.platform},
    )


async def _discover_nodes(api_client: Any, cluster_id: str) -> AsyncIterator[NormalizedCloudAsset]:
    result = await asyncio.to_thread(k8s_client.CoreV1Api(api_client).list_node)
    for node in result.items:
        conditions = {c.type: c.status for c in (node.status.conditions or [])}
        yield NormalizedCloudAsset(
            provider="kubernetes",
            native_id=str(node.metadata.uid),
            native_resource_type="v1.Node",
            normalized_category="node",
            name=str(node.metadata.name),
            parent_native_id=cluster_id,
            account_or_subscription_or_project=cluster_id,
            lifecycle_state="Ready" if conditions.get("Ready") == "True" else "NotReady",
            created_at_provider=node.metadata.creation_timestamp,
            tags=dict(node.metadata.labels) if node.metadata.labels else {},
            raw_metadata={"kubelet_version": node.status.node_info.kubelet_version}
            if node.status.node_info
            else {},
        )


async def _discover_namespaces(
    api_client: Any, cluster_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    result = await asyncio.to_thread(k8s_client.CoreV1Api(api_client).list_namespace)
    for ns in result.items:
        yield NormalizedCloudAsset(
            provider="kubernetes",
            native_id=str(ns.metadata.uid),
            native_resource_type="v1.Namespace",
            normalized_category="namespace",
            name=str(ns.metadata.name),
            parent_native_id=cluster_id,
            account_or_subscription_or_project=cluster_id,
            lifecycle_state=ns.status.phase if ns.status else None,
            created_at_provider=ns.metadata.creation_timestamp,
            tags=dict(ns.metadata.labels) if ns.metadata.labels else {},
        )


async def _discover_pods(api_client: Any, cluster_id: str) -> AsyncIterator[NormalizedCloudAsset]:
    result = await asyncio.to_thread(k8s_client.CoreV1Api(api_client).list_pod_for_all_namespaces)
    for pod in result.items:
        yield NormalizedCloudAsset(
            provider="kubernetes",
            native_id=str(pod.metadata.uid),
            native_resource_type="v1.Pod",
            normalized_category="pod",
            name=str(pod.metadata.name),
            parent_native_id=str(pod.metadata.namespace),
            account_or_subscription_or_project=cluster_id,
            lifecycle_state=pod.status.phase if pod.status else None,
            created_at_provider=pod.metadata.creation_timestamp,
            tags=dict(pod.metadata.labels) if pod.metadata.labels else {},
            internet_exposure_known=bool(pod.spec.host_network) if pod.spec else None,
        )


async def _discover_deployments(
    api_client: Any, cluster_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    result = await asyncio.to_thread(
        k8s_client.AppsV1Api(api_client).list_deployment_for_all_namespaces
    )
    for deployment in result.items:
        yield NormalizedCloudAsset(
            provider="kubernetes",
            native_id=str(deployment.metadata.uid),
            native_resource_type="apps/v1.Deployment",
            normalized_category="deployment",
            name=str(deployment.metadata.name),
            parent_native_id=str(deployment.metadata.namespace),
            account_or_subscription_or_project=cluster_id,
            created_at_provider=deployment.metadata.creation_timestamp,
            tags=dict(deployment.metadata.labels) if deployment.metadata.labels else {},
            raw_metadata={"replicas": deployment.spec.replicas} if deployment.spec else {},
        )


async def _discover_services(
    api_client: Any, cluster_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    result = await asyncio.to_thread(
        k8s_client.CoreV1Api(api_client).list_service_for_all_namespaces
    )
    for service in result.items:
        yield NormalizedCloudAsset(
            provider="kubernetes",
            native_id=str(service.metadata.uid),
            native_resource_type="v1.Service",
            normalized_category="service",
            name=str(service.metadata.name),
            parent_native_id=str(service.metadata.namespace),
            account_or_subscription_or_project=cluster_id,
            created_at_provider=service.metadata.creation_timestamp,
            tags=dict(service.metadata.labels) if service.metadata.labels else {},
            internet_exposure_known=(
                str(service.spec.type) == "LoadBalancer" if service.spec else None
            ),
        )


async def discover_assets(
    profile: CloudConnectionProfile, scope_native_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    api_client = await asyncio.to_thread(_build_api_client, profile)
    cluster_id = scope_native_id

    async for asset in _safe_assets(
        _discover_cluster_identity(api_client, cluster_id), "cluster_identity"
    ):
        yield asset
    async for asset in _safe_assets(_discover_nodes(api_client, cluster_id), "node"):
        yield asset
    async for asset in _safe_assets(_discover_namespaces(api_client, cluster_id), "namespace"):
        yield asset
    async for asset in _safe_assets(_discover_pods(api_client, cluster_id), "pod"):
        yield asset
    async for asset in _safe_assets(
        _discover_deployments(api_client, cluster_id), "deployment"
    ):
        yield asset
    async for asset in _safe_assets(_discover_services(api_client, cluster_id), "service"):
        yield asset


async def _relationships(
    api_client: Any, cluster_id: str
) -> AsyncIterator[NormalizedCloudRelationship]:
    pods = await asyncio.to_thread(k8s_client.CoreV1Api(api_client).list_pod_for_all_namespaces)
    for pod in pods.items:
        yield NormalizedCloudRelationship(
            source_native_id=str(pod.metadata.uid),
            target_native_id=str(pod.metadata.namespace),
            relationship_type="BELONGS_TO",
            is_direct=True,
        )
        if pod.spec and pod.spec.node_name:
            yield NormalizedCloudRelationship(
                source_native_id=str(pod.metadata.uid),
                target_native_id=str(pod.spec.node_name),
                relationship_type="RUNS_ON",
                is_direct=True,
            )

    deployments = await asyncio.to_thread(
        k8s_client.AppsV1Api(api_client).list_deployment_for_all_namespaces
    )
    for deployment in deployments.items:
        yield NormalizedCloudRelationship(
            source_native_id=str(deployment.metadata.uid),
            target_native_id=str(deployment.metadata.namespace),
            relationship_type="BELONGS_TO",
            is_direct=True,
        )

    services = await asyncio.to_thread(
        k8s_client.CoreV1Api(api_client).list_service_for_all_namespaces
    )
    for service in services.items:
        yield NormalizedCloudRelationship(
            source_native_id=str(service.metadata.uid),
            target_native_id=str(service.metadata.namespace),
            relationship_type="BELONGS_TO",
            is_direct=True,
        )


async def discover_relationships(
    profile: CloudConnectionProfile, scope_native_id: str
) -> AsyncIterator[NormalizedCloudRelationship]:
    api_client = await asyncio.to_thread(_build_api_client, profile)
    async for rel in _safe_relationships(
        _relationships(api_client, scope_native_id), "k8s_relationships"
    ):
        yield rel
