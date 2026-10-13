"""EDP-009 Part 1, Section 10: the real, per-category GCP discovery
implementations `gds_api.cloud.adapters.gcp.GCPProviderAdapter` composes.
Bounded to the 6 categories `_IMPLEMENTED_CATEGORIES` (gcp.py) declares - a
real, disclosed subset of the 19 the provider registry lists for GCP, per
Section 10's own explicit permission to keep this bounded when no live
credentials exist to verify a fuller scope against.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterable, Iterator
from datetime import datetime
from typing import TYPE_CHECKING, Any

import google.cloud.storage as storage
from google.cloud import compute_v1, resourcemanager_v3

from gds_api.cloud.adapters.gcp import _build_credentials, _classify
from gds_api.cloud.schemas import NormalizedCloudAsset, NormalizedCloudRelationship
from gds_api.logging_config import get_logger

if TYPE_CHECKING:
    from gds_api.models import CloudConnectionProfile

_logger = get_logger("gds_api.cloud.adapters.gcp")


def _to_datetime(value: Any) -> datetime | None:
    """`resourcemanager_v3.Project.create_time` is a protobuf `Timestamp`, not a
    Python `datetime` - real conversion via the message's own `ToDatetime()`,
    isolated here once rather than at every real call site."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    to_datetime = getattr(value, "ToDatetime", None)
    if to_datetime is None:
        return None
    result: datetime = to_datetime()
    return result


def _name_from_url(url: str | None) -> str | None:
    if not url:
        return None
    return url.rstrip("/").rsplit("/", 1)[-1]


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


async def _safe_assets(
    agen: AsyncIterator[NormalizedCloudAsset], category: str
) -> AsyncIterator[NormalizedCloudAsset]:
    try:
        async for item in agen:
            yield item
    except Exception as exc:  # noqa: BLE001 - contained per-category, never aborts the stream
        error = _classify(exc)
        _logger.warning(
            "cloud.gcp_discovery_category_failed",
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
            "cloud.gcp_discovery_relationship_category_failed",
            category=category,
            error_category=error.category.value,
            message=error.sanitized_message,
        )


async def _discover_project(
    credentials: Any, project_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    client = resourcemanager_v3.ProjectsClient(credentials=credentials)
    project = await asyncio.to_thread(client.get_project, name=f"projects/{project_id}")
    yield NormalizedCloudAsset(
        provider="gcp",
        native_id=str(project.project_id),
        native_resource_type="cloudresourcemanager.Project",
        normalized_category="project",
        name=str(project.display_name or project.project_id),
        parent_native_id=str(project.parent) if project.parent else None,
        account_or_subscription_or_project=project.project_id,
        lifecycle_state=project.state.name if project.state else None,
        created_at_provider=_to_datetime(project.create_time),
        tags=dict(project.labels) if project.labels else {},
    )


async def _discover_compute_instances(
    credentials: Any, project_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    client = compute_v1.InstancesClient(credentials=credentials)
    async for zone_key, scoped_list in _stream_paged(client.aggregated_list(project=project_id)):
        for instance in scoped_list.instances or []:
            zone = _name_from_url(instance.zone) or _name_from_url(zone_key)
            yield NormalizedCloudAsset(
                provider="gcp",
                native_id=str(instance.id),
                native_resource_type="compute.Instance",
                normalized_category="compute_instance",
                name=str(instance.name),
                region_or_location=zone[:-2] if zone and zone[-2] == "-" else zone,
                availability_zone=zone,
                account_or_subscription_or_project=project_id,
                lifecycle_state=instance.status,
                created_at_provider=None,
                tags=dict(instance.labels) if instance.labels else {},
                internet_exposure_known=any(
                    bool(iface.access_configs)
                    for iface in (instance.network_interfaces or [])
                ),
                raw_metadata={"self_link": instance.self_link} if instance.self_link else {},
            )


async def _discover_networks(
    credentials: Any, project_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    client = compute_v1.NetworksClient(credentials=credentials)
    async for network in _stream_paged(client.list(project=project_id)):
        yield NormalizedCloudAsset(
            provider="gcp",
            native_id=str(network.id),
            native_resource_type="compute.Network",
            normalized_category="network",
            name=str(network.name),
            account_or_subscription_or_project=project_id,
            raw_metadata={"self_link": network.self_link} if network.self_link else {},
        )


async def _discover_subnetworks(
    credentials: Any, project_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    client = compute_v1.SubnetworksClient(credentials=credentials)
    async for region_key, scoped_list in _stream_paged(
        client.aggregated_list(project=project_id)
    ):
        for subnetwork in scoped_list.subnetworks or []:
            yield NormalizedCloudAsset(
                provider="gcp",
                native_id=str(subnetwork.id),
                native_resource_type="compute.Subnetwork",
                normalized_category="subnetwork",
                name=str(subnetwork.name),
                region_or_location=_name_from_url(subnetwork.region) or _name_from_url(region_key),
                parent_native_id=_name_from_url(subnetwork.network),
                account_or_subscription_or_project=project_id,
                internet_exposure_known=bool(subnetwork.enable_flow_logs),
                raw_metadata={"self_link": subnetwork.self_link} if subnetwork.self_link else {},
            )


async def _discover_firewall_rules(
    credentials: Any, project_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    client = compute_v1.FirewallsClient(credentials=credentials)
    async for rule in _stream_paged(client.list(project=project_id)):
        yield NormalizedCloudAsset(
            provider="gcp",
            native_id=str(rule.id),
            native_resource_type="compute.Firewall",
            normalized_category="firewall_rule",
            name=str(rule.name),
            parent_native_id=_name_from_url(rule.network),
            account_or_subscription_or_project=project_id,
            lifecycle_state="ENABLED" if not rule.disabled else "DISABLED",
            internet_exposure_known=bool(
                rule.source_ranges and "0.0.0.0/0" in list(rule.source_ranges)
            ),
            raw_metadata={"self_link": rule.self_link} if rule.self_link else {},
        )


async def _discover_storage_buckets(
    credentials: Any, project_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    client = storage.Client(project=project_id, credentials=credentials)
    buckets = await asyncio.to_thread(lambda: list(client.list_buckets()))
    for bucket in buckets:
        yield NormalizedCloudAsset(
            provider="gcp",
            native_id=str(bucket.name),
            native_resource_type="storage.Bucket",
            normalized_category="cloud_storage_bucket",
            name=str(bucket.name),
            region_or_location=bucket.location,
            account_or_subscription_or_project=project_id,
            created_at_provider=bucket.time_created,
            tags=dict(bucket.labels) if bucket.labels else {},
            managed_service=True,
        )


async def discover_assets(
    profile: CloudConnectionProfile, scope_native_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    credentials = await asyncio.to_thread(_build_credentials, profile)
    project_id = scope_native_id

    async for asset in _safe_assets(_discover_project(credentials, project_id), "project"):
        yield asset
    async for asset in _safe_assets(
        _discover_compute_instances(credentials, project_id), "compute_instance"
    ):
        yield asset
    async for asset in _safe_assets(_discover_networks(credentials, project_id), "network"):
        yield asset
    async for asset in _safe_assets(
        _discover_subnetworks(credentials, project_id), "subnetwork"
    ):
        yield asset
    async for asset in _safe_assets(
        _discover_firewall_rules(credentials, project_id), "firewall_rule"
    ):
        yield asset
    async for asset in _safe_assets(
        _discover_storage_buckets(credentials, project_id), "cloud_storage_bucket"
    ):
        yield asset


async def _relationships(
    credentials: Any, project_id: str
) -> AsyncIterator[NormalizedCloudRelationship]:
    subnet_client = compute_v1.SubnetworksClient(credentials=credentials)
    async for _region_key, scoped_list in _stream_paged(
        subnet_client.aggregated_list(project=project_id)
    ):
        for subnetwork in scoped_list.subnetworks or []:
            network_name = _name_from_url(subnetwork.network)
            if network_name:
                yield NormalizedCloudRelationship(
                    source_native_id=str(subnetwork.id),
                    target_native_id=network_name,
                    relationship_type="BELONGS_TO",
                    is_direct=True,
                )

    instance_client = compute_v1.InstancesClient(credentials=credentials)
    async for _zone_key, scoped_list in _stream_paged(
        instance_client.aggregated_list(project=project_id)
    ):
        for instance in scoped_list.instances or []:
            for iface in instance.network_interfaces or []:
                network_name = _name_from_url(iface.network)
                if network_name:
                    yield NormalizedCloudRelationship(
                        source_native_id=str(instance.id),
                        target_native_id=network_name,
                        relationship_type="CONNECTED_TO",
                        is_direct=True,
                    )
                subnet_name = _name_from_url(iface.subnetwork)
                if subnet_name:
                    yield NormalizedCloudRelationship(
                        source_native_id=str(instance.id),
                        target_native_id=subnet_name,
                        relationship_type="ATTACHED_TO",
                        is_direct=True,
                    )


async def discover_relationships(
    profile: CloudConnectionProfile, scope_native_id: str
) -> AsyncIterator[NormalizedCloudRelationship]:
    credentials = await asyncio.to_thread(_build_credentials, profile)
    async for rel in _safe_relationships(
        _relationships(credentials, scope_native_id), "gcp_relationships"
    ):
        yield rel
