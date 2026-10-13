"""EDP-009 Part 1, Section 9: the real, per-category Azure discovery
implementations `gds_api.cloud.adapters.azure.AzureProviderAdapter` composes.
Bounded to the 7 categories `_IMPLEMENTED_CATEGORIES` (azure.py) declares - a
real, disclosed subset of the 19 the provider registry lists for Azure, per
Section 9's own explicit permission to keep this bounded when (as here) no
live credentials exist to verify a fuller scope against.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any

from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource.resources import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.subscription import SubscriptionClient

from gds_api.cloud.adapters.azure import _build_credential, _classify, _stream_paged
from gds_api.cloud.schemas import NormalizedCloudAsset, NormalizedCloudRelationship
from gds_api.logging_config import get_logger

if TYPE_CHECKING:
    from gds_api.models import CloudConnectionProfile

_logger = get_logger("gds_api.cloud.adapters.azure")


def _as_dict(model: Any) -> dict[str, object]:
    """Azure SDK model objects expose a real `.as_dict()` method, but it has no
    type stubs (`no-untyped-call` in a typed context) - isolated here once
    rather than an `# type: ignore` at every one of this module's real call
    sites."""
    as_dict = getattr(model, "as_dict", None)
    if as_dict is None:
        return {}
    result: dict[str, object] = as_dict()
    return result


def _resource_group_from_id(resource_id: str | None) -> str | None:
    if not resource_id:
        return None
    parts = resource_id.lower().split("/")
    if "resourcegroups" in parts:
        idx = parts.index("resourcegroups")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return None


async def _safe_assets(
    agen: AsyncIterator[NormalizedCloudAsset], category: str
) -> AsyncIterator[NormalizedCloudAsset]:
    try:
        async for item in agen:
            yield item
    except Exception as exc:  # noqa: BLE001 - contained per-category, never aborts the stream
        error = _classify(exc)
        _logger.warning(
            "cloud.azure_discovery_category_failed",
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
            "cloud.azure_discovery_relationship_category_failed",
            category=category,
            error_category=error.category.value,
            message=error.sanitized_message,
        )


async def _discover_subscription(
    credential: Any, subscription_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    sub_client = SubscriptionClient(credential)
    sub = await asyncio.to_thread(sub_client.subscriptions.get, subscription_id)
    yield NormalizedCloudAsset(
        provider="azure",
        native_id=str(sub.subscription_id),
        native_resource_type="Microsoft.Subscription",
        normalized_category="subscription",
        name=str(sub.display_name),
        lifecycle_state=str(sub.state) if sub.state else None,
        raw_metadata=_as_dict(sub),
    )


async def _discover_resource_groups(
    credential: Any, subscription_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    rg_client = ResourceManagementClient(credential, subscription_id)
    async for rg in _stream_paged(rg_client.resource_groups.list()):
        yield NormalizedCloudAsset(
            provider="azure",
            native_id=str(rg.id),
            native_resource_type="Microsoft.Resources/resourceGroups",
            normalized_category="resource_group",
            name=str(rg.name),
            region_or_location=rg.location,
            parent_native_id=subscription_id,
            account_or_subscription_or_project=subscription_id,
            lifecycle_state=rg.properties.provisioning_state if rg.properties else None,
            tags=dict(rg.tags) if rg.tags else {},
            raw_metadata=_as_dict(rg),
        )


async def _discover_virtual_machines(
    credential: Any, subscription_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    compute_client = ComputeManagementClient(credential, subscription_id)
    async for vm in _stream_paged(compute_client.virtual_machines.list_all()):
        yield NormalizedCloudAsset(
            provider="azure",
            native_id=str(vm.id),
            native_resource_type="Microsoft.Compute/virtualMachines",
            normalized_category="virtual_machine",
            name=str(vm.name),
            region_or_location=vm.location,
            parent_native_id=_resource_group_from_id(vm.id),
            account_or_subscription_or_project=subscription_id,
            lifecycle_state=vm.provisioning_state,
            tags=dict(vm.tags) if vm.tags else {},
            raw_metadata=_as_dict(vm),
        )


async def _discover_virtual_networks(
    credential: Any, subscription_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    network_client = NetworkManagementClient(credential, subscription_id)
    async for vnet in _stream_paged(network_client.virtual_networks.list_all()):
        yield NormalizedCloudAsset(
            provider="azure",
            native_id=str(vnet.id),
            native_resource_type="Microsoft.Network/virtualNetworks",
            normalized_category="virtual_network",
            name=str(vnet.name),
            region_or_location=vnet.location,
            parent_native_id=_resource_group_from_id(vnet.id),
            account_or_subscription_or_project=subscription_id,
            lifecycle_state=vnet.provisioning_state,
            tags=dict(vnet.tags) if vnet.tags else {},
            raw_metadata=_as_dict(vnet),
        )
        for subnet in vnet.subnets or []:
            yield NormalizedCloudAsset(
                provider="azure",
                native_id=str(subnet.id),
                native_resource_type="Microsoft.Network/virtualNetworks/subnets",
                normalized_category="subnet",
                name=str(subnet.name),
                region_or_location=vnet.location,
                parent_native_id=str(vnet.id),
                account_or_subscription_or_project=subscription_id,
                lifecycle_state=subnet.provisioning_state,
                raw_metadata=_as_dict(subnet),
            )


async def _discover_storage_accounts(
    credential: Any, subscription_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    storage_client = StorageManagementClient(credential, subscription_id)
    async for account in _stream_paged(storage_client.storage_accounts.list()):
        yield NormalizedCloudAsset(
            provider="azure",
            native_id=str(account.id),
            native_resource_type="Microsoft.Storage/storageAccounts",
            normalized_category="storage_account",
            name=str(account.name),
            region_or_location=account.location,
            parent_native_id=_resource_group_from_id(account.id),
            account_or_subscription_or_project=subscription_id,
            lifecycle_state=account.provisioning_state,
            tags=dict(account.tags) if account.tags else {},
            internet_exposure_known=(
                str(account.public_network_access) == "Enabled"
                if account.public_network_access
                else None
            ),
            managed_service=True,
            raw_metadata=_as_dict(account),
        )


async def _discover_key_vaults(
    credential: Any, subscription_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    kv_client = KeyVaultManagementClient(credential, subscription_id)
    async for vault in _stream_paged(kv_client.vaults.list_by_subscription()):
        yield NormalizedCloudAsset(
            provider="azure",
            native_id=str(vault.id),
            native_resource_type="Microsoft.KeyVault/vaults",
            normalized_category="key_vault_metadata",
            name=str(vault.name),
            region_or_location=vault.location,
            parent_native_id=_resource_group_from_id(vault.id),
            account_or_subscription_or_project=subscription_id,
            tags=dict(vault.tags) if vault.tags else {},
            managed_service=True,
            raw_metadata=_as_dict(vault),
        )


async def discover_assets(
    profile: CloudConnectionProfile, scope_native_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    credential = await asyncio.to_thread(_build_credential, profile)
    subscription_id = scope_native_id

    async for asset in _safe_assets(
        _discover_subscription(credential, subscription_id), "subscription"
    ):
        yield asset
    async for asset in _safe_assets(
        _discover_resource_groups(credential, subscription_id), "resource_group"
    ):
        yield asset
    async for asset in _safe_assets(
        _discover_virtual_machines(credential, subscription_id), "virtual_machine"
    ):
        yield asset
    async for asset in _safe_assets(
        _discover_virtual_networks(credential, subscription_id), "virtual_network"
    ):
        yield asset
    async for asset in _safe_assets(
        _discover_storage_accounts(credential, subscription_id), "storage_account"
    ):
        yield asset
    async for asset in _safe_assets(
        _discover_key_vaults(credential, subscription_id), "key_vault_metadata"
    ):
        yield asset


async def _relationships(
    credential: Any, subscription_id: str
) -> AsyncIterator[NormalizedCloudRelationship]:
    network_client = NetworkManagementClient(credential, subscription_id)
    async for vnet in _stream_paged(network_client.virtual_networks.list_all()):
        rg = _resource_group_from_id(vnet.id)
        if rg:
            yield NormalizedCloudRelationship(
                source_native_id=str(vnet.id),
                target_native_id=rg,
                relationship_type="BELONGS_TO",
                is_direct=True,
            )
        for subnet in vnet.subnets or []:
            yield NormalizedCloudRelationship(
                source_native_id=str(subnet.id),
                target_native_id=str(vnet.id),
                relationship_type="BELONGS_TO",
                is_direct=True,
            )

    compute_client = ComputeManagementClient(credential, subscription_id)
    async for vm in _stream_paged(compute_client.virtual_machines.list_all()):
        rg = _resource_group_from_id(vm.id)
        if rg:
            yield NormalizedCloudRelationship(
                source_native_id=str(vm.id),
                target_native_id=rg,
                relationship_type="BELONGS_TO",
                is_direct=True,
            )
        network_profile = vm.network_profile
        for nic_ref in (network_profile.network_interfaces if network_profile else None) or []:
            if nic_ref.id:
                yield NormalizedCloudRelationship(
                    source_native_id=str(vm.id),
                    target_native_id=str(nic_ref.id),
                    relationship_type="ATTACHED_TO",
                    is_direct=True,
                )

    storage_client = StorageManagementClient(credential, subscription_id)
    async for account in _stream_paged(storage_client.storage_accounts.list()):
        rg = _resource_group_from_id(account.id)
        if rg:
            yield NormalizedCloudRelationship(
                source_native_id=str(account.id),
                target_native_id=rg,
                relationship_type="BELONGS_TO",
                is_direct=True,
            )


async def discover_relationships(
    profile: CloudConnectionProfile, scope_native_id: str
) -> AsyncIterator[NormalizedCloudRelationship]:
    credential = await asyncio.to_thread(_build_credential, profile)
    async for rel in _safe_relationships(
        _relationships(credential, scope_native_id), "azure_relationships"
    ):
        yield rel
