"""EDP-009 Part 1: the real HTTP surface over the Multi-Cloud Foundation - the
Cloud Provider Registry (read-only, code-defined), CloudEnvironment registration,
governed CloudConnectionProfile management, real read-only connection validation,
and (sub-phase 2) starting/tracking a real CloudDiscoveryJob through the existing
Capability Broker pipeline. Asset/relationship/graph endpoints and evidence
integration are later sub-phases of this same Part.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.cloud.assets import (
    compute_freshness_state,
    get_asset,
    list_assets,
    list_relationships_for_asset,
)
from gds_api.cloud.changes import list_change_events
from gds_api.cloud.connections import (
    CloudConnectionProfileNotFound,
    InvalidAuthenticationType,
    create_connection_profile,
    get_connection_profile,
    validate_connection,
)
from gds_api.cloud.discovery import (
    CloudDiscoveryJobNotFound,
    CloudDiscoveryStartError,
    cancel_discovery_job,
    get_discovery_job,
    list_discovery_jobs,
    start_discovery,
)
from gds_api.cloud.environments import (
    CloudEnvironmentNotFound,
    InvalidEnvironmentType,
    UnknownCloudProvider,
    list_environments,
    register_environment,
)
from gds_api.cloud.environments import get_environment as get_environment_service
from gds_api.cloud.graph import get_asset_subgraph
from gds_api.cloud.providers import list_providers
from gds_api.cloud.snapshots import list_snapshots
from gds_api.db import get_db
from gds_api.models import (
    CloudAsset,
    CloudAssetChangeEvent,
    CloudAssetRelationship,
    CloudConnectionProfile,
    CloudDiscoveryJob,
    CloudEnvironment,
    CloudInventorySnapshot,
)
from gds_api.schemas import (
    CloudAssetChangeEventOut,
    CloudAssetOut,
    CloudAssetRelationshipOut,
    CloudConnectionProfileCreateRequest,
    CloudConnectionProfileOut,
    CloudConnectionValidationOut,
    CloudDiscoveryJobOut,
    CloudDiscoveryJobStartRequest,
    CloudEnvironmentCreateRequest,
    CloudEnvironmentOut,
    CloudGraphSubgraphOut,
    CloudInventorySnapshotOut,
    CloudProviderOut,
)
from gds_api.security import CurrentUser, require_permission

router = APIRouter(prefix="/cloud", tags=["cloud"])


def _provider_to_out(provider) -> CloudProviderOut:  # type: ignore[no-untyped-def]
    return CloudProviderOut(
        provider_id=provider.provider_id,
        display_name=provider.display_name,
        status=provider.status.value,
        supported_authentication_mechanisms=provider.supported_authentication_mechanisms,
        supported_discovery_scopes=tuple(s.value for s in provider.supported_discovery_scopes),
        supported_resource_categories=provider.supported_resource_categories,
        regional=provider.regional,
        adapter_available=provider.adapter_available,
        connection_test_capability=provider.connection_test_capability,
        inventory_capability=provider.inventory_capability,
        known_limitations=provider.known_limitations,
    )


def _environment_to_out(env: CloudEnvironment) -> CloudEnvironmentOut:
    return CloudEnvironmentOut(
        id=env.id,
        tenant_id=env.tenant_id,
        provider=env.provider,
        name=env.name,
        native_id=env.native_id,
        environment_type=env.environment_type,
        parent_environment_id=env.parent_environment_id,
        organisational_path=env.organisational_path,
        status=env.status,
        connection_profile_id=env.connection_profile_id,
        discovery_status=env.discovery_status,
        last_successful_discovery_at=env.last_successful_discovery_at,
        last_attempted_discovery_at=env.last_attempted_discovery_at,
        last_failure_detail=env.last_failure_detail,
        asset_count=env.asset_count,
        region_count=env.region_count,
        graph_sync_status=env.graph_sync_status,
        graph_last_synced_at=env.graph_last_synced_at,
        created_by_user_id=env.created_by_user_id,
        tags=env.tags,
        classification=env.classification,
        description=env.description,
        enabled=env.enabled,
        created_at=env.created_at,
        updated_at=env.updated_at,
    )


def _connection_profile_to_out(profile: CloudConnectionProfile) -> CloudConnectionProfileOut:
    return CloudConnectionProfileOut(
        id=profile.id,
        tenant_id=profile.tenant_id,
        environment_id=profile.environment_id,
        provider=profile.provider,
        authentication_type=profile.authentication_type,
        credential_reference=profile.credential_reference,
        role_or_principal_reference=profile.role_or_principal_reference,
        external_id=profile.external_id,
        permission_scope=profile.permission_scope,
        read_only=profile.read_only,
        validation_status=profile.validation_status,
        last_validated_at=profile.last_validated_at,
        expiry_at=profile.expiry_at,
        rotation_state=profile.rotation_state,
        created_by_user_id=profile.created_by_user_id,
        enabled=profile.enabled,
        created_at=profile.created_at,
        updated_at=profile.updated_at,
    )


@router.get("/providers", response_model=list[CloudProviderOut])
async def list_cloud_providers(
    current_user: CurrentUser = Depends(require_permission("cloud:read")),
) -> list[CloudProviderOut]:
    return [_provider_to_out(p) for p in list_providers()]


@router.get("/environments", response_model=list[CloudEnvironmentOut])
async def list_cloud_environments(
    provider: str | None = None,
    environment_type: str | None = None,
    discovery_status: str | None = None,
    limit: int = 50,
    offset: int = 0,
    current_user: CurrentUser = Depends(require_permission("cloud:environments:read")),
    db: AsyncSession = Depends(get_db),
) -> list[CloudEnvironmentOut]:
    envs = await list_environments(
        db,
        tenant_id=current_user.tenant_id,
        provider=provider,
        environment_type=environment_type,
        discovery_status=discovery_status,
        limit=limit,
        offset=offset,
    )
    return [_environment_to_out(e) for e in envs]


@router.post("/environments", response_model=CloudEnvironmentOut)
async def create_cloud_environment(
    body: CloudEnvironmentCreateRequest,
    current_user: CurrentUser = Depends(require_permission("cloud:environments:manage")),
    db: AsyncSession = Depends(get_db),
) -> CloudEnvironmentOut:
    try:
        env = await register_environment(
            db,
            tenant_id=current_user.tenant_id,
            created_by_user_id=current_user.user_id,
            provider=body.provider,
            name=body.name,
            native_id=body.native_id,
            environment_type=body.environment_type,
            parent_environment_id=body.parent_environment_id,
            classification=body.classification,
            description=body.description,
            tags=body.tags,
        )
    except (UnknownCloudProvider, InvalidEnvironmentType) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except CloudEnvironmentNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    await db.commit()
    await db.refresh(env)
    return _environment_to_out(env)


@router.get("/environments/{environment_id}", response_model=CloudEnvironmentOut)
async def get_cloud_environment(
    environment_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("cloud:environments:read")),
    db: AsyncSession = Depends(get_db),
) -> CloudEnvironmentOut:
    try:
        env = await get_environment_service(
            db, tenant_id=current_user.tenant_id, environment_id=environment_id
        )
    except CloudEnvironmentNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    return _environment_to_out(env)


@router.post("/connections", response_model=CloudConnectionProfileOut)
async def create_cloud_connection_profile(
    body: CloudConnectionProfileCreateRequest,
    current_user: CurrentUser = Depends(require_permission("cloud:connections:manage")),
    db: AsyncSession = Depends(get_db),
) -> CloudConnectionProfileOut:
    # 404, not a silent create, if the environment doesn't real-exist for this tenant.
    try:
        await get_environment_service(
            db, tenant_id=current_user.tenant_id, environment_id=body.environment_id
        )
    except CloudEnvironmentNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc

    try:
        profile = await create_connection_profile(
            db,
            tenant_id=current_user.tenant_id,
            created_by_user_id=current_user.user_id,
            environment_id=body.environment_id,
            provider=body.provider,
            authentication_type=body.authentication_type,
            credential_reference=body.credential_reference,
            role_or_principal_reference=body.role_or_principal_reference,
            external_id=body.external_id,
            permission_scope=body.permission_scope,
            read_only=body.read_only,
        )
    except InvalidAuthenticationType as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    await db.commit()
    await db.refresh(profile)
    return _connection_profile_to_out(profile)


@router.get("/connections/{connection_profile_id}", response_model=CloudConnectionProfileOut)
async def get_cloud_connection_profile(
    connection_profile_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("cloud:connections:read")),
    db: AsyncSession = Depends(get_db),
) -> CloudConnectionProfileOut:
    try:
        profile = await get_connection_profile(
            db, tenant_id=current_user.tenant_id, connection_profile_id=connection_profile_id
        )
    except CloudConnectionProfileNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    return _connection_profile_to_out(profile)


@router.post(
    "/connections/{connection_profile_id}/validate",
    response_model=CloudConnectionValidationOut,
)
async def validate_cloud_connection(
    connection_profile_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("cloud:connections:validate")),
    db: AsyncSession = Depends(get_db),
) -> CloudConnectionValidationOut:
    try:
        validation = await validate_connection(
            db,
            tenant_id=current_user.tenant_id,
            actor_user_id=current_user.user_id,
            connection_profile_id=connection_profile_id,
        )
    except CloudConnectionProfileNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    await db.commit()
    await db.refresh(validation)
    return CloudConnectionValidationOut(
        id=validation.id,
        tenant_id=validation.tenant_id,
        connection_profile_id=validation.connection_profile_id,
        provider_identity=validation.provider_identity,
        scope_identity=validation.scope_identity,
        status=validation.status,
        attempted_at=validation.attempted_at,
        completed_at=validation.completed_at,
        sanitized_error=validation.sanitized_error,
        capability_availability=validation.capability_availability,
        latency_ms=validation.latency_ms,
        actor_user_id=validation.actor_user_id,
        correlation_id=validation.correlation_id,
        evidence_id=validation.evidence_id,
    )


def _discovery_job_to_out(job: CloudDiscoveryJob) -> CloudDiscoveryJobOut:
    return CloudDiscoveryJobOut(
        id=job.id,
        tenant_id=job.tenant_id,
        environment_id=job.environment_id,
        provider=job.provider,
        connection_profile_id=job.connection_profile_id,
        requested_scope=job.requested_scope,
        discovery_categories=job.discovery_categories,
        regions=job.regions,
        initiated_by_user_id=job.initiated_by_user_id,
        mission_id=job.mission_id,
        workflow_run_id=job.workflow_run_id,
        status=job.status,
        started_at=job.started_at,
        completed_at=job.completed_at,
        assets_discovered=job.assets_discovered,
        assets_updated=job.assets_updated,
        assets_unchanged=job.assets_unchanged,
        assets_marked_absent=job.assets_marked_absent,
        relationships_discovered=job.relationships_discovered,
        errors=job.errors,
        warnings=job.warnings,
        rate_limit_state=job.rate_limit_state,
        evidence_id=job.evidence_id,
        correlation_id=job.correlation_id,
        created_at=job.created_at,
        updated_at=job.updated_at,
    )


@router.post("/discovery-jobs", response_model=CloudDiscoveryJobOut)
async def start_cloud_discovery(
    body: CloudDiscoveryJobStartRequest,
    current_user: CurrentUser = Depends(require_permission("cloud:inventory:run")),
    db: AsyncSession = Depends(get_db),
) -> CloudDiscoveryJobOut:
    try:
        job = await start_discovery(
            db,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
            environment_id=body.environment_id,
            discovery_categories=body.discovery_categories,
        )
    except CloudDiscoveryStartError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, exc.reason) from exc
    await db.commit()
    await db.refresh(job)
    return _discovery_job_to_out(job)


@router.get("/discovery-jobs", response_model=list[CloudDiscoveryJobOut])
async def list_cloud_discovery_jobs(
    environment_id: uuid.UUID | None = None,
    status_filter: str | None = None,
    limit: int = 50,
    offset: int = 0,
    current_user: CurrentUser = Depends(require_permission("cloud:inventory:read")),
    db: AsyncSession = Depends(get_db),
) -> list[CloudDiscoveryJobOut]:
    jobs = await list_discovery_jobs(
        db,
        tenant_id=current_user.tenant_id,
        environment_id=environment_id,
        status_filter=status_filter,
        limit=limit,
        offset=offset,
    )
    return [_discovery_job_to_out(j) for j in jobs]


@router.get("/discovery-jobs/{discovery_job_id}", response_model=CloudDiscoveryJobOut)
async def get_cloud_discovery_job(
    discovery_job_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("cloud:inventory:read")),
    db: AsyncSession = Depends(get_db),
) -> CloudDiscoveryJobOut:
    try:
        job = await get_discovery_job(
            db, tenant_id=current_user.tenant_id, discovery_job_id=discovery_job_id
        )
    except CloudDiscoveryJobNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    return _discovery_job_to_out(job)


@router.post("/discovery-jobs/{discovery_job_id}/cancel", response_model=CloudDiscoveryJobOut)
async def cancel_cloud_discovery_job(
    discovery_job_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("cloud:inventory:cancel")),
    db: AsyncSession = Depends(get_db),
) -> CloudDiscoveryJobOut:
    try:
        job = await cancel_discovery_job(
            db,
            tenant_id=current_user.tenant_id,
            discovery_job_id=discovery_job_id,
            user_id=current_user.user_id,
        )
    except CloudDiscoveryJobNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    except CloudDiscoveryStartError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, exc.reason) from exc
    await db.commit()
    await db.refresh(job)
    return _discovery_job_to_out(job)


def _asset_to_out(asset: CloudAsset) -> CloudAssetOut:
    return CloudAssetOut(
        id=asset.id,
        tenant_id=asset.tenant_id,
        environment_id=asset.environment_id,
        provider=asset.provider,
        native_id=asset.native_id,
        native_resource_type=asset.native_resource_type,
        provider_category=asset.provider_category,
        normalized_category=asset.normalized_category,
        name=asset.name,
        display_name=asset.display_name,
        region_or_location=asset.region_or_location,
        availability_zone=asset.availability_zone,
        parent_asset_id=asset.parent_asset_id,
        account_or_subscription_or_project=asset.account_or_subscription_or_project,
        resource_group_or_org_path=asset.resource_group_or_org_path,
        lifecycle_state=asset.lifecycle_state,
        created_at_provider=asset.created_at_provider,
        first_seen_at=asset.first_seen_at,
        last_seen_at=asset.last_seen_at,
        last_changed_at=asset.last_changed_at,
        discovery_job_id=asset.discovery_job_id,
        tags=asset.tags,
        internet_exposure_known=asset.internet_exposure_known,
        managed_service=asset.managed_service,
        raw_metadata=asset.raw_metadata,
        schema_version=asset.schema_version,
        freshness_state=compute_freshness_state(asset.last_seen_at),
        absence_state=asset.absence_state,
        evidence_id=asset.evidence_id,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
    )


def _relationship_to_out(relationship: CloudAssetRelationship) -> CloudAssetRelationshipOut:
    return CloudAssetRelationshipOut(
        id=relationship.id,
        tenant_id=relationship.tenant_id,
        source_asset_id=relationship.source_asset_id,
        target_asset_id=relationship.target_asset_id,
        relationship_type=relationship.relationship_type,
        discovery_job_id=relationship.discovery_job_id,
        first_seen_at=relationship.first_seen_at,
        last_seen_at=relationship.last_seen_at,
        confidence_basis=relationship.confidence_basis,
        is_direct=relationship.is_direct,
        derivation_rule=relationship.derivation_rule,
        relationship_metadata=relationship.relationship_metadata,
        evidence_id=relationship.evidence_id,
        created_at=relationship.created_at,
        updated_at=relationship.updated_at,
    )


@router.get("/assets", response_model=list[CloudAssetOut])
async def list_cloud_assets(
    environment_id: uuid.UUID | None = None,
    normalized_category: str | None = None,
    provider: str | None = None,
    region: str | None = None,
    native_resource_type: str | None = None,
    lifecycle_state: str | None = None,
    absence_state: str | None = None,
    freshness_state: str | None = None,
    internet_exposure_known: bool | None = None,
    tag_key: str | None = None,
    tag_value: str | None = None,
    first_seen_after: datetime | None = None,
    first_seen_before: datetime | None = None,
    last_seen_after: datetime | None = None,
    last_seen_before: datetime | None = None,
    q: str | None = None,
    limit: int = 50,
    offset: int = 0,
    current_user: CurrentUser = Depends(require_permission("cloud:assets:read")),
    db: AsyncSession = Depends(get_db),
) -> list[CloudAssetOut]:
    assets = await list_assets(
        db,
        tenant_id=current_user.tenant_id,
        environment_id=environment_id,
        normalized_category=normalized_category,
        provider=provider,
        region=region,
        native_resource_type=native_resource_type,
        lifecycle_state=lifecycle_state,
        absence_state=absence_state,
        freshness_state=freshness_state,
        internet_exposure_known=internet_exposure_known,
        tag_key=tag_key,
        tag_value=tag_value,
        first_seen_after=first_seen_after,
        first_seen_before=first_seen_before,
        last_seen_after=last_seen_after,
        last_seen_before=last_seen_before,
        q=q,
        limit=limit,
        offset=offset,
    )
    return [_asset_to_out(a) for a in assets]


@router.get("/assets/{asset_id}", response_model=CloudAssetOut)
async def get_cloud_asset(
    asset_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("cloud:assets:read")),
    db: AsyncSession = Depends(get_db),
) -> CloudAssetOut:
    asset = await get_asset(db, tenant_id=current_user.tenant_id, asset_id=asset_id)
    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Cloud asset not found")
    return _asset_to_out(asset)


@router.get("/assets/{asset_id}/relationships", response_model=list[CloudAssetRelationshipOut])
async def list_cloud_asset_relationships(
    asset_id: uuid.UUID,
    limit: int = 50,
    current_user: CurrentUser = Depends(require_permission("cloud:graph:read")),
    db: AsyncSession = Depends(get_db),
) -> list[CloudAssetRelationshipOut]:
    asset = await get_asset(db, tenant_id=current_user.tenant_id, asset_id=asset_id)
    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Cloud asset not found")
    relationships = await list_relationships_for_asset(
        db, tenant_id=current_user.tenant_id, asset_id=asset_id, limit=limit
    )
    return [_relationship_to_out(r) for r in relationships]


def _snapshot_to_out(snapshot: CloudInventorySnapshot) -> CloudInventorySnapshotOut:
    return CloudInventorySnapshotOut(
        id=snapshot.id,
        tenant_id=snapshot.tenant_id,
        environment_id=snapshot.environment_id,
        provider=snapshot.provider,
        discovery_job_id=snapshot.discovery_job_id,
        started_at=snapshot.started_at,
        completed_at=snapshot.completed_at,
        status=snapshot.status,
        resource_counts_by_category=snapshot.resource_counts_by_category,
        relationship_count=snapshot.relationship_count,
        regions_covered=snapshot.regions_covered,
        failed_scopes=snapshot.failed_scopes,
        warnings=snapshot.warnings,
        completeness_status=snapshot.completeness_status,
        previous_snapshot_id=snapshot.previous_snapshot_id,
        change_summary=snapshot.change_summary,
        evidence_id=snapshot.evidence_id,
        created_at=snapshot.created_at,
    )


def _change_event_to_out(event: CloudAssetChangeEvent) -> CloudAssetChangeEventOut:
    return CloudAssetChangeEventOut(
        id=event.id,
        tenant_id=event.tenant_id,
        environment_id=event.environment_id,
        asset_id=event.asset_id,
        discovery_job_id=event.discovery_job_id,
        change_type=event.change_type,
        previous_value=event.previous_value,
        new_value=event.new_value,
        detected_at=event.detected_at,
    )


@router.get("/snapshots", response_model=list[CloudInventorySnapshotOut])
async def list_cloud_inventory_snapshots(
    environment_id: uuid.UUID | None = None,
    limit: int = 50,
    offset: int = 0,
    current_user: CurrentUser = Depends(require_permission("cloud:inventory:read")),
    db: AsyncSession = Depends(get_db),
) -> list[CloudInventorySnapshotOut]:
    snapshots = await list_snapshots(
        db,
        tenant_id=current_user.tenant_id,
        environment_id=environment_id,
        limit=limit,
        offset=offset,
    )
    return [_snapshot_to_out(s) for s in snapshots]


@router.get("/changes", response_model=list[CloudAssetChangeEventOut])
async def list_cloud_asset_changes(
    environment_id: uuid.UUID | None = None,
    asset_id: uuid.UUID | None = None,
    limit: int = 50,
    offset: int = 0,
    current_user: CurrentUser = Depends(require_permission("cloud:assets:read")),
    db: AsyncSession = Depends(get_db),
) -> list[CloudAssetChangeEventOut]:
    events = await list_change_events(
        db,
        tenant_id=current_user.tenant_id,
        environment_id=environment_id,
        asset_id=asset_id,
        limit=limit,
        offset=offset,
    )
    return [_change_event_to_out(e) for e in events]


@router.get("/graph/{asset_id}", response_model=CloudGraphSubgraphOut)
async def get_cloud_asset_graph(
    asset_id: uuid.UUID,
    depth: int = 1,
    current_user: CurrentUser = Depends(require_permission("cloud:graph:read")),
    db: AsyncSession = Depends(get_db),
) -> CloudGraphSubgraphOut:
    asset = await get_asset(db, tenant_id=current_user.tenant_id, asset_id=asset_id)
    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Cloud asset not found")
    subgraph = await get_asset_subgraph(
        tenant_id=current_user.tenant_id, asset_id=asset_id, depth=depth
    )
    return CloudGraphSubgraphOut(
        nodes=subgraph["nodes"], edges=subgraph["edges"], truncated=subgraph["truncated"]
    )
