"""EDP-009 Part 1, Section 2: real CloudEnvironment registration and lookup.
Registering an environment never connects to anything - it only records real facts
about an authorised organisational cloud scope the operator is declaring, mirroring
gds_api.repository.registry.register_repository's own "recording a fact, not
performing an action" precedent."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.audit import record_audit_event
from gds_api.cloud.providers import get_provider
from gds_api.metrics import cloud_environments_registered_total
from gds_api.models import CloudEnvironment

_ENVIRONMENT_TYPES = {
    "organisation",
    "account",
    "subscription",
    "project",
    "resource_group",
    "management_group",
    "folder",
    "cluster",
    "namespace",
}


class CloudEnvironmentNotFound(Exception):
    pass


class UnknownCloudProvider(Exception):
    pass


class InvalidEnvironmentType(Exception):
    pass


async def register_environment(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    created_by_user_id: uuid.UUID,
    provider: str,
    name: str,
    native_id: str,
    environment_type: str,
    parent_environment_id: uuid.UUID | None = None,
    classification: str | None = None,
    description: str | None = None,
    tags: dict[str, object] | None = None,
) -> CloudEnvironment:
    if get_provider(provider) is None:
        raise UnknownCloudProvider(f"'{provider}' is not a real registered cloud provider")
    if environment_type not in _ENVIRONMENT_TYPES:
        raise InvalidEnvironmentType(
            f"'{environment_type}' is not a real environment type "
            f"(expected one of {sorted(_ENVIRONMENT_TYPES)})"
        )
    if parent_environment_id is not None:
        parent = await db.get(CloudEnvironment, parent_environment_id)
        if parent is None or parent.tenant_id != tenant_id:
            raise CloudEnvironmentNotFound("Parent environment not found")

    env = CloudEnvironment(
        tenant_id=tenant_id,
        provider=provider,
        name=name,
        native_id=native_id,
        environment_type=environment_type,
        parent_environment_id=parent_environment_id,
        created_by_user_id=created_by_user_id,
        classification=classification,
        description=description,
        tags=tags or {},
        status="registered",
    )
    db.add(env)
    await db.flush()
    cloud_environments_registered_total.labels(provider=provider).inc()

    await record_audit_event(
        db,
        tenant_id=tenant_id,
        user_id=created_by_user_id,
        action="cloud.environment_registered",
        detail={
            "environment_id": str(env.id),
            "provider": provider,
            "environment_type": environment_type,
            "native_id": native_id,
        },
    )
    return env


async def get_environment(
    db: AsyncSession, *, tenant_id: uuid.UUID, environment_id: uuid.UUID
) -> CloudEnvironment:
    env = await db.get(CloudEnvironment, environment_id)
    if env is None or env.tenant_id != tenant_id:
        raise CloudEnvironmentNotFound("Cloud environment not found")
    return env


async def list_environments(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    provider: str | None = None,
    environment_type: str | None = None,
    discovery_status: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[CloudEnvironment]:
    """Section 30: `discovery_status` also drives the real "stale cloud inventories"/
    "failed discovery jobs" Cloud Commands (Section 31) - both filter this same real
    column, never a separately maintained list."""
    limit = max(1, min(limit, 200))
    query = select(CloudEnvironment).where(CloudEnvironment.tenant_id == tenant_id)
    if provider:
        query = query.where(CloudEnvironment.provider == provider)
    if environment_type:
        query = query.where(CloudEnvironment.environment_type == environment_type)
    if discovery_status:
        query = query.where(CloudEnvironment.discovery_status == discovery_status)
    query = query.order_by(CloudEnvironment.created_at.desc()).limit(limit).offset(offset)
    result = await db.execute(query)
    return list(result.scalars().all())


async def set_connection_profile(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    environment_id: uuid.UUID,
    connection_profile_id: uuid.UUID | None,
) -> CloudEnvironment:
    env = await get_environment(db, tenant_id=tenant_id, environment_id=environment_id)
    env.connection_profile_id = connection_profile_id
    await db.flush()
    return env
