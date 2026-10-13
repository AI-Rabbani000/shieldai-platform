"""EDP-009 Part 1, Section 16: real inventory snapshots - a "versioned
current-state record" strategy (see `CloudInventorySnapshot`'s own docstring
for why this Part doesn't materialize a full copy of every asset on every
run). One real snapshot per discovery job, created after that job's own real
asset/relationship persistence and change detection have already run.
"""

from __future__ import annotations

import uuid
from collections import Counter

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.models import (
    CloudAsset,
    CloudAssetRelationship,
    CloudDiscoveryJob,
    CloudInventorySnapshot,
)


async def create_snapshot(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    environment_id: uuid.UUID,
    provider: str,
    discovery_job: CloudDiscoveryJob,
    change_summary: dict[str, int],
) -> CloudInventorySnapshot:
    assets = (
        (
            await db.execute(
                select(CloudAsset).where(CloudAsset.discovery_job_id == discovery_job.id)
            )
        )
        .scalars()
        .all()
    )
    resource_counts: Counter[str] = Counter(a.normalized_category for a in assets)
    regions = sorted({a.region_or_location for a in assets if a.region_or_location})

    relationship_count_result = await db.execute(
        select(CloudAssetRelationship).where(
            CloudAssetRelationship.tenant_id == tenant_id,
            CloudAssetRelationship.discovery_job_id == discovery_job.id,
        )
    )
    relationship_count = len(relationship_count_result.scalars().all())

    previous = (
        (
            await db.execute(
                select(CloudInventorySnapshot)
                .where(CloudInventorySnapshot.environment_id == environment_id)
                .order_by(CloudInventorySnapshot.created_at.desc())
            )
        )
        .scalars()
        .first()
    )

    # A real, deliberately optimistic simplification, disclosed rather than
    # hidden (see docs/guides/cloud-asset-model.md's own closing section): no
    # structured per-category success/failure signal crosses the adapter
    # boundary yet (Section 8's own per-category isolation absorbs it), so
    # "complete" here means "the job reached CloudDiscoveryJob.status ==
    # completed", not a verified guarantee every category actually succeeded.
    completeness_status = "complete" if discovery_job.status == "completed" else "unknown"

    snapshot = CloudInventorySnapshot(
        tenant_id=tenant_id,
        environment_id=environment_id,
        provider=provider,
        discovery_job_id=discovery_job.id,
        started_at=discovery_job.started_at or discovery_job.created_at,
        completed_at=discovery_job.completed_at,
        status=discovery_job.status,
        resource_counts_by_category=dict(resource_counts),
        relationship_count=relationship_count,
        regions_covered=regions,
        failed_scopes=list(discovery_job.errors),
        warnings=list(discovery_job.warnings),
        completeness_status=completeness_status,
        previous_snapshot_id=previous.id if previous else None,
        change_summary=change_summary,
    )
    db.add(snapshot)
    await db.flush()
    return snapshot


async def list_snapshots(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    environment_id: uuid.UUID | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[CloudInventorySnapshot]:
    limit = max(1, min(limit, 200))
    query = select(CloudInventorySnapshot).where(CloudInventorySnapshot.tenant_id == tenant_id)
    if environment_id:
        query = query.where(CloudInventorySnapshot.environment_id == environment_id)
    query = query.order_by(CloudInventorySnapshot.created_at.desc()).limit(limit).offset(offset)
    result = await db.execute(query)
    return list(result.scalars().all())
