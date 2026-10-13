"""EDP-009 Part 1, Section 17: real asset change detection - a durable
`CloudAssetChangeEvent` row per real, detected change, produced only at the end
of a discovery run that genuinely touched at least one real asset (the caller,
`tool_gateway._discover_cloud_environment`, enforces that safeguard - see its
own comment for why).

Section 17's own explicit rule: "not observed is not always deleted." Absence
is graduated, never a single boolean flip:

    unknown -> (missed once) -> absent_current_run -> (missed again) -> confirmed_absent
                                        |
                                        +-- (seen again) --> present (a real "reappeared" event)

An asset is never jumped straight from `present` to `confirmed_absent` on a
single missed run - it must be missed twice in a row, and a single successful
re-discovery at any point resets it straight back to `present`.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.models import CloudAsset, CloudAssetChangeEvent

_FIELD_TO_CHANGE_TYPE: dict[str, str] = {
    "lifecycle_state": "lifecycle_state_changed",
    "region_or_location": "region_changed",
    "tags": "tag_changed",
    "internet_exposure_known": "exposure_changed",
}


async def record_asset_added(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    environment_id: uuid.UUID,
    asset_id: uuid.UUID,
    discovery_job_id: uuid.UUID | None,
) -> None:
    db.add(
        CloudAssetChangeEvent(
            tenant_id=tenant_id,
            environment_id=environment_id,
            asset_id=asset_id,
            discovery_job_id=discovery_job_id,
            change_type="asset_added",
        )
    )
    await db.flush()


async def record_asset_changes(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    environment_id: uuid.UUID,
    asset_id: uuid.UUID,
    discovery_job_id: uuid.UUID | None,
    changed_fields: dict[str, tuple[object, object]],
) -> None:
    """One real event per changed field - `gds_api.cloud.assets.upsert_asset`
    already computed exactly what changed, this only turns that into durable
    rows, never re-derives it."""
    for field, (old_value, new_value) in changed_fields.items():
        if field == "absence_state":
            change_type = "asset_reappeared"
        else:
            change_type = _FIELD_TO_CHANGE_TYPE.get(field, "asset_updated")
        db.add(
            CloudAssetChangeEvent(
                tenant_id=tenant_id,
                environment_id=environment_id,
                asset_id=asset_id,
                discovery_job_id=discovery_job_id,
                change_type=change_type,
                previous_value={field: old_value} if not isinstance(old_value, dict) else old_value,
                new_value={field: new_value} if not isinstance(new_value, dict) else new_value,
            )
        )
    await db.flush()


async def detect_and_record_absences(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    environment_id: uuid.UUID,
    discovery_job_id: uuid.UUID,
    run_started_at: datetime,
) -> dict[str, int]:
    """Real absence sweep: every CloudAsset for this environment that was not
    touched by this run (last_seen_at is still before this run started) and is
    not already `confirmed_absent` gets graduated one step - never straight to
    `confirmed_absent` on a single miss."""
    candidates = (
        (
            await db.execute(
                select(CloudAsset).where(
                    CloudAsset.tenant_id == tenant_id,
                    CloudAsset.environment_id == environment_id,
                    CloudAsset.last_seen_at < run_started_at,
                    CloudAsset.absence_state != "confirmed_absent",
                )
            )
        )
        .scalars()
        .all()
    )
    absent_current_run = 0
    confirmed_absent = 0
    for asset in candidates:
        previous_state = asset.absence_state
        if previous_state == "absent_current_run":
            asset.absence_state = "confirmed_absent"
            confirmed_absent += 1
            change_type = "asset_confirmed_absent"
        else:
            asset.absence_state = "absent_current_run"
            absent_current_run += 1
            change_type = "asset_absent_current_run"
        db.add(
            CloudAssetChangeEvent(
                tenant_id=tenant_id,
                environment_id=environment_id,
                asset_id=asset.id,
                discovery_job_id=discovery_job_id,
                change_type=change_type,
                previous_value={"absence_state": previous_state},
                new_value={"absence_state": asset.absence_state},
            )
        )
    await db.flush()
    return {"absent_current_run": absent_current_run, "confirmed_absent": confirmed_absent}


async def list_change_events(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    environment_id: uuid.UUID | None = None,
    asset_id: uuid.UUID | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[CloudAssetChangeEvent]:
    limit = max(1, min(limit, 200))
    query = select(CloudAssetChangeEvent).where(CloudAssetChangeEvent.tenant_id == tenant_id)
    if environment_id:
        query = query.where(CloudAssetChangeEvent.environment_id == environment_id)
    if asset_id:
        query = query.where(CloudAssetChangeEvent.asset_id == asset_id)
    query = query.order_by(CloudAssetChangeEvent.detected_at.desc()).limit(limit).offset(offset)
    result = await db.execute(query)
    return list(result.scalars().all())
