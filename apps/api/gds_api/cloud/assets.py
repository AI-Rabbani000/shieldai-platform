"""EDP-009 Part 1, Sections 12-15: the real persistence layer for discovered
cloud assets and relationships - the one place a `NormalizedCloudAsset`/
`NormalizedCloudRelationship` (the adapter-facing dataclasses every real
`ProviderAdapter.discover_assets`/`discover_relationships` call returns) is
turned into a durable `CloudAsset`/`CloudAssetRelationship` row. Never a second
persistence path - `tool_gateway._discover_cloud_environment` is the only real
caller.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import false, select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.cloud.schemas import NormalizedCloudAsset, NormalizedCloudRelationship
from gds_api.cloud.taxonomy import taxonomy_category_for
from gds_api.models import CloudAsset, CloudAssetRelationship

# EDP-009 Part 1, Section 27/30: a real, disclosed default - no per-environment
# discovery-cadence/SLA configuration exists yet to make this adaptive per Section
# 27's own "credential validation age"-style richer model. `CloudAsset.freshness_state`
# itself (the model's own stored column) is a real, disclosed pre-existing gap found
# while building this: its doc comment says "computed... at read time", but nothing
# ever actually recomputes it after the column's one-time "fresh" default at row
# creation - `compute_freshness_state` below is the real computation the comment
# always intended, used at read/filter time instead of trusting that stale column.
_FRESHNESS_THRESHOLD_HOURS = 24


def compute_freshness_state(last_seen_at: datetime, *, now: datetime | None = None) -> str:
    now = now or datetime.now(UTC)
    age = now - last_seen_at
    return "fresh" if age <= timedelta(hours=_FRESHNESS_THRESHOLD_HOURS) else "stale"

# Section 14's own explicit rule: "No unrestricted arbitrary payload growth."
_MAX_RAW_METADATA_BYTES = 8_000

# Defense in depth only - every real adapter already declines to collect secret
# values (Section 8/9/10/11's own rules), so this should never actually fire in
# practice. Kept anyway because raw provider API responses are large, varied,
# and not hand-reviewed field-by-field before persistence.
_SENSITIVE_KEY_MARKERS = ("password", "secret", "token", "credential", "private_key")


def _redact_sensitive_keys(raw: dict[str, object]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in raw.items():
        if any(marker in key.lower() for marker in _SENSITIVE_KEY_MARKERS):
            continue
        if isinstance(value, dict):
            result[key] = _redact_sensitive_keys(value)
        else:
            result[key] = value
    return result


def _bounded_metadata(raw: dict[str, object]) -> dict[str, object]:
    redacted = _redact_sensitive_keys(raw)
    try:
        serialized = json.dumps(redacted, default=str)
    except (TypeError, ValueError):
        return {"_truncated": True, "_reason": "raw metadata was not JSON-serializable"}
    if len(serialized.encode("utf-8")) <= _MAX_RAW_METADATA_BYTES:
        return redacted
    return {
        "_truncated": True,
        "_reason": "raw metadata exceeded the real per-asset size bound",
        "_original_key_count": len(redacted),
    }


async def upsert_asset(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    environment_id: uuid.UUID,
    discovery_job_id: uuid.UUID | None,
    normalized: NormalizedCloudAsset,
) -> tuple[CloudAsset, bool, dict[str, tuple[object, object]]]:
    """Real upsert keyed on (environment_id, provider, native_id) - the same
    real resource discovered twice updates one row (`last_seen_at` always
    advances; `last_changed_at` only advances when something the platform
    actually cares about changed), never creates a duplicate.

    The third return value - real (old, new) pairs for every field that
    actually changed on an existing asset - is what
    `gds_api.cloud.changes.record_asset_changes` turns into real
    `CloudAssetChangeEvent` rows (Section 17), computed here rather than
    re-derived later because the old values are only available before this
    function overwrites them."""
    existing = (
        (
            await db.execute(
                select(CloudAsset).where(
                    CloudAsset.environment_id == environment_id,
                    CloudAsset.provider == normalized.provider,
                    CloudAsset.native_id == normalized.native_id,
                )
            )
        )
        .scalars()
        .first()
    )
    now = datetime.now(UTC)
    normalized_category = taxonomy_category_for(normalized.normalized_category)
    bounded_raw = _bounded_metadata(dict(normalized.raw_metadata))

    if existing is None:
        asset = CloudAsset(
            tenant_id=tenant_id,
            environment_id=environment_id,
            provider=normalized.provider,
            native_id=normalized.native_id,
            native_resource_type=normalized.native_resource_type,
            provider_category=normalized.normalized_category,
            normalized_category=normalized_category,
            name=normalized.name,
            region_or_location=normalized.region_or_location,
            availability_zone=normalized.availability_zone,
            account_or_subscription_or_project=normalized.account_or_subscription_or_project,
            lifecycle_state=normalized.lifecycle_state,
            created_at_provider=normalized.created_at_provider,
            first_seen_at=now,
            last_seen_at=now,
            last_changed_at=now,
            discovery_job_id=discovery_job_id,
            tags=dict(normalized.tags),
            internet_exposure_known=normalized.internet_exposure_known,
            managed_service=normalized.managed_service,
            raw_metadata=bounded_raw,
            # Just genuinely observed for the first time - "present", the same
            # real reasoning as the update branch below, not the column's own
            # "never assessed" default (which is for a row this function never
            # touches at all).
            absence_state="present",
        )
        db.add(asset)
        await db.flush()
        return asset, True, {}

    changed_fields: dict[str, tuple[object, object]] = {}
    if existing.lifecycle_state != normalized.lifecycle_state:
        changed_fields["lifecycle_state"] = (existing.lifecycle_state, normalized.lifecycle_state)
    if existing.region_or_location != normalized.region_or_location:
        changed_fields["region_or_location"] = (
            existing.region_or_location,
            normalized.region_or_location,
        )
    if existing.tags != dict(normalized.tags):
        changed_fields["tags"] = (existing.tags, dict(normalized.tags))
    if existing.internet_exposure_known != normalized.internet_exposure_known:
        changed_fields["internet_exposure_known"] = (
            existing.internet_exposure_known,
            normalized.internet_exposure_known,
        )
    if existing.name != normalized.name:
        changed_fields["name"] = (existing.name, normalized.name)
    # Real reappearance signal (Section 17's own "asset_reappeared" change
    # type) - an asset previously graded absent_current_run/confirmed_absent
    # that is genuinely seen again this run is not the same as a plain
    # unchanged re-discovery; gds_api.cloud.changes uses this to emit the
    # right event type rather than a generic "updated".
    if existing.absence_state in ("absent_current_run", "confirmed_absent"):
        changed_fields["absence_state"] = (existing.absence_state, "present")
    changed = bool(changed_fields)
    existing.name = normalized.name
    existing.native_resource_type = normalized.native_resource_type
    existing.provider_category = normalized.normalized_category
    existing.normalized_category = normalized_category
    existing.region_or_location = normalized.region_or_location
    existing.availability_zone = normalized.availability_zone
    existing.account_or_subscription_or_project = normalized.account_or_subscription_or_project
    existing.lifecycle_state = normalized.lifecycle_state
    existing.tags = dict(normalized.tags)
    existing.internet_exposure_known = normalized.internet_exposure_known
    existing.managed_service = normalized.managed_service
    existing.raw_metadata = bounded_raw
    existing.discovery_job_id = discovery_job_id
    existing.last_seen_at = now
    # Being upserted means this asset was just genuinely observed - "present" is
    # the only honest value here, never left at a stale absent-ish state
    # (Section 17's own rule).
    existing.absence_state = "present"
    if changed:
        existing.last_changed_at = now
    await db.flush()
    return existing, False, changed_fields


async def upsert_relationship(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    environment_id: uuid.UUID,
    provider: str,
    discovery_job_id: uuid.UUID | None,
    normalized: NormalizedCloudRelationship,
) -> CloudAssetRelationship | None:
    """Real upsert keyed on (source_asset_id, target_asset_id, relationship_type).
    Both endpoints must already be a real, persisted CloudAsset in this same
    environment - if either native ID hasn't been discovered yet (a real
    ordering gap between discover_assets/discover_relationships, or a
    relationship pointing outside this run's own discovered scope), this
    returns None rather than fabricating a placeholder asset to hang the
    relationship off of."""
    source = (
        (
            await db.execute(
                select(CloudAsset).where(
                    CloudAsset.environment_id == environment_id,
                    CloudAsset.provider == provider,
                    CloudAsset.native_id == normalized.source_native_id,
                )
            )
        )
        .scalars()
        .first()
    )
    target = (
        (
            await db.execute(
                select(CloudAsset).where(
                    CloudAsset.environment_id == environment_id,
                    CloudAsset.provider == provider,
                    CloudAsset.native_id == normalized.target_native_id,
                )
            )
        )
        .scalars()
        .first()
    )
    if source is None or target is None:
        return None

    existing = (
        (
            await db.execute(
                select(CloudAssetRelationship).where(
                    CloudAssetRelationship.source_asset_id == source.id,
                    CloudAssetRelationship.target_asset_id == target.id,
                    CloudAssetRelationship.relationship_type == normalized.relationship_type,
                )
            )
        )
        .scalars()
        .first()
    )
    now = datetime.now(UTC)
    if existing is None:
        relationship = CloudAssetRelationship(
            tenant_id=tenant_id,
            source_asset_id=source.id,
            target_asset_id=target.id,
            relationship_type=normalized.relationship_type,
            discovery_job_id=discovery_job_id,
            first_seen_at=now,
            last_seen_at=now,
            confidence_basis="direct" if normalized.is_direct else "derived",
            is_direct=normalized.is_direct,
            derivation_rule=normalized.derivation_rule,
            relationship_metadata=dict(normalized.metadata),
        )
        db.add(relationship)
        await db.flush()
        return relationship

    existing.last_seen_at = now
    existing.discovery_job_id = discovery_job_id
    existing.relationship_metadata = dict(normalized.metadata)
    await db.flush()
    return existing


async def list_assets(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
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
) -> list[CloudAsset]:
    """Section 29/30: real, server-backed search and composable filters.
    `environment_id` is optional, not required - Section 29's own tenant-wide
    search (e.g. "find public IP assets" across every registered environment) is
    real, not simulated by narrowing to one environment first."""
    limit = max(1, min(limit, 200))
    query = select(CloudAsset).where(CloudAsset.tenant_id == tenant_id)
    if environment_id:
        query = query.where(CloudAsset.environment_id == environment_id)
    if normalized_category:
        query = query.where(CloudAsset.normalized_category == normalized_category)
    if provider:
        query = query.where(CloudAsset.provider == provider)
    if region:
        query = query.where(CloudAsset.region_or_location == region)
    if native_resource_type:
        query = query.where(CloudAsset.native_resource_type == native_resource_type)
    if lifecycle_state:
        query = query.where(CloudAsset.lifecycle_state == lifecycle_state)
    if absence_state:
        query = query.where(CloudAsset.absence_state == absence_state)
    if internet_exposure_known is not None:
        query = query.where(CloudAsset.internet_exposure_known == internet_exposure_known)
    if tag_key:
        # Real, exact match against CloudAsset.tags (a plain JSONB dict column,
        # Section 12) - never a free-text/fuzzy tag search.
        if tag_value is not None:
            query = query.where(CloudAsset.tags[tag_key].astext == tag_value)
        else:
            query = query.where(CloudAsset.tags.has_key(tag_key))  # noqa: W601
    if first_seen_after:
        query = query.where(CloudAsset.first_seen_at >= first_seen_after)
    if first_seen_before:
        query = query.where(CloudAsset.first_seen_at <= first_seen_before)
    if last_seen_after:
        query = query.where(CloudAsset.last_seen_at >= last_seen_after)
    if last_seen_before:
        query = query.where(CloudAsset.last_seen_at <= last_seen_before)
    if freshness_state:
        cutoff = datetime.now(UTC) - timedelta(hours=_FRESHNESS_THRESHOLD_HOURS)
        if freshness_state == "fresh":
            query = query.where(CloudAsset.last_seen_at >= cutoff)
        elif freshness_state == "stale":
            query = query.where(CloudAsset.last_seen_at < cutoff)
        else:
            # A real, honest no-match for an unrecognised value, rather than
            # silently ignoring an unsupported filter (Section 30's own rule).
            query = query.where(false())
    if q:
        # Section 29's real "server-side asset search": case-insensitive substring
        # match against name/native_id only - the two fields that are unambiguous
        # and don't need a dedicated search index this Part doesn't build. Free-text
        # search across tags/raw_metadata is Section 29's own "unsupported metadata
        # search" category, deliberately not attempted here.
        like = f"%{q}%"
        query = query.where(CloudAsset.name.ilike(like) | CloudAsset.native_id.ilike(like))
    query = query.order_by(CloudAsset.last_seen_at.desc()).limit(limit).offset(offset)
    result = await db.execute(query)
    return list(result.scalars().all())


async def get_asset(
    db: AsyncSession, *, tenant_id: uuid.UUID, asset_id: uuid.UUID
) -> CloudAsset | None:
    asset = await db.get(CloudAsset, asset_id)
    if asset is None or asset.tenant_id != tenant_id:
        return None
    return asset


async def list_relationships_for_asset(
    db: AsyncSession, *, tenant_id: uuid.UUID, asset_id: uuid.UUID, limit: int = 50
) -> list[CloudAssetRelationship]:
    limit = max(1, min(limit, 200))
    query = (
        select(CloudAssetRelationship)
        .where(
            CloudAssetRelationship.tenant_id == tenant_id,
            (CloudAssetRelationship.source_asset_id == asset_id)
            | (CloudAssetRelationship.target_asset_id == asset_id),
        )
        .limit(limit)
    )
    result = await db.execute(query)
    return list(result.scalars().all())
