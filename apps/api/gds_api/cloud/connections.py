"""EDP-009 Part 1, Sections 3-5: governed CloudConnectionProfile management and
real, read-only connection validation. Never stores or returns a raw secret value -
`credential_reference` is always an opaque pointer (see CloudConnectionProfile's own
docstring); this module never resolves it to anything, since no secrets-manager
integration exists yet (disclosed limitation, see docs/guides/security-guide.md).
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.audit import record_audit_event
from gds_api.cloud.adapter import ProviderError, ProviderErrorCategory, get_adapter
from gds_api.cloud.providers import get_provider
from gds_api.logging_config import get_logger
from gds_api.metrics import cloud_connection_validations_total
from gds_api.models import CloudConnectionProfile, CloudConnectionValidation, CloudEnvironment

_logger = get_logger("gds_api.cloud.connections")


class CloudConnectionProfileNotFound(Exception):
    pass


class InvalidAuthenticationType(Exception):
    pass


async def create_connection_profile(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    created_by_user_id: uuid.UUID,
    environment_id: uuid.UUID,
    provider: str,
    authentication_type: str,
    credential_reference: str | None = None,
    role_or_principal_reference: str | None = None,
    external_id: str | None = None,
    permission_scope: str | None = None,
    read_only: bool = True,
) -> CloudConnectionProfile:
    provider_def = get_provider(provider)
    if provider_def is None:
        raise InvalidAuthenticationType(f"'{provider}' is not a real registered cloud provider")
    if authentication_type not in provider_def.supported_authentication_mechanisms:
        raise InvalidAuthenticationType(
            f"'{authentication_type}' is not a real authentication mechanism for "
            f"'{provider}' (expected one of {provider_def.supported_authentication_mechanisms})"
        )

    profile = CloudConnectionProfile(
        tenant_id=tenant_id,
        environment_id=environment_id,
        provider=provider,
        authentication_type=authentication_type,
        credential_reference=credential_reference,
        role_or_principal_reference=role_or_principal_reference,
        external_id=external_id,
        permission_scope=permission_scope,
        read_only=read_only,
        created_by_user_id=created_by_user_id,
        validation_status="never_validated",
    )
    db.add(profile)
    await db.flush()

    # A profile is useless to discovery/validation until the environment it was
    # created for actually points back at it - without this, CloudEnvironment.
    # connection_profile_id stays permanently null and every later real operation
    # against the environment (discovery, validation) fails closed as "no
    # connection profile configured", even though one plainly exists.
    environment = await db.get(CloudEnvironment, environment_id)
    if environment is not None:
        environment.connection_profile_id = profile.id
        await db.flush()

    await record_audit_event(
        db,
        tenant_id=tenant_id,
        user_id=created_by_user_id,
        action="cloud.connection_profile_created",
        detail={
            "connection_profile_id": str(profile.id),
            "environment_id": str(environment_id),
            "provider": provider,
            "authentication_type": authentication_type,
            # Never the credential_reference value itself in audit detail beyond
            # confirming one was set - matches the model's own "opaque pointer,
            # never resolved" contract.
            "credential_reference_set": credential_reference is not None,
        },
    )
    return profile


async def get_connection_profile(
    db: AsyncSession, *, tenant_id: uuid.UUID, connection_profile_id: uuid.UUID
) -> CloudConnectionProfile:
    profile = await db.get(CloudConnectionProfile, connection_profile_id)
    if profile is None or profile.tenant_id != tenant_id:
        raise CloudConnectionProfileNotFound("Cloud connection profile not found")
    return profile


async def validate_connection(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    connection_profile_id: uuid.UUID,
) -> CloudConnectionValidation:
    """Real, read-only connection test - never a destructive call, never a cloud
    mutation (Section 5). Honest by construction: if no real adapter is registered
    for this provider (true for every provider in this environment as of this
    sub-phase - see docs/reviews/phase-22-cloud-foundation-pre-build-audit.md), this
    returns a real failed CloudConnectionValidation row with a genuine, disclosed
    reason, never a simulated success (Section 49's own explicit rule)."""
    profile = await get_connection_profile(
        db, tenant_id=tenant_id, connection_profile_id=connection_profile_id
    )
    correlation_id = uuid.uuid4()
    start = time.perf_counter()
    attempted_at = datetime.now(UTC)

    adapter = get_adapter(profile.provider)
    if adapter is None:
        error = ProviderError(
            category=ProviderErrorCategory.SERVICE_UNAVAILABLE,
            sanitized_message=(
                f"No real provider adapter is available for '{profile.provider}' in "
                "this deployment yet - connection validation cannot run until one is "
                "built and registered."
            ),
            retryable=False,
        )
        validation = CloudConnectionValidation(
            tenant_id=tenant_id,
            connection_profile_id=connection_profile_id,
            provider_identity=None,
            scope_identity=None,
            status="error",
            attempted_at=attempted_at,
            completed_at=datetime.now(UTC),
            sanitized_error=error.sanitized_message,
            capability_availability={},
            latency_ms=round((time.perf_counter() - start) * 1000, 1),
            actor_user_id=actor_user_id,
            correlation_id=correlation_id,
        )
    else:
        try:
            outcome = await adapter.validate_connection(profile)
        except Exception as exc:  # noqa: BLE001 - classified and sanitized below, never re-raised raw
            classified = adapter.classify_provider_error(exc)
            _logger.warning(
                "cloud.connection_validation_failed",
                connection_profile_id=str(connection_profile_id),
                provider=profile.provider,
                error_category=classified.category.value,
                correlation_id=str(correlation_id),
            )
            validation = CloudConnectionValidation(
                tenant_id=tenant_id,
                connection_profile_id=connection_profile_id,
                status="error",
                attempted_at=attempted_at,
                completed_at=datetime.now(UTC),
                sanitized_error=classified.sanitized_message,
                capability_availability={},
                latency_ms=round((time.perf_counter() - start) * 1000, 1),
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
            )
        else:
            validation = CloudConnectionValidation(
                tenant_id=tenant_id,
                connection_profile_id=connection_profile_id,
                provider_identity=outcome.provider_identity,
                scope_identity=(
                    outcome.scope_identity.native_id if outcome.scope_identity else None
                ),
                status="success" if outcome.success else "failure",
                attempted_at=attempted_at,
                completed_at=datetime.now(UTC),
                sanitized_error=outcome.error.sanitized_message if outcome.error else None,
                capability_availability=dict(outcome.capability_availability),
                latency_ms=outcome.latency_ms,
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
            )

    db.add(validation)
    profile.validation_status = "valid" if validation.status == "success" else validation.status
    profile.last_validated_at = validation.completed_at
    await db.flush()
    cloud_connection_validations_total.labels(
        provider=profile.provider, status=validation.status
    ).inc()

    await record_audit_event(
        db,
        tenant_id=tenant_id,
        user_id=actor_user_id,
        action="cloud.connection_validated",
        detail={
            "connection_profile_id": str(connection_profile_id),
            "provider": profile.provider,
            "status": validation.status,
            "correlation_id": str(correlation_id),
        },
    )
    return validation


async def sync_environment_from_scope(
    db: AsyncSession, *, environment: CloudEnvironment, validation: CloudConnectionValidation
) -> None:
    """A successful validation may reveal the environment's own real native
    organisational path for the first time - update it honestly rather than leave a
    stale/empty value once it's actually known."""
    if validation.status != "success" or validation.scope_identity is None:
        return
    environment.status = "active"
