"""EDP-009 Part 1, Section 8: the real AWS Discovery Adapter.

Every AWS call in this module goes through real `boto3` clients (the project's
newly-accepted AWS SDK dependency - see pyproject.toml) wrapped in
`asyncio.to_thread`, matching this codebase's own established convention for
synchronous SDK clients (see `gds_api/evidence.py`'s minio-py usage, and the
extensive `asyncio.to_thread`-wrapped git/subprocess calls in `tool_gateway.py`
and `gds_api/repository/`) - boto3 has no first-party async client, and this
project does not introduce a second async-SDK dependency (`aioboto3`) just for
this one provider.

Per this Part's own Section 49 honesty rule and the Phase 22 pre-build audit's
decisive finding: no live AWS credentials exist anywhere in this deployment
environment. Every real call this adapter makes will genuinely fail (most
commonly `NoCredentialsError`/`ClientError(InvalidClientTokenId)`) whenever
actually invoked here - that is the correct, honest behaviour, never
special-cased or faked into a successful result. Verified instead via
contract/fixture tests (`tests/test_aws_adapter.py`) using `botocore.stub.Stubber`
against real AWS response shapes - never described as live-provider
verification. See `docs/adr/0050-provider-neutral-cloud-foundation.md`'s
sub-phase addendum for the full design rationale.

Bounded scope, per Section 8's own explicit instruction ("Do not attempt every
AWS service in Part 1. Document unsupported services."): this adapter covers
exactly the 25 resource categories `CLOUD_PROVIDER_REGISTRY["aws"]` already
declares (`gds_api/cloud/providers.py`) - never a service beyond that list, and
every one of those 25 is implemented for real (no silent subset), each a
read-only `list`/`describe` call, never a mutation.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

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

# Adaptive retry mode + a bounded max attempt count together satisfy Section 39's
# "exponential backoff, jitter, maximum attempt count" requirement using
# botocore's own real, built-in retry machinery rather than a second, hand-rolled
# one - `tenacity` (already a project dependency) is not layered on top of this,
# since doing so would double-retry the same real throttling response.
_BOTO_CONFIG = Config(
    retries={"mode": "adaptive", "max_attempts": 6},
    connect_timeout=5,
    read_timeout=25,
)

# Real botocore/AWS error codes this adapter has actually observed documented in
# AWS's own API references, mapped to this Part's sanitized, provider-neutral
# category vocabulary (Section 7). Never a raw SDK exception surfaces past this
# module - see ProviderErrorCategory's own docstring for why.
_CLIENT_ERROR_CATEGORY: dict[str, ProviderErrorCategory] = {
    "AccessDenied": ProviderErrorCategory.PERMISSION_DENIED,
    "AccessDeniedException": ProviderErrorCategory.PERMISSION_DENIED,
    "UnauthorizedOperation": ProviderErrorCategory.PERMISSION_DENIED,
    "AuthorizationErrorException": ProviderErrorCategory.PERMISSION_DENIED,
    "ExpiredToken": ProviderErrorCategory.AUTHENTICATION_FAILED,
    "ExpiredTokenException": ProviderErrorCategory.AUTHENTICATION_FAILED,
    "InvalidClientTokenId": ProviderErrorCategory.AUTHENTICATION_FAILED,
    "UnrecognizedClientException": ProviderErrorCategory.AUTHENTICATION_FAILED,
    "AuthFailure": ProviderErrorCategory.AUTHENTICATION_FAILED,
    "SignatureDoesNotMatch": ProviderErrorCategory.AUTHENTICATION_FAILED,
    "InvalidSignatureException": ProviderErrorCategory.AUTHENTICATION_FAILED,
    "Throttling": ProviderErrorCategory.RATE_LIMITED,
    "ThrottlingException": ProviderErrorCategory.RATE_LIMITED,
    "RequestLimitExceeded": ProviderErrorCategory.RATE_LIMITED,
    "TooManyRequestsException": ProviderErrorCategory.RATE_LIMITED,
    "SlowDown": ProviderErrorCategory.RATE_LIMITED,
    "AWSOrganizationsNotInUseException": ProviderErrorCategory.SCOPE_NOT_FOUND,
    "OrganizationNotFoundException": ProviderErrorCategory.SCOPE_NOT_FOUND,
    "ResourceNotFoundException": ProviderErrorCategory.SCOPE_NOT_FOUND,
    "NoSuchEntity": ProviderErrorCategory.SCOPE_NOT_FOUND,
    "OptInRequired": ProviderErrorCategory.SERVICE_UNSUPPORTED,
    "SubscriptionRequiredException": ProviderErrorCategory.SERVICE_UNSUPPORTED,
    "InvalidAction": ProviderErrorCategory.SERVICE_UNSUPPORTED,
    "UnsupportedOperation": ProviderErrorCategory.SERVICE_UNSUPPORTED,
    "UnrecognizedClientException.RegionDisabledException": (
        ProviderErrorCategory.SERVICE_UNSUPPORTED
    ),
}


def _classify(exc: Exception) -> ProviderError:
    if isinstance(exc, ClientError):
        error = exc.response.get("Error", {}) if hasattr(exc, "response") else {}
        code = str(error.get("Code", "Unknown"))
        message = str(error.get("Message", str(exc)))
        category = _CLIENT_ERROR_CATEGORY.get(code, ProviderErrorCategory.UNKNOWN)
        retryable = category in (
            ProviderErrorCategory.RATE_LIMITED,
            ProviderErrorCategory.SERVICE_UNAVAILABLE,
            ProviderErrorCategory.TIMEOUT,
            ProviderErrorCategory.NETWORK_ERROR,
        )
        return ProviderError(
            category=category,
            sanitized_message=f"AWS {code}: {message}"[:500],
            retryable=retryable,
        )
    if isinstance(exc, BotoCoreError):
        text = str(exc)
        if "Unable to locate credentials" in text or "credentials" in text.lower():
            return ProviderError(
                category=ProviderErrorCategory.AUTHENTICATION_FAILED,
                sanitized_message="AWS: no usable credentials for this connection profile.",
                retryable=False,
            )
        endpoint_error = "Could not connect to the endpoint" in text
        endpoint_error = endpoint_error or "EndpointConnectionError" in type(exc).__name__
        if endpoint_error:
            return ProviderError(
                category=ProviderErrorCategory.NETWORK_ERROR,
                sanitized_message="AWS: could not connect to the requested regional endpoint.",
                retryable=True,
            )
        if "Read timeout" in text or "ConnectTimeoutError" in type(exc).__name__:
            return ProviderError(
                category=ProviderErrorCategory.TIMEOUT,
                sanitized_message="AWS: request timed out.",
                retryable=True,
            )
        return ProviderError(
            category=ProviderErrorCategory.UNKNOWN,
            sanitized_message=f"AWS SDK error: {text}"[:500],
            retryable=False,
        )
    return ProviderError(
        category=ProviderErrorCategory.UNKNOWN,
        sanitized_message=f"Unexpected error calling AWS: {exc}"[:500],
        retryable=False,
    )


def _build_session(profile: CloudConnectionProfile) -> boto3.Session:
    """Real cross-account role assumption (Section 8's own explicit requirement)
    when the profile declares a role to assume; otherwise the default credential
    chain, which - per this Part's own decisive pre-build-audit finding - resolves
    to no real credentials anywhere in this deployment, and so genuinely fails the
    first real call, honestly, rather than at session-construction time (boto3
    itself is lazy about credential resolution)."""
    if profile.role_or_principal_reference:
        base = boto3.Session()
        sts = base.client("sts", config=_BOTO_CONFIG)
        assume_kwargs: dict[str, Any] = {
            "RoleArn": profile.role_or_principal_reference,
            "RoleSessionName": "gds-security-os-discovery",
        }
        if profile.external_id:
            assume_kwargs["ExternalId"] = profile.external_id
        creds = sts.assume_role(**assume_kwargs)["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
    return boto3.Session()


def _next_page(iterator: Iterator[dict[str, Any]]) -> dict[str, Any] | None:
    return next(iterator, None)


async def _paginate(
    client: Any, operation: str, result_key: str, **kwargs: Any
) -> AsyncIterator[dict[str, Any]]:
    """Real page-at-a-time streaming (Section 41's own performance requirement -
    never buffer an entire account's inventory before the caller sees anything):
    each AWS page is fetched via one real `asyncio.to_thread` call, then its items
    are yielded individually, before the next page is fetched."""
    paginator = client.get_paginator(operation)
    page_iterator = iter(paginator.paginate(**kwargs))
    while True:
        page = await asyncio.to_thread(_next_page, page_iterator)
        if page is None:
            return
        for item in page.get(result_key, []) or []:
            yield item


def _tag_dict(raw_tags: Any) -> dict[str, str]:
    """AWS represents tags as a list of {"Key": ..., "Value": ...} dicts almost
    everywhere except a few services (e.g. S3) that use a differently-shaped
    TagSet - this handles the common [{"Key":k,"Value":v}] shape used by EC2/RDS/
    Lambda/ECS/EKS/KMS/etc."""
    if not raw_tags:
        return {}
    return {str(t.get("Key")): str(t.get("Value")) for t in raw_tags if t.get("Key") is not None}


class AWSProviderAdapter(ProviderAdapter):
    provider_id = "aws"

    async def validate_connection(
        self, profile: CloudConnectionProfile
    ) -> ConnectionValidationOutcome:
        start = datetime.now(UTC)
        try:
            session = await asyncio.to_thread(_build_session, profile)
            sts = session.client("sts", config=_BOTO_CONFIG)
            identity = await asyncio.to_thread(sts.get_caller_identity)
        except Exception as exc:  # noqa: BLE001 - classified below, never re-raised raw
            error = _classify(exc)
            latency_ms = (datetime.now(UTC) - start).total_seconds() * 1000
            return ConnectionValidationOutcome(
                success=False,
                provider_identity=None,
                scope_identity=None,
                capability_availability={},
                latency_ms=round(latency_ms, 1),
                error=error,
            )
        latency_ms = (datetime.now(UTC) - start).total_seconds() * 1000
        scope = ScopeIdentity(
            native_id=str(identity.get("Account", "")),
            display_name=str(identity.get("Arn", "")),
            environment_type="account",
        )
        return ConnectionValidationOutcome(
            success=True,
            provider_identity=str(identity.get("Arn", "")),
            scope_identity=scope,
            capability_availability={"sts:GetCallerIdentity": True},
            latency_ms=round(latency_ms, 1),
        )

    async def identify_scope(self, profile: CloudConnectionProfile) -> ScopeIdentity:
        session = await asyncio.to_thread(_build_session, profile)
        sts = session.client("sts", config=_BOTO_CONFIG)
        try:
            identity = await asyncio.to_thread(sts.get_caller_identity)
        except Exception as exc:  # noqa: BLE001 - re-raised as a classified ProviderError below
            error = _classify(exc)
            raise RuntimeError(error.sanitized_message) from exc
        return ScopeIdentity(
            native_id=str(identity.get("Account", "")),
            display_name=str(identity.get("Arn", "")),
            environment_type="account",
        )

    async def enumerate_child_environments(
        self, profile: CloudConnectionProfile
    ) -> list[ChildEnvironmentRef]:
        session = await asyncio.to_thread(_build_session, profile)
        org_client = session.client("organizations", config=_BOTO_CONFIG)
        refs: list[ChildEnvironmentRef] = []
        try:
            async for account in _paginate(org_client, "list_accounts", "Accounts"):
                refs.append(
                    ChildEnvironmentRef(
                        native_id=str(account.get("Id", "")),
                        display_name=str(account.get("Name", "")),
                        environment_type="account",
                        parent_native_id=None,
                    )
                )
        except Exception as exc:  # noqa: BLE001 - classified and re-raised, never swallowed silently
            error = _classify(exc)
            raise RuntimeError(error.sanitized_message) from exc
        return refs

    async def list_regions_or_locations(self, profile: CloudConnectionProfile) -> list[str]:
        session = await asyncio.to_thread(_build_session, profile)
        ec2 = session.client("ec2", config=_BOTO_CONFIG)
        try:
            result = await asyncio.to_thread(ec2.describe_regions, AllRegions=False)
        except Exception as exc:  # noqa: BLE001
            error = _classify(exc)
            raise RuntimeError(error.sanitized_message) from exc
        return sorted(str(r["RegionName"]) for r in result.get("Regions", []))

    def classify_provider_error(self, exc: Exception) -> ProviderError:
        return _classify(exc)

    def capability_matrix(self) -> CapabilityMatrix:
        provider_def = get_provider("aws")
        categories = provider_def.supported_resource_categories if provider_def else ()
        return CapabilityMatrix(
            provider_id="aws",
            can_validate_connection=True,
            can_enumerate_child_environments=True,
            can_list_regions=True,
            can_discover_assets=True,
            can_discover_relationships=True,
            supported_resource_categories=categories,
        )

    # ------------------------------------------------------------------
    # Discovery (Section 8) - see gds_api.cloud.adapters.aws_discovery for the
    # real, per-category implementations this module composes. Split into a
    # separate module purely for file size/readability - both are the same
    # adapter's real behaviour, never a second adapter.
    # ------------------------------------------------------------------

    async def discover_assets(
        self, profile: CloudConnectionProfile, scope_native_id: str
    ) -> AsyncIterator[NormalizedCloudAsset]:
        from gds_api.cloud.adapters.aws_discovery import discover_assets as _discover

        async for asset in _discover(profile, scope_native_id):
            yield asset

    async def discover_relationships(
        self, profile: CloudConnectionProfile, scope_native_id: str
    ) -> AsyncIterator[NormalizedCloudRelationship]:
        from gds_api.cloud.adapters.aws_discovery import discover_relationships as _discover

        async for relationship in _discover(profile, scope_native_id):
            yield relationship


register_adapter(AWSProviderAdapter())
