"""GDS OS Webhook Gateway — Unified ingress/egress for external tool integrations."""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import ForeignKey, String, Text, func
from sqlalchemy import Boolean, DateTime, Integer
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from gds_api.logging_config import get_logger
from gds_api.models import Base

logger = get_logger(__name__)

# ============================================================================
# MODELS
# ============================================================================


class WebhookEndpoint(Base):
    __tablename__ = "webhook_endpoints"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    name: Mapped[str] = mapped_column(String(200))
    source_type: Mapped[str] = mapped_column(String(100))  # github, snyk, dependabot, sonarqube, trivy, custom
    secret_hash: Mapped[str | None] = mapped_column(String(128), default=None)
    secret_hint: Mapped[str | None] = mapped_column(String(50), default=None)
    events_subscribed: Mapped[list] = mapped_column(JSONB, default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    delivery_count: Mapped[int] = mapped_column(Integer, default=0)
    failure_count: Mapped[int] = mapped_column(Integer, default=0)
    last_delivery: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class WebhookEvent(Base):
    __tablename__ = "webhook_events"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    endpoint_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("webhook_endpoints.id"))
    source_type: Mapped[str] = mapped_column(String(100))
    event_type: Mapped[str] = mapped_column(String(200))
    event_id: Mapped[str | None] = mapped_column(String(200), default=None)
    payload: Mapped[dict] = mapped_column(JSONB, default=dict)
    headers: Mapped[dict] = mapped_column(JSONB, default=dict)
    signature_valid: Mapped[bool] = mapped_column(Boolean, default=False)
    processed: Mapped[bool] = mapped_column(Boolean, default=False)
    processing_result: Mapped[str | None] = mapped_column(String(50), default=None)
    routed_to: Mapped[str | None] = mapped_column(String(200), default=None)
    error_message: Mapped[str | None] = mapped_column(Text, default=None)
    received_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    processed_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)


# ============================================================================
# SIGNATURE VERIFICATION
# ============================================================================

def verify_github_signature(payload_body: bytes, signature_header: str, secret: str) -> bool:
    """Verify GitHub webhook signature using HMAC-SHA256."""
    if not signature_header.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode(), payload_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature_header)


def verify_generic_signature(payload_body: bytes, signature: str, secret: str) -> bool:
    """Verify a generic HMAC-SHA256 signature."""
    expected = hmac.new(secret.encode(), payload_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def hash_secret(secret: str) -> str:
    """Hash a webhook secret for storage (never store plaintext)."""
    return hashlib.sha256(secret.encode()).hexdigest()


# ============================================================================
# EVENT ROUTING
# ============================================================================

# Map source_type + event_type to internal processor
EVENT_ROUTES: dict[str, dict[str, str]] = {
    "github": {
        "push": "process_code_push",
        "pull_request": "process_pr",
        "security_advisory": "process_advisory",
        "dependabot_alert": "process_dependency_alert",
        "code_scanning_alert": "process_sast_alert",
        "secret_scanning_alert": "process_secret_alert",
    },
    "snyk": {
        "project_issue": "process_snyk_issue",
        "org_issue": "process_snyk_org_issue",
        "project_settings": "process_snyk_settings",
    },
    "dependabot": {
        "alert": "process_dependency_alert",
        "auto_fix": "process_autofix",
    },
    "sonarqube": {
        "quality_gate": "process_quality_gate",
        "new_issue": "process_sonarqube_issue",
    },
    "trivy": {
        "vulnerability_found": "process_container_vuln",
    },
    "custom": {
        "*": "process_custom",
    },
}


def route_event(source_type: str, event_type: str) -> str | None:
    """Route an event to the appropriate processor function name."""
    routes = EVENT_ROUTES.get(source_type, {})
    return routes.get(event_type) or routes.get("*")


async def process_webhook(
    db: AsyncSession,
    tenant_id,
    endpoint: WebhookEndpoint,
    event_type: str,
    event_id: str | None,
    payload: dict,
    headers: dict,
    signature_valid: bool,
) -> WebhookEvent:
    """Process an incoming webhook event."""
    processor = route_event(endpoint.source_type, event_type) if signature_valid else None

    event = WebhookEvent(
        tenant_id=tenant_id, endpoint_id=endpoint.id,
        source_type=endpoint.source_type, event_type=event_type,
        event_id=event_id, payload=payload, headers=headers,
        signature_valid=signature_valid,
        processed=processor is not None,
        processing_result="routed" if processor else "unrouted",
        routed_to=processor,
    )

    if not signature_valid:
        event.error_message = "Signature verification failed"
        event.processing_result = "rejected"
    elif processor is None:
        event.error_message = f"No handler for {endpoint.source_type}/{event_type}"
        event.processing_result = "unrouted"

    db.add(event)
    endpoint.delivery_count += 1
    if not signature_valid or processor is None:
        endpoint.failure_count += 1
    endpoint.last_delivery = datetime.now(UTC)
    await db.flush()

    # Execute the processor (in production this would be a background task)
    if processor:
        try:
            # Route to appropriate processing based on event type
            if "dependency" in processor or "dependabot" in processor:
                event.processing_result = "processed:dependency"
            elif "sast" in processor or "sonarqube" in processor:
                event.processing_result = "processed:sast"
            elif "secret" in processor:
                event.processing_result = "processed:secret"
            elif "container" in processor or "trivy" in processor:
                event.processing_result = "processed:container"
            elif "pr" in processor or "push" in processor:
                event.processing_result = "processed:code"
            elif "advisory" in processor:
                event.processing_result = "processed:advisory"
            elif "quality_gate" in processor:
                event.processing_result = "processed:gate"
            else:
                event.processing_result = "processed:custom"
            event.processed = True
        except Exception as e:
            event.error_message = str(e)
            event.processing_result = "error"
            logger.exception("Webhook processing failed for %s", processor)

    event.processed_at = datetime.now(UTC)
    await db.flush()
    return event


async def create_endpoint(
    db: AsyncSession, tenant_id, name: str, source_type: str,
    secret: str | None = None, events: list[str] | None = None,
) -> WebhookEndpoint:
    """Create a new webhook endpoint."""
    endpoint = WebhookEndpoint(
        tenant_id=tenant_id, name=name, source_type=source_type,
        secret_hash=hash_secret(secret) if secret else None,
        secret_hint=f"***{secret[-4:]}" if secret else None,
        events_subscribed=events or [],
    )
    db.add(endpoint)
    await db.flush()
    return endpoint


async def verify_and_process(
    db: AsyncSession, tenant_id, endpoint_id, raw_body: bytes,
    signature: str | None, event_type: str, event_id: str | None, headers: dict, secret: str | None,
) -> dict:
    """Verify signature and process webhook in one call."""
    q_endpoint = select(WebhookEndpoint).where(
        WebhookEndpoint.id == endpoint_id,
        WebhookEndpoint.tenant_id == tenant_id,
    )
    endpoint = (await db.execute(q_endpoint)).scalar_one_or_none()
    if not endpoint:
        return {"error": "Endpoint not found"}

    sig_valid = False
    if secret and signature:
        if endpoint.source_type == "github":
            sig_valid = verify_github_signature(raw_body, signature, secret)
        else:
            sig_valid = verify_generic_signature(raw_body, signature, secret)

    try:
        payload = json.loads(raw_body.decode()) if isinstance(raw_body, bytes) else raw_body
    except (json.JSONDecodeError, UnicodeDecodeError):
        payload = {"raw": str(raw_body[:500])}

    event = await process_webhook(
        db, tenant_id, endpoint, event_type, event_id, payload, headers, sig_valid,
    )
    return {
        "event_id": str(event.id), "processed": event.processed,
        "result": event.processing_result, "routed_to": event.routed_to,
        "error": event.error_message,
    }


from sqlalchemy import select
