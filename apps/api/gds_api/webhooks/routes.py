"""GDS OS Webhook Gateway — Routes."""
from __future__ import annotations

import json
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.db import get_db
from gds_api.security import CurrentUser
from gds_api.webhooks.gateway import (
    WebhookEndpoint,
    WebhookEvent,
    create_endpoint,
    verify_and_process,
)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


class CreateEndpointRequest(BaseModel):
    name: str
    source_type: str
    secret: str | None = None
    events: list[str] | None = None


@router.post("/endpoints", status_code=status.HTTP_201_CREATED)
async def create_webhook_endpoint(body: CreateEndpointRequest, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    ep = await create_endpoint(db, user.tenant_id, body.name, body.source_type, body.secret, body.events)
    await db.commit()
    return {"id": str(ep.id), "name": ep.name, "source_type": ep.source_type, "secret_hint": ep.secret_hint}


@router.get("/endpoints")
async def list_endpoints(db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> list[dict]:
    q = select(WebhookEndpoint).where(WebhookEndpoint.tenant_id == user.tenant_id).order_by(WebhookEndpoint.created_at.desc())
    result = await db.execute(q)
    return [
        {"id": str(e.id), "name": e.name, "source_type": e.source_type,
         "events_subscribed": e.events_subscribed, "is_active": e.is_active,
         "delivery_count": e.delivery_count, "failure_count": e.failure_count,
         "last_delivery": e.last_delivery.isoformat() if e.last_delivery else None}
        for e in result.scalars().all()
    ]


@router.get("/endpoints/{endpoint_id}")
async def get_endpoint(endpoint_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    q = select(WebhookEndpoint).where(WebhookEndpoint.id == endpoint_id, WebhookEndpoint.tenant_id == user.tenant_id)
    e = (await db.execute(q)).scalar_one_or_none()
    if not e:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return {"id": str(e.id), "name": e.name, "source_type": e.source_type,
            "events_subscribed": e.events_subscribed, "is_active": e.is_active,
            "delivery_count": e.delivery_count, "failure_count": e.failure_count,
            "last_delivery": e.last_delivery.isoformat() if e.last_delivery else None}


@router.delete("/endpoints/{endpoint_id}")
async def delete_endpoint(endpoint_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    q = select(WebhookEndpoint).where(WebhookEndpoint.id == endpoint_id, WebhookEndpoint.tenant_id == user.tenant_id)
    e = (await db.execute(q)).scalar_one_or_none()
    if not e:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    e.is_active = False
    await db.commit()
    return {"id": str(endpoint_id), "status": "deactivated"}


@router.post("/ingest/{endpoint_id}")
async def ingest_webhook(endpoint_id: uuid.UUID, request: Request, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    """Receive a webhook from an external tool."""
    raw_body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256") or request.headers.get("X-Signature") or ""
    event_type = request.headers.get("X-GitHub-Event") or request.headers.get("X-Snyk-Event") or request.headers.get("X-Event-Type") or "unknown"
    event_id = request.headers.get("X-GitHub-Delivery") or request.headers.get("X-Event-ID")
    headers = dict(request.headers)

    # Try to get secret from endpoint config (in production, would use vault/secrets manager)
    secret = request.headers.get("X-Webhook-Secret", "")

    result = await verify_and_process(db, user.tenant_id, endpoint_id, raw_body, signature or None, event_type, event_id, headers, secret or None)
    await db.commit()
    return result


@router.get("/events")
async def list_events(source_type: str | None = None, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> list[dict]:
    q = select(WebhookEvent).where(WebhookEvent.tenant_id == user.tenant_id)
    if source_type:
        q = q.where(WebhookEvent.source_type == source_type)
    q = q.order_by(WebhookEvent.received_at.desc()).limit(100)
    result = await db.execute(q)
    return [
        {"id": str(e.id), "source_type": e.source_type, "event_type": e.event_type,
         "signature_valid": e.signature_valid, "processed": e.processed,
         "processing_result": e.processing_result, "routed_to": e.routed_to,
         "error_message": e.error_message,
         "received_at": e.received_at.isoformat() if e.received_at else None}
        for e in result.scalars().all()
    ]


@router.get("/events/{event_id}")
async def get_event(event_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: CurrentUser = Depends) -> dict:
    q = select(WebhookEvent).where(WebhookEvent.id == event_id, WebhookEvent.tenant_id == user.tenant_id)
    e = (await db.execute(q)).scalar_one_or_none()
    if not e:
        raise HTTPException(status_code=404, detail="Event not found")
    return {"id": str(e.id), "source_type": e.source_type, "event_type": e.event_type,
            "event_id": e.event_id, "payload": e.payload, "headers": e.headers,
            "signature_valid": e.signature_valid, "processed": e.processed,
            "processing_result": e.processing_result, "routed_to": e.routed_to,
            "error_message": e.error_message,
            "received_at": e.received_at.isoformat() if e.received_at else None,
            "processed_at": e.processed_at.isoformat() if e.processed_at else None}


@router.get("/supported-sources")
async def list_supported_sources() -> dict[str, Any]:
    from gds_api.webhooks.gateway import EVENT_ROUTES
    return {source: {"events": list(events.keys())} for source, events in EVENT_ROUTES.items()}
