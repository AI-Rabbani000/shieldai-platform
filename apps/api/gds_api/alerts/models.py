"""GDS OS Real-time Alerting Pipeline — Models."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy import Boolean, Integer
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from gds_api.models import Base


class AlertRule(Base):
    __tablename__ = "alert_rules"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text, default=None)
    entity_type: Mapped[str] = mapped_column(String(100))
    condition_field: Mapped[str] = mapped_column(String(200))
    condition_operator: Mapped[str] = mapped_column(String(50))
    condition_value: Mapped[str] = mapped_column(String(500))
    severity: Mapped[str] = mapped_column(String(50))
    channels: Mapped[list] = mapped_column(JSONB, default=list)
    cooldown_minutes: Mapped[int] = mapped_column(Integer, default=30)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_fired: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    fire_count: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class AlertEvent(Base):
    __tablename__ = "alert_events"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    rule_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("alert_rules.id"))
    rule_name: Mapped[str] = mapped_column(String(200))
    entity_type: Mapped[str] = mapped_column(String(100))
    entity_id: Mapped[str] = mapped_column(String(200))
    entity_title: Mapped[str] = mapped_column(String(500))
    severity: Mapped[str] = mapped_column(String(50))
    channels_dispatched: Mapped[list] = mapped_column(JSONB, default=list)
    delivery_results: Mapped[dict] = mapped_column(JSONB, default=dict)
    status: Mapped[str] = mapped_column(String(50), default="dispatched")
    acknowledged_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), default=None)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
