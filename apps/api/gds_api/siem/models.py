import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from gds_api.models import Base


class SIEMEvent(Base):
    __tablename__ = "siem_events"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    source: Mapped[str] = mapped_column(String(200))  # system name that sent the log
    source_type: Mapped[str] = mapped_column(String(100))  # firewall, edr, cloud, app, network, auth
    event_category: Mapped[str] = mapped_column(String(100))  # authentication, network, system, security, audit
    severity: Mapped[str] = mapped_column(String(50), default="info")  # info, low, medium, high, critical
    raw_data: Mapped[dict] = mapped_column(JSONB, default=dict)  # original log
    normalized: Mapped[dict] = mapped_column(JSONB, default=dict)  # normalized fields
    src_ip: Mapped[str | None] = mapped_column(String(45), default=None)
    dst_ip: Mapped[str | None] = mapped_column(String(45), default=None)
    src_port: Mapped[int | None] = mapped_column(default=None)
    dst_port: Mapped[int | None] = mapped_column(default=None)
    protocol: Mapped[str | None] = mapped_column(String(20), default=None)
    user: Mapped[str | None] = mapped_column(String(200), default=None)
    action: Mapped[str | None] = mapped_column(String(200), default=None)
    result: Mapped[str | None] = mapped_column(String(100), default=None)  # success, failure, blocked
    country: Mapped[str | None] = mapped_column(String(100), default=None)  # geo-enriched
    threat_intel_match: Mapped[bool] = mapped_column(default=False)
    correlated: Mapped[bool] = mapped_column(default=False)
    correlation_id: Mapped[uuid.UUID | None] = mapped_column(default=None)
    event_time: Mapped[datetime] = mapped_column(server_default=func.now())  # when the event occurred
    ingested_at: Mapped[datetime] = mapped_column(server_default=func.now())  # when we received it


class CorrelationRule(Base):
    __tablename__ = "siem_correlation_rules"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text, default=None)
    rule_type: Mapped[str] = mapped_column(String(100))  # threshold, sequence, aggregation, mitre_match
    conditions: Mapped[dict] = mapped_column(JSONB, default=dict)  # {field: value, ...}
    time_window_seconds: Mapped[int] = mapped_column(default=300)  # lookback window
    threshold: Mapped[int] = mapped_column(default=1)  # how many matches needed
    severity: Mapped[str] = mapped_column(String(50), default="high")
    mitre_technique: Mapped[str | None] = mapped_column(String(50), default=None)  # T-ID
    is_active: Mapped[bool] = mapped_column(default=True)
    fire_count: Mapped[int] = mapped_column(default=0)
    last_fired: Mapped[datetime | None] = mapped_column(default=None)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class CorrelatedIncident(Base):
    __tablename__ = "siem_correlated_incidents"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    rule_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("siem_correlation_rules.id"))
    rule_name: Mapped[str] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(50))
    event_ids: Mapped[list] = mapped_column(JSONB, default=list)  # list of SIEMEvent IDs
    event_count: Mapped[int] = mapped_column(default=0)
    summary: Mapped[str] = mapped_column(Text)
    mitre_technique: Mapped[str | None] = mapped_column(String(50), default=None)
    status: Mapped[str] = mapped_column(String(50), default="open")  # open, investigating, resolved, false_positive
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    resolved_at: Mapped[datetime | None] = mapped_column(default=None)
