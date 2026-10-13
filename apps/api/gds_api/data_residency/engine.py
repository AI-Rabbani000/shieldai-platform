"""GDS OS Data Residency — Regional data compliance engine.

Enforces data localization requirements per GDPR, DORA, NIS2, and regional laws.
Tracks data zones, classification, residency rules, and compliance status.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import ForeignKey, String, Text, func
from sqlalchemy import Boolean, DateTime, Integer
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import select

from gds_api.logging_config import get_logger
from gds_api.models import Base

logger = get_logger(__name__)

# ============================================================================
# MODELS
# ============================================================================


class DataResidencyZone(Base):
    __tablename__ = "data_residency_zones"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    zone_name: Mapped[str] = mapped_column(String(100))  # eu, us, uk, apac, middle_east, global
    region: Mapped[str] = mapped_column(String(100))  # eu-west-1, us-east-1, etc
    country: Mapped[str] = mapped_column(String(100))
    data_classification: Mapped[str] = mapped_column(String(100))  # public, internal, confidential, restricted, pii, phi
    storage_endpoint: Mapped[str | None] = mapped_column(String(500), default=None)
    encryption_required: Mapped[bool] = mapped_column(Boolean, default=True)
    cross_border_allowed: Mapped[bool] = mapped_column(Boolean, default=False)
    allowed_destinations: Mapped[list] = mapped_column(JSONB, default=list)
    regulatory_basis: Mapped[str | None] = mapped_column(Text, default=None)  # GDPR Art.44, DORA Art.x
    retention_days: Mapped[int] = mapped_column(Integer, default=365)
    is_primary: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class DataResidencyRule(Base):
    __tablename__ = "data_residency_rules"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    rule_name: Mapped[str] = mapped_column(String(200))
    data_type: Mapped[str] = mapped_column(String(100))  # pii, phi, financial, secrets, audit_logs, telemetry
    required_zone: Mapped[str] = mapped_column(String(100))  # eu, us, uk, etc
    blocked_zones: Mapped[list] = mapped_column(JSONB, default=list)
    encryption_at_rest: Mapped[bool] = mapped_column(Boolean, default=True)
    encryption_in_transit: Mapped[bool] = mapped_column(Boolean, default=True)
    anonymization_required: Mapped[bool] = mapped_column(Boolean, default=False)
    retention_days: Mapped[int] = mapped_column(Integer, default=365)
    regulatory_basis: Mapped[str | None] = mapped_column(Text, default=None)
    violation_action: Mapped[str] = mapped_column(String(100), default="block")  # block, warn, log
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class DataMovementLog(Base):
    __tablename__ = "data_movement_logs"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    source_zone: Mapped[str] = mapped_column(String(100))
    dest_zone: Mapped[str] = mapped_column(String(100))
    data_type: Mapped[str] = mapped_column(String(100))
    data_classification: Mapped[str] = mapped_column(String(100))
    volume_mb: Mapped[int] = mapped_column(Integer, default=0)
    rule_evaluated: Mapped[str | None] = mapped_column(String(200), default=None)
    decision: Mapped[str] = mapped_column(String(50))  # allowed, blocked, warned
    reason: Mapped[str | None] = mapped_column(Text, default=None)
    entity_type: Mapped[str | None] = mapped_column(String(100), default=None)
    entity_id: Mapped[str | None] = mapped_column(String(200), default=None)
    occurred_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


# ============================================================================
# REGULATORY PRESETS
# ============================================================================

REGULATORY_PRESETS: dict[str, dict[str, Any]] = {
    "GDPR": {
        "description": "EU General Data Protection Regulation",
        "required_zone": "eu",
        "blocked_zones": ["us", "apac"] ,
        "cross_border_allowed": False,
        "encryption_at_rest": True,
        "encryption_in_transit": True,
        "anonymization_required": True,
        "retention_days": 365,
        "regulatory_basis": "GDPR Art.44 (cross-border data transfers), Art.32 (security of processing)",
        "data_types": ["pii", "financial", "audit_logs"],
        "violation_action": "block",
    },
    "DORA": {
        "description": "Digital Operational Resilience Act",
        "required_zone": "eu",
        "blocked_zones": [],
        "cross_border_allowed": True,
        "encryption_at_rest": True,
        "encryption_in_transit": True,
        "anonymization_required": False,
        "retention_days": 1825,  # 5 years for ICT records
        "regulatory_basis": "DORA Art.6 (protection and prevention), Art.11 (testing)",
        "data_types": ["audit_logs", "telemetry", "financial"],
        "violation_action": "warn",
    },
    "NIS2": {
        "description": "Network and Information Security Directive 2",
        "required_zone": "eu",
        "blocked_zones": [],
        "cross_border_allowed": True,
        "encryption_at_rest": True,
        "encryption_in_transit": True,
        "anonymization_required": False,
        "retention_days": 1095,  # 3 years
        "regulatory_basis": "NIS2 Art.21 (security measures), Art.23 (incident reporting)",
        "data_types": ["audit_logs", "telemetry"],
        "violation_action": "warn",
    },
    "EU_AI_ACT": {
        "description": "EU AI Act",
        "required_zone": "eu",
        "blocked_zones": [],
        "cross_border_allowed": True,
        "encryption_at_rest": True,
        "encryption_in_transit": True,
        "anonymization_required": True,
        "retention_days": 365,
        "regulatory_basis": "EU AI Act Art.10 (data governance), Art.12 (human oversight)",
        "data_types": ["pii", "telemetry"],
        "violation_action": "block",
    },
    "CCPA": {
        "description": "California Consumer Privacy Act",
        "required_zone": "us",
        "blocked_zones": [],
        "cross_border_allowed": True,
        "encryption_at_rest": True,
        "encryption_in_transit": True,
        "anonymization_required": False,
        "retention_days": 730,
        "regulatory_basis": "CCPA §1798.100 (consumer rights)",
        "data_types": ["pii"],
        "violation_action": "warn",
    },
    "PDPA_SG": {
        "description": "Singapore Personal Data Protection Act",
        "required_zone": "apac",
        "blocked_zones": [],
        "cross_border_allowed": True,
        "encryption_at_rest": True,
        "encryption_in_transit": True,
        "anonymization_required": False,
        "retention_days": 365,
        "regulatory_basis": "PDPA §26 (transfer limitation)",
        "data_types": ["pii", "financial"],
        "violation_action": "warn",
    },
}


# ============================================================================
# ENGINE FUNCTIONS
# ============================================================================


async def create_zone(
    db: AsyncSession, tenant_id, zone_name: str, region: str, country: str,
    data_classification: str = "internal", storage_endpoint: str | None = None,
    cross_border_allowed: bool = False, regulatory_basis: str | None = None,
    retention_days: int = 365, is_primary: bool = False,
) -> DataResidencyZone:
    """Create a data residency zone."""
    if is_primary:
        q = select(DataResidencyZone).where(
            DataResidencyZone.tenant_id == tenant_id,
            DataResidencyZone.is_primary == True,  # noqa: E712
        )
        for z in (await db.execute(q)).scalars().all():
            z.is_primary = False

    zone = DataResidencyZone(
        tenant_id=tenant_id, zone_name=zone_name, region=region, country=country,
        data_classification=data_classification, storage_endpoint=storage_endpoint,
        cross_border_allowed=cross_border_allowed,
        regulatory_basis=regulatory_basis, retention_days=retention_days,
        is_primary=is_primary,
    )
    db.add(zone)
    await db.flush()
    return zone


async def create_rule_from_preset(
    db: AsyncSession, tenant_id, regulation: str, data_type: str | None = None,
) -> list[DataResidencyRule]:
    """Create residency rules from a regulatory preset."""
    preset = REGULATORY_PRESETS.get(regulation)
    if not preset:
        return []

    rules = []
    types = [data_type] if data_type else preset["data_types"]
    for dt in types:
        rule = DataResidencyRule(
            tenant_id=tenant_id, rule_name=f"{regulation} — {dt}",
            data_type=dt, required_zone=preset["required_zone"],
            blocked_zones=preset["blocked_zones"],
            encryption_at_rest=preset["encryption_at_rest"],
            encryption_in_transit=preset["encryption_in_transit"],
            anonymization_required=preset["anonymization_required"],
            retention_days=preset["retention_days"],
            regulatory_basis=preset["regulatory_basis"],
            violation_action=preset["violation_action"],
            is_active=True,
        )
        db.add(rule)
        rules.append(rule)
    await db.flush()
    return rules


async def evaluate_data_movement(
    db: AsyncSession, tenant_id, source_zone: str, dest_zone: str,
    data_type: str, data_classification: str = "internal",
    volume_mb: int = 0, entity_type: str | None = None, entity_id: str | None = None,
) -> dict[str, Any]:
    """Evaluate if a data movement is allowed under residency rules."""
    q = select(DataResidencyRule).where(
        DataResidencyRule.tenant_id == tenant_id,
        DataResidencyRule.data_type == data_type,
        DataResidencyRule.is_active == True,  # noqa: E712
    )
    rules = (await db.execute(q)).scalars().all()

    decision = "allowed"
    reason = None
    matched_rule = None

    for rule in rules:
        matched_rule = rule.rule_name
        if dest_zone in (rule.blocked_zones or []):
            if rule.violation_action == "block":
                decision = "blocked"
                reason = f"Destination {dest_zone} is blocked by {rule.rule_name}"
            elif rule.violation_action == "warn":
                decision = "warned"
                reason = f"Destination {dest_zone} is flagged by {rule.rule_name}"
            break
        if rule.required_zone and dest_zone != rule.required_zone and source_zone != rule.required_zone:
            if rule.violation_action == "block":
                decision = "blocked"
                reason = f"Data type {data_type} must reside in {rule.required_zone} per {rule.rule_name}"
            elif rule.violation_action == "warn":
                decision = "warned"
                reason = f"Data type {data_type} should reside in {rule.required_zone} per {rule.rule_name}"
            break

    # Log the movement
    log = DataMovementLog(
        tenant_id=tenant_id, source_zone=source_zone, dest_zone=dest_zone,
        data_type=data_type, data_classification=data_classification,
        volume_mb=volume_mb, rule_evaluated=matched_rule,
        decision=decision, reason=reason,
        entity_type=entity_type, entity_id=entity_id,
    )
    db.add(log)
    await db.flush()

    return {"decision": decision, "reason": reason, "rule": matched_rule, "log_id": str(log.id)}


async def get_residency_summary(db: AsyncSession, tenant_id) -> dict[str, Any]:
    """Get a summary of the tenant's data residency posture."""
    zones = (await db.execute(
        select(DataResidencyZone).where(DataResidencyZone.tenant_id == tenant_id)
    )).scalars().all()
    rules = (await db.execute(
        select(DataResidencyRule).where(DataResidencyRule.tenant_id == tenant_id)
    )).scalars().all()
    logs = (await db.execute(
        select(DataMovementLog).where(DataMovementLog.tenant_id == tenant_id).order_by(
            DataMovementLog.occurred_at.desc()
        ).limit(50)
    )).scalars().all()

    blocked = sum(1 for l in logs if l.decision == "blocked")
    warned = sum(1 for l in logs if l.decision == "warned")
    allowed = sum(1 for l in logs if l.decision == "allowed")

    return {
        "total_zones": len(zones),
        "active_zones": [z.zone_name for z in zones if z.is_active],
        "primary_zone": next((z.zone_name for z in zones if z.is_primary), None),
        "total_rules": len(rules),
        "active_rules": sum(1 for r in rules if r.is_active),
        "regulations_covered": list(set(r.rule_name.split(" — ")[0] for r in rules if " — " in r.rule_name)),
        "recent_movements": len(logs),
        "blocked_movements": blocked,
        "warned_movements": warned,
        "allowed_movements": allowed,
        "compliance_rate": round(allowed / max(len(logs), 1) * 100, 1),
    }
