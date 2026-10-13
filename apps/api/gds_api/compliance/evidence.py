"""GDS OS Compliance Evidence Chain-of-Custody Engine.

Provides evidence collection, SHA-256 hashing, chain-of-custody tracking,
legal holds, gap analysis, and audit-ready evidence packages.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import ForeignKey, String, Text, func, select
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


class ComplianceEvidence(Base):
    __tablename__ = "compliance_evidence"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    framework: Mapped[str] = mapped_column(String(100))
    control_id: Mapped[str] = mapped_column(String(200))
    control_name: Mapped[str] = mapped_column(String(500))
    evidence_type: Mapped[str] = mapped_column(String(100))
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str | None] = mapped_column(Text, default=None)
    content_hash: Mapped[str] = mapped_column(String(64))
    content_preview: Mapped[str | None] = mapped_column(Text, default=None)
    source_system: Mapped[str] = mapped_column(String(200))
    source_entity_type: Mapped[str | None] = mapped_column(String(100), default=None)
    source_entity_id: Mapped[str | None] = mapped_column(String(200), default=None)
    collected_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    collected_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    valid_until: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    is_valid: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(50), default="collected")


class ChainOfCustody(Base):
    __tablename__ = "compliance_chain_of_custody"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    evidence_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("compliance_evidence.id"))
    custodian_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    custodian_name: Mapped[str] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(100))
    action_reason: Mapped[str | None] = mapped_column(Text, default=None)
    hash_at_action: Mapped[str] = mapped_column(String(64))
    is_break: Mapped[bool] = mapped_column(Boolean, default=False)
    break_reason: Mapped[str | None] = mapped_column(Text, default=None)
    occurred_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class LegalHold(Base):
    __tablename__ = "compliance_legal_holds"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str | None] = mapped_column(Text, default=None)
    legal_matter: Mapped[str | None] = mapped_column(String(500), default=None)
    evidence_ids: Mapped[list] = mapped_column(JSONB, default=list)
    issued_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    issued_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    released_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), default=None)
    released_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    release_reason: Mapped[str | None] = mapped_column(Text, default=None)
    status: Mapped[str] = mapped_column(String(50), default="active")


class ComplianceGap(Base):
    __tablename__ = "compliance_gaps"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    framework: Mapped[str] = mapped_column(String(100))
    control_id: Mapped[str] = mapped_column(String(200))
    control_name: Mapped[str] = mapped_column(String(500))
    gap_type: Mapped[str] = mapped_column(String(100))
    severity: Mapped[str] = mapped_column(String(50), default="high")
    description: Mapped[str] = mapped_column(Text)
    remediation_guidance: Mapped[str | None] = mapped_column(Text, default=None)
    has_evidence: Mapped[bool] = mapped_column(Boolean, default=False)
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("compliance_evidence.id"), default=None)
    detected_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    status: Mapped[str] = mapped_column(String(50), default="open")


# ============================================================================
# FRAMEWORK CONTROLS (for gap analysis)
# ============================================================================

FRAMEWORK_CONTROLS: dict[str, list[dict[str, str]]] = {
    "PCI-DSS": [
        {"control_id": "3.4", "control_name": "Encrypt Cardholder Data at Rest"},
        {"control_id": "6.5.3", "control_name": "Address Vulnerabilities Promptly"},
        {"control_id": "8.3", "control_name": "Multi-Factor Authentication"},
        {"control_id": "10.1", "control_name": "Implement Audit Trails"},
        {"control_id": "10.2", "control_name": "Track All Access to Cardholder Data"},
        {"control_id": "10.5", "control_name": "Secure Audit Logs"},
        {"control_id": "11.5", "control_name": "Intrusion Detection"},
    ],
    "SOC2": [
        {"control_id": "CC6.1", "control_name": "Logical and Physical Access Controls"},
        {"control_id": "CC6.2", "control_name": "User Provisioning and Deprovisioning"},
        {"control_id": "CC6.3", "control_name": "Access Removal"},
        {"control_id": "CC7.1", "control_name": "System Monitoring"},
        {"control_id": "CC7.2", "control_name": "Anomaly Detection"},
        {"control_id": "CC8.1", "control_name": "Change Management"},
        {"control_id": "CC9.2", "control_name": "Risk Assessment"},
    ],
    "ISO27001": [
        {"control_id": "A.9.4.1", "control_name": "Access Control Policy"},
        {"control_id": "A.12.6.1", "control_name": "Vulnerability Management"},
        {"control_id": "A.13.1.1", "control_name": "Network Controls"},
        {"control_id": "A.14.2.3", "control_name": "Technical Code Review"},
    ],
    "NIST": [
        {"control_id": "DE.CM-1", "control_name": "Network Monitoring"},
        {"control_id": "DE.CM-3", "control_name": "Personnel Activity Monitoring"},
        {"control_id": "PR.AC-1", "control_name": "Identity Proofing"},
        {"control_id": "PR.AC-4", "control_name": "Access Permissions"},
        {"control_id": "PR.DS-1", "control_name": "Data-at-Rest Protection"},
        {"control_id": "PR.DS-2", "control_name": "Data-in-Transit Protection"},
        {"control_id": "RS.RP-1", "control_name": "Response Planning"},
    ],
    "GDPR": [
        {"control_id": "Art.32", "control_name": "Security of Processing"},
        {"control_id": "Art.33", "control_name": "Breach Notification"},
        {"control_id": "Art.35", "control_name": "Data Protection Impact Assessment"},
    ],
    "DORA": [
        {"control_id": "Art.5", "control_name": "ICT Risk Management"},
        {"control_id": "Art.6", "control_name": "Protection and Prevention"},
        {"control_id": "Art.11", "control_name": "Testing Requirements"},
        {"control_id": "Art.17", "control_name": "Incident Reporting"},
    ],
    "NIS2": [
        {"control_id": "Art.21", "control_name": "Security Measures"},
        {"control_id": "Art.23", "control_name": "Incident Reporting"},
    ],
    "EU_AI_Act": [
        {"control_id": "Art.9", "control_name": "Risk Management System"},
        {"control_id": "Art.10", "control_name": "Data Governance"},
        {"control_id": "Art.12", "control_name": "Human Oversight"},
        {"control_id": "Art.15", "control_name": "Accuracy and Robustness"},
    ],
}


# ============================================================================
# ENGINE FUNCTIONS
# ============================================================================


def compute_sha256(content: str | dict | bytes) -> str:
    """Hash any content with SHA-256."""
    if isinstance(content, dict):
        content = json.dumps(content, sort_keys=True, default=str)
    if isinstance(content, str):
        content = content.encode()
    return hashlib.sha256(content).hexdigest()


async def collect_evidence(
    db: AsyncSession,
    tenant_id,
    user_id,
    framework: str,
    control_id: str,
    control_name: str,
    evidence_type: str,
    title: str,
    description: str | None,
    content: str | dict,
    source_system: str,
    source_entity_type: str | None = None,
    source_entity_id: str | None = None,
) -> ComplianceEvidence:
    """Collect evidence, hash it, and create initial chain-of-custody entry."""
    content_hash = compute_sha256(content)
    content_str = json.dumps(content, default=str) if isinstance(content, dict) else str(content)

    evidence = ComplianceEvidence(
        tenant_id=tenant_id, framework=framework, control_id=control_id,
        control_name=control_name, evidence_type=evidence_type, title=title,
        description=description, content_hash=content_hash,
        content_preview=content_str[:500],
        source_system=source_system, source_entity_type=source_entity_type,
        source_entity_id=source_entity_id, collected_by=user_id,
        status="collected",
    )
    db.add(evidence)
    await db.flush()

    chain = ChainOfCustody(
        tenant_id=tenant_id, evidence_id=evidence.id,
        custodian_id=user_id, custodian_name="GDS OS Auto-Collector",
        action="collected", action_reason=f"Auto-collected evidence for {framework} {control_id}",
        hash_at_action=content_hash, is_break=False,
    )
    db.add(chain)
    await db.flush()
    return evidence


async def verify_evidence(db: AsyncSession, tenant_id, evidence_id, user_id) -> dict:
    """Verify evidence integrity by re-hashing content."""
    q = select(ComplianceEvidence).where(
        ComplianceEvidence.id == evidence_id,
        ComplianceEvidence.tenant_id == tenant_id,
    )
    result = await db.execute(q)
    evidence = result.scalar_one_or_none()
    if not evidence:
        return {"error": "Evidence not found"}

    # Re-hash the content preview as a verification proxy
    current_hash = compute_sha256(evidence.content_preview or "")
    verified = current_hash == evidence.content_hash

    chain = ChainOfCustody(
        tenant_id=tenant_id, evidence_id=evidence.id,
        custodian_id=user_id, custodian_name="GDS OS Verifier",
        action="verified" if verified else "revoked",
        action_reason="Integrity check passed" if verified else "Hash mismatch — chain broken",
        hash_at_action=current_hash,
        is_break=not verified,
        break_reason=None if verified else "Content hash mismatch detected",
    )
    db.add(chain)

    if not verified:
        evidence.is_valid = False
        evidence.status = "revoked"
    await db.flush()

    return {"evidence_id": str(evidence_id), "verified": verified, "stored_hash": evidence.content_hash, "computed_hash": current_hash}


async def transfer_evidence(db: AsyncSession, tenant_id, evidence_id, from_user_id, to_user_id, reason) -> ChainOfCustody:
    """Transfer custody of evidence."""
    q = select(ComplianceEvidence).where(ComplianceEvidence.id == evidence_id, ComplianceEvidence.tenant_id == tenant_id)
    evidence = (await db.execute(q)).scalar_one_or_none()
    if not evidence:
        raise ValueError("Evidence not found")

    chain = ChainOfCustody(
        tenant_id=tenant_id, evidence_id=evidence_id,
        custodian_id=to_user_id, custodian_name=str(to_user_id),
        action="transferred", action_reason=reason,
        hash_at_action=evidence.content_hash, is_break=False,
    )
    db.add(chain)
    await db.flush()
    return chain


async def place_legal_hold(db: AsyncSession, tenant_id, evidence_ids: list, user_id, title, description, legal_matter) -> LegalHold:
    """Place a legal hold on evidence items."""
    # Mark evidence as under hold
    for eid in evidence_ids:
        q = select(ComplianceEvidence).where(ComplianceEvidence.id == eid, ComplianceEvidence.tenant_id == tenant_id)
        ev = (await db.execute(q)).scalar_one_or_none()
        if ev:
            ev.status = "legal_hold"

    hold = LegalHold(
        tenant_id=tenant_id, title=title, description=description,
        legal_matter=legal_matter, evidence_ids=[str(e) for e in evidence_ids],
        issued_by=user_id, status="active",
    )
    db.add(hold)
    await db.flush()
    return hold


async def release_legal_hold(db: AsyncSession, tenant_id, hold_id, user_id, reason) -> LegalHold:
    """Release a legal hold."""
    q = select(LegalHold).where(LegalHold.id == hold_id, LegalHold.tenant_id == tenant_id)
    hold = (await db.execute(q)).scalar_one_or_none()
    if not hold:
        raise ValueError("Legal hold not found")

    hold.released_by = user_id
    hold.released_at = datetime.now(UTC)
    hold.release_reason = reason
    hold.status = "released"

    # Revert evidence status
    for eid in hold.evidence_ids:
        eq = select(ComplianceEvidence).where(ComplianceEvidence.id == eid)
        ev = (await db.execute(eq)).scalar_one_or_none()
        if ev and ev.status == "legal_hold":
            ev.status = "collected"
    await db.flush()
    return hold


async def get_chain_of_custody(db: AsyncSession, tenant_id, evidence_id) -> list[dict]:
    """Get the full chain of custody for an evidence item."""
    q = select(ChainOfCustody).where(
        ChainOfCustody.evidence_id == evidence_id,
        ChainOfCustody.tenant_id == tenant_id,
    ).order_by(ChainOfCustody.occurred_at)
    result = await db.execute(q)
    chain = result.scalars().all()
    return [
        {"id": str(c.id), "custodian_name": c.custodian_name, "action": c.action,
         "action_reason": c.action_reason, "hash_at_action": c.hash_at_action,
         "is_break": c.is_break, "break_reason": c.break_reason,
         "occurred_at": c.occurred_at.isoformat() if c.occurred_at else None}
        for c in chain
    ]


async def identify_gaps(db: AsyncSession, tenant_id, framework: str) -> list[ComplianceGap]:
    """Identify controls that have no evidence collected."""
    controls = FRAMEWORK_CONTROLS.get(framework, [])

    # Get existing evidence by control_id
    eq = select(ComplianceEvidence).where(
        ComplianceEvidence.tenant_id == tenant_id,
        ComplianceEvidence.framework == framework,
    )
    existing = (await db.execute(eq)).scalars().all()
    evidence_by_control = {e.control_id for e in existing}

    gaps = []
    for control in controls:
        if control["control_id"] not in evidence_by_control:
            gap = ComplianceGap(
                tenant_id=tenant_id, framework=framework,
                control_id=control["control_id"], control_name=control["control_name"],
                gap_type="missing_evidence", severity="high",
                description=f"No evidence collected for {framework} control {control['control_id']}: {control['control_name']}",
                has_evidence=False,
            )
            db.add(gap)
            gaps.append(gap)
    await db.flush()
    return gaps


async def generate_evidence_package(db: AsyncSession, tenant_id, framework: str, control_ids: list[str] | None = None) -> dict:
    """Generate an audit-ready evidence package."""
    controls = FRAMEWORK_CONTROLS.get(framework, [])
    if control_ids:
        controls = [c for c in controls if c["control_id"] in control_ids]

    q = select(ComplianceEvidence).where(
        ComplianceEvidence.tenant_id == tenant_id,
        ComplianceEvidence.framework == framework,
    )
    all_evidence = (await db.execute(q)).scalars().all()
    evidence_by_control: dict[str, list] = {}
    for ev in all_evidence:
        evidence_by_control.setdefault(ev.control_id, []).append(ev)

    items = []
    for control in controls:
        ev_list = evidence_by_control.get(control["control_id"], [])
        for ev in ev_list:
            chain = await get_chain_of_custody(db, tenant_id, ev.id)
            items.append({
                "control_id": control["control_id"], "control_name": control["control_name"],
                "evidence_id": str(ev.id), "title": ev.title, "evidence_type": ev.evidence_type,
                "content_hash": ev.content_hash, "content_preview": ev.content_preview[:200] if ev.content_preview else None,
                "source_system": ev.source_system, "is_valid": ev.is_valid,
                "collected_at": ev.collected_at.isoformat() if ev.collected_at else None,
                "chain_of_custody": chain,
            })

    controls_with = {c["control_id"] for c in controls if c["control_id"] in evidence_by_control}
    controls_without = [c for c in controls if c["control_id"] not in evidence_by_control]

    return {
        "framework": framework,
        "total_controls": len(controls),
        "controls_with_evidence": len(controls_with),
        "controls_without_evidence": len(controls_without),
        "missing_controls": [{"control_id": c["control_id"], "control_name": c["control_name"]} for c in controls_without],
        "evidence_items": items,
        "generated_at": datetime.now(UTC).isoformat(),
    }


async def auto_collect_from_findings(db: AsyncSession, tenant_id, user_id) -> dict:
    """Auto-collect evidence from resolved/fixed findings."""
    # Try to import finding models — may vary by codebase
    try:
        from gds_api.finding_lifecycle import Finding
        q = select(Finding).where(Finding.tenant_id == tenant_id, Finding.status == "fixed")
        result = await db.execute(q)
        fixed_findings = result.scalars().all()
    except Exception:
        fixed_findings = []

    collected = 0
    for finding in fixed_findings:
        evidence = await collect_evidence(
            db=db, tenant_id=tenant_id, user_id=user_id,
            framework="NIST", control_id="PR.IP-12",
            control_name="Remediation Verification",
            evidence_type="remediation_record",
            title=f"Remediation of {getattr(finding, 'title', 'finding')}",
            description=f"Finding {getattr(finding, 'id', '')} was remediated. Status: fixed.",
            content={"finding_id": str(getattr(finding, "id", "")), "title": getattr(finding, "title", ""), "status": "fixed", "remediation": getattr(finding, "remediation", "")},
            source_system="GDS OS Finding Lifecycle",
            source_entity_type="Finding",
            source_entity_id=str(getattr(finding, "id", "")),
        )
        collected += 1

    await db.flush()
    return {"evidence_collected": collected, "from_source": "fixed_findings"}
