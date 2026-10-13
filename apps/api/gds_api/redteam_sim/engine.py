"""GDS OS W10 — Adversary Simulation / Red Team Automation.

Automates adversary emulation using MITRE ATT&CK techniques,
Atomic Red Team tests, and purple team exercises.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func, select as sa_select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from gds_api.models import Base


# ============================================================================
# MODELS
# ============================================================================

class AdversaryProfile(Base):
    __tablename__ = "redteam_adversary_profiles"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    sophistication: Mapped[str] = mapped_column(String(50))
    threat_actor_ref: Mapped[str | None] = mapped_column(String(200), default=None)
    tactics: Mapped[list] = mapped_column(JSONB, default=list)
    techniques: Mapped[list] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class SimulationCampaign(Base):
    __tablename__ = "redteam_campaigns"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    name: Mapped[str] = mapped_column(String(200))
    adversary_profile_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("redteam_adversary_profiles.id"))
    adversary_name: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(50), default="pending")
    total_techniques: Mapped[int] = mapped_column(Integer, default=0)
    detected: Mapped[int] = mapped_column(Integer, default=0)
    prevented: Mapped[int] = mapped_column(Integer, default=0)
    missed: Mapped[int] = mapped_column(Integer, default=0)
    detection_rate: Mapped[float] = mapped_column(default=0.0)
    prevention_rate: Mapped[float] = mapped_column(default=0.0)
    coverage_pct: Mapped[float] = mapped_column(default=0.0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    report: Mapped[dict] = mapped_column(JSONB, default=dict)


class SimulationStep(Base):
    __tablename__ = "redteam_steps"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    campaign_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("redteam_campaigns.id"))
    step_number: Mapped[int] = mapped_column(Integer)
    mitre_tactic: Mapped[str] = mapped_column(String(100))
    mitre_technique: Mapped[str] = mapped_column(String(50))
    technique_name: Mapped[str] = mapped_column(String(200))
    atomic_test: Mapped[str | None] = mapped_column(Text, default=None)
    expected_detection: Mapped[bool] = mapped_column(Boolean, default=True)
    actual_detected: Mapped[bool] = mapped_column(Boolean, default=False)
    actual_prevented: Mapped[bool] = mapped_column(Boolean, default=False)
    response_time_seconds: Mapped[float] = mapped_column(default=0.0)
    outcome: Mapped[str] = mapped_column(String(50), default="pending")
    executed_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)


# ============================================================================
# MITRE ATT&CK TECHNIQUE CATALOG (30+ techniques across 14 tactics)
# ============================================================================

MITRE_TECHNIQUES: list[dict[str, Any]] = [
    {"id": "T1595", "tactic": "Reconnaissance", "name": "Active Scanning", "atomic": "nmap -sV target", "detection_prob": 0.7},
    {"id": "T1592", "tactic": "Reconnaissance", "name": "Gather Victim Host Info", "atomic": "nslookup target.com", "detection_prob": 0.5},
    {"id": "T1589", "tactic": "Reconnaissance", "name": "Gather Victim Identity Info", "atomic": "OSINT email harvesting", "detection_prob": 0.3},
    {"id": "T1078", "tactic": "Initial Access", "name": "Valid Accounts", "atomic": "Brute-force RDP", "detection_prob": 0.8},
    {"id": "T1190", "tactic": "Initial Access", "name": "Exploit Public-Facing App", "atomic": "Exploit CVE-2021-44228", "detection_prob": 0.85},
    {"id": "T1566", "tactic": "Initial Access", "name": "Phishing", "atomic": "Spear-phish with macro payload", "detection_prob": 0.75},
    {"id": "T1059", "tactic": "Execution", "name": "Command and Scripting Interpreter", "atomic": "powershell.exe -enc <base64>", "detection_prob": 0.8},
    {"id": "T1106", "tactic": "Execution", "name": "Native API", "atomic": "Win32 API CreateProcess", "detection_prob": 0.6},
    {"id": "T1547", "tactic": "Persistence", "name": "Boot or Logon Autostart", "atomic": "Registry Run key", "detection_prob": 0.9},
    {"id": "T1136", "tactic": "Persistence", "name": "Create Account", "atomic": "net user backdoor P@ss /add", "detection_prob": 0.85},
    {"id": "T1068", "tactic": "Privilege Escalation", "name": "Exploitation for Privilege Escalation", "atomic": "Exploit CVE-2021-3156 (sudo)", "detection_prob": 0.7},
    {"id": "T1548", "tactic": "Privilege Escalation", "name": "Abuse Elevation Control Mechanism", "atomic": "UAC bypass via fodhelper", "detection_prob": 0.65},
    {"id": "T1027", "tactic": "Defense Evasion", "name": "Obfuscated Files or Information", "atomic": "Base64 encode payload", "detection_prob": 0.6},
    {"id": "T1562", "tactic": "Defense Evasion", "name": "Impair Defenses", "atomic": "Disable Windows Defender", "detection_prob": 0.95},
    {"id": "T1070", "tactic": "Defense Evasion", "name": "Indicator Removal", "atomic": "Clear Windows Event Logs", "detection_prob": 0.9},
    {"id": "T1003", "tactic": "Credential Access", "name": "OS Credential Dumping", "atomic": "LSASS memory dump via mimikatz", "detection_prob": 0.9},
    {"id": "T1110", "tactic": "Credential Access", "name": "Brute Force", "atomic": "Password spraying O365", "detection_prob": 0.75},
    {"id": "T1555", "tactic": "Credential Access", "name": "Credentials from Password Stores", "atomic": "Chrome password extraction", "detection_prob": 0.7},
    {"id": "T1087", "tactic": "Discovery", "name": "Account Discovery", "atomic": "net user /domain", "detection_prob": 0.6},
    {"id": "T1046", "tactic": "Discovery", "name": "Network Service Discovery", "atomic": "nmap -sn 10.0.0.0/24", "detection_prob": 0.7},
    {"id": "T1021", "tactic": "Lateral Movement", "name": "Remote Services", "atomic": "PsExec \\\\target cmd.exe", "detection_prob": 0.8},
    {"id": "T1072", "tactic": "Lateral Movement", "name": "Software Deployment Tools", "atomic": "SCCM package deployment", "detection_prob": 0.65},
    {"id": "T1560", "tactic": "Collection", "name": "Archive Collected Data", "atomic": "7z a data.7z C:\\sensitive", "detection_prob": 0.55},
    {"id": "T1056", "tactic": "Collection", "name": "Input Capture", "atomic": "Keylogger deployment", "detection_prob": 0.7},
    {"id": "T1071", "tactic": "Command and Control", "name": "Application Layer Protocol", "atomic": "HTTPS C2 beacon", "detection_prob": 0.6},
    {"id": "T1573", "tactic": "Command and Control", "name": "Encrypted Channel", "atomic": "TLS-encrypted C2", "detection_prob": 0.5},
    {"id": "T1041", "tactic": "Exfiltration", "name": "Exfiltration Over C2 Channel", "atomic": "Upload via C2 tunnel", "detection_prob": 0.65},
    {"id": "T1567", "tactic": "Exfiltration", "name": "Exfiltration Over Web Service", "atomic": "Upload to cloud storage", "detection_prob": 0.7},
    {"id": "T1486", "tactic": "Impact", "name": "Data Encrypted for Impact", "atomic": "Ransomware encryption simulation", "detection_prob": 0.95},
    {"id": "T1490", "tactic": "Impact", "name": "Inhibit System Recovery", "atomic": "vssadmin delete shadows", "detection_prob": 0.9},
    {"id": "T1489", "tactic": "Impact", "name": "Service Stop", "atomic": "Stop critical services", "detection_prob": 0.85},
]


# ============================================================================
# PREDEFINED ADVERSARY PROFILES (5 APT groups)
# ============================================================================

ADVERSARY_PROFILES: list[dict[str, Any]] = [
    {
        "name": "APT29 (Cozy Bear)",
        "description": "Russian SVR-linked APT. Known for supply chain attacks (SolarWinds), cloud compromise, and diplomatic phishing. Targets government and think tanks.",
        "sophistication": "advanced",
        "threat_actor_ref": "APT29",
        "tactics": ["Initial Access", "Execution", "Persistence", "Defense Evasion", "Credential Access", "Lateral Movement", "Collection", "Exfiltration"],
        "techniques": ["T1190", "T1566", "T1059", "T1547", "T1027", "T1562", "T1003", "T1021", "T1560", "T1041", "T1078", "T1071"],
    },
    {
        "name": "Scattered Spider",
        "description": "English-speaking threat group known for SIM swapping, MFA bypass, and social engineering against telecom and tech companies.",
        "sophistication": "high",
        "threat_actor_ref": "Scattered Spider",
        "tactics": ["Reconnaissance", "Initial Access", "Credential Access", "Persistence", "Lateral Movement", "Collection", "Exfiltration"],
        "techniques": ["T1589", "T1078", "T1110", "T1555", "T1547", "T1021", "T1560", "T1567", "T1566", "T1087"],
    },
    {
        "name": "LockBit Ransomware",
        "description": "Ransomware-as-a-Service (RaaS) operation. Known for double extortion, self-spreading malware, and targeting healthcare and critical infrastructure.",
        "sophistication": "high",
        "threat_actor_ref": "LockBit",
        "tactics": ["Initial Access", "Execution", "Privilege Escalation", "Defense Evasion", "Lateral Movement", "Collection", "Impact"],
        "techniques": ["T1190", "T1078", "T1059", "T1068", "T1562", "T1070", "T1021", "T1560", "T1486", "T1490", "T1489"],
    },
    {
        "name": "FIN7",
        "description": "Financially motivated threat group targeting retail, hospitality, and financial services. Known for CARBANAK malware and drive-by downloads.",
        "sophistication": "high",
        "threat_actor_ref": "FIN7",
        "tactics": ["Reconnaissance", "Initial Access", "Execution", "Persistence", "Credential Access", "Lateral Movement", "Collection", "Exfiltration"],
        "techniques": ["T1595", "T1566", "T1059", "T1106", "T1547", "T1003", "T1021", "T1560", "T1041", "T1072"],
    },
    {
        "name": "Lazarus Group",
        "description": "North Korean state-sponsored group. Known for SWIFT bank heists, cryptocurrency exchange attacks, and supply chain compromise (3CX).",
        "sophistication": "advanced",
        "threat_actor_ref": "Lazarus",
        "tactics": ["Reconnaissance", "Initial Access", "Execution", "Defense Evasion", "Credential Access", "Lateral Movement", "Collection", "Exfiltration", "Impact"],
        "techniques": ["T1592", "T1566", "T1190", "T1059", "T1027", "T1070", "T1110", "T1021", "T1560", "T1567", "T1486"],
    },
]


def get_technique_by_id(tech_id: str) -> dict[str, Any] | None:
    for t in MITRE_TECHNIQUES:
        if t["id"] == tech_id:
            return t
    return None


def calculate_detection_rate(detected: int, total: int) -> float:
    return round((detected / total) * 100, 1) if total > 0 else 0.0


def calculate_prevention_rate(prevented: int, total: int) -> float:
    return round((prevented / total) * 100, 1) if total > 0 else 0.0


def calculate_coverage(tactics_covered: list[str]) -> float:
    return round((len(set(tactics_covered)) / 14) * 100, 1)


async def create_campaign(
    db: AsyncSession, tenant_id: uuid.UUID,
    name: str, adversary_profile_name: str,
) -> dict[str, Any]:
    profile = next((p for p in ADVERSARY_PROFILES if p["name"] == adversary_profile_name), None)
    if not profile:
        raise ValueError(f"Unknown adversary profile: {adversary_profile_name}")

    ap = AdversaryProfile(
        tenant_id=tenant_id, name=profile["name"], description=profile["description"],
        sophistication=profile["sophistication"], threat_actor_ref=profile["threat_actor_ref"],
        tactics=profile["tactics"], techniques=profile["techniques"],
    )
    db.add(ap)
    db.flush()

    campaign = SimulationCampaign(
        tenant_id=tenant_id, name=name,
        adversary_profile_id=ap.id, adversary_name=profile["name"],
        status="pending", total_techniques=len(profile["techniques"]),
    )
    db.add(campaign)
    db.flush()

    for i, tech_id in enumerate(profile["techniques"], 1):
        tech = get_technique_by_id(tech_id)
        if tech:
            step = SimulationStep(
                tenant_id=tenant_id, campaign_id=campaign.id, step_number=i,
                mitre_tactic=tech["tactic"], mitre_technique=tech["id"],
                technique_name=tech["name"], atomic_test=tech["atomic"],
                expected_detection=True, outcome="pending",
            )
            db.add(step)

    db.flush()
    return {
        "campaign_id": str(campaign.id), "profile_id": str(ap.id),
        "name": name, "adversary": profile["name"],
        "total_techniques": len(profile["techniques"]), "status": "pending",
    }


async def execute_step(step: SimulationStep, detection_prob: float, prevention_prob: float = 0.3) -> SimulationStep:
    # Deterministic probability-based outcome (no random)
    # Detection succeeds when detection probability is above threshold
    is_detected = detection_prob >= 0.5
    # Prevention succeeds when prevention probability is above threshold and detection occurred
    is_prevented = is_detected and prevention_prob >= 0.4
    step.actual_detected = is_detected
    step.actual_prevented = is_prevented
    # Response time is deterministic: faster when detected, slower when missed
    step.response_time_seconds = round(30.0 * (1 - detection_prob) + 5.0, 2) if is_detected else round(120.0 * (1 - detection_prob) + 30.0, 2)
    step.executed_at = datetime.utcnow()
    step.outcome = "prevented" if is_prevented else ("detected" if is_detected else "missed")
    return step


async def run_campaign(db: AsyncSession, campaign_id: uuid.UUID, tenant_id: uuid.UUID) -> dict[str, Any]:
    stmt = sa_select(SimulationCampaign).where(SimulationCampaign.id == campaign_id, SimulationCampaign.tenant_id == tenant_id)
    campaign = (await db.execute(stmt)).scalar_one_or_none()
    if not campaign:
        raise ValueError("Campaign not found")

    campaign.status = "running"
    campaign.started_at = datetime.utcnow()
    db.flush()

    step_stmt = sa_select(SimulationStep).where(
        SimulationStep.campaign_id == campaign_id, SimulationStep.tenant_id == tenant_id,
    ).order_by(SimulationStep.step_number)
    steps = (await db.execute(step_stmt)).scalars().all()

    detected = prevented = missed = 0
    tactics_covered: list[str] = []

    for step in steps:
        tech = get_technique_by_id(step.mitre_technique)
        det_prob = tech["detection_prob"] if tech else 0.5
        step = await execute_step(step, det_prob)
        if step.outcome == "prevented":
            prevented += 1
        elif step.outcome == "detected":
            detected += 1
        else:
            missed += 1
        if step.mitre_tactic not in tactics_covered:
            tactics_covered.append(step.mitre_tactic)

    campaign.detected = detected
    campaign.prevented = prevented
    campaign.missed = missed
    campaign.detection_rate = calculate_detection_rate(detected, len(steps))
    campaign.prevention_rate = calculate_prevention_rate(prevented, len(steps))
    campaign.coverage_pct = calculate_coverage(tactics_covered)
    campaign.status = "completed"
    campaign.completed_at = datetime.utcnow()
    campaign.report = generate_report_sync(campaign, steps, tactics_covered)
    db.flush()

    return {
        "campaign_id": str(campaign.id), "status": "completed",
        "total_techniques": len(steps), "detected": detected, "prevented": prevented,
        "missed": missed, "detection_rate": campaign.detection_rate,
        "prevention_rate": campaign.prevention_rate, "coverage_pct": campaign.coverage_pct,
    }


def generate_report_sync(campaign: SimulationCampaign, steps: list[SimulationStep], tactics_covered: list[str]) -> dict[str, Any]:
    gaps = [s for s in steps if s.outcome == "missed"]
    gaps_by_tactic: dict[str, list[str]] = {}
    for g in gaps:
        if g.mitre_tactic not in gaps_by_tactic:
            gaps_by_tactic[g.mitre_tactic] = []
        gaps_by_tactic[g.mitre_tactic].append(f"{g.mitre_technique}: {g.technique_name}")

    all_tactics = sorted(set(s.mitre_tactic for s in steps))
    return {
        "executive_summary": (
            f"Adversary simulation '{campaign.name}' using {campaign.adversary_name} profile completed. "
            f"Of {campaign.total_techniques} techniques: {campaign.detected} detected, "
            f"{campaign.prevented} prevented, {campaign.missed} missed. "
            f"Detection rate: {campaign.detection_rate}%. Coverage: {campaign.coverage_pct}%."
        ),
        "key_findings": [
            f"Detection rate: {campaign.detection_rate}% ({campaign.detected}/{campaign.total_techniques})",
            f"Prevention rate: {campaign.prevention_rate}% ({campaign.prevented}/{campaign.total_techniques})",
            f"Missed techniques: {campaign.missed} — detection gaps",
            f"MITRE tactic coverage: {campaign.coverage_pct}% ({len(tactics_covered)}/14 tactics)",
        ],
        "detection_gaps": gaps_by_tactic,
        "recommendations": [
            f"Close {len(gaps)} detection gaps starting with {list(gaps_by_tactic.keys())[0] if gaps_by_tactic else 'N/A'}",
            "Deploy Sigma rules for missed MITRE techniques",
            "Increase EDR coverage on endpoints where techniques were missed",
            "Conduct follow-up purple team exercise to verify remediation",
        ] if gaps else ["No detection gaps — all techniques caught"],
        "tactics_covered": all_tactics,
        "technique_results": [
            {"step": s.step_number, "technique": s.mitre_technique, "name": s.technique_name,
             "tactic": s.mitre_tactic, "outcome": s.outcome, "response_time_s": s.response_time_seconds}
            for s in steps
        ],
    }
