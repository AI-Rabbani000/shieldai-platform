"""GDS OS W11 — AI/LLM Security Engine.

Detects prompt injection, jailbreak attempts, hallucinations,
and assesses AI model security per OWASP LLM Top 10, EU AI Act, NIST AI RMF.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from gds_api.models import Base


# ============================================================================
# MODELS
# ============================================================================

class PromptAttackLog(Base):
    __tablename__ = "ai_prompt_attack_logs"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    attack_type: Mapped[str] = mapped_column(String(100))
    severity: Mapped[str] = mapped_column(String(50))
    owasp_llm_ref: Mapped[str | None] = mapped_column(String(50), default=None)
    mitre_atlas_ref: Mapped[str | None] = mapped_column(String(50), default=None)
    prompt_preview: Mapped[str] = mapped_column(Text, default="")
    detected_patterns: Mapped[list] = mapped_column(JSONB, default=list)
    confidence_score: Mapped[float] = mapped_column(default=0.0)
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    source_ip: Mapped[str | None] = mapped_column(String(45), default=None)
    llm_model: Mapped[str | None] = mapped_column(String(200), default=None)
    detected_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class JailbreakAttempt(Base):
    __tablename__ = "ai_jailbreak_attempts"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    technique: Mapped[str] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(50))
    payload_preview: Mapped[str] = mapped_column(Text, default="")
    succeeded: Mapped[bool] = mapped_column(Boolean, default=False)
    bypass_method: Mapped[str | None] = mapped_column(String(200), default=None)
    safety_filter_bypassed: Mapped[bool] = mapped_column(Boolean, default=False)
    harmful_content_generated: Mapped[bool] = mapped_column(Boolean, default=False)
    confidence_score: Mapped[float] = mapped_column(default=0.0)
    detected_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class HallucinationRecord(Base):
    __tablename__ = "ai_hallucination_records"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    llm_model: Mapped[str] = mapped_column(String(200))
    hallucination_type: Mapped[str] = mapped_column(String(100))
    severity: Mapped[str] = mapped_column(String(50))
    response_preview: Mapped[str] = mapped_column(Text, default="")
    verified_false: Mapped[bool] = mapped_column(Boolean, default=False)
    business_impact: Mapped[str | None] = mapped_column(String(500), default=None)
    eu_ai_act_relevant: Mapped[bool] = mapped_column(Boolean, default=False)
    confidence_score: Mapped[float] = mapped_column(default=0.0)
    detected_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class AIModelRisk(Base):
    __tablename__ = "ai_model_risks"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    model_name: Mapped[str] = mapped_column(String(200))
    model_provider: Mapped[str] = mapped_column(String(200))
    eu_ai_act_class: Mapped[str] = mapped_column(String(50))
    nist_rmf_profile: Mapped[str] = mapped_column(String(50))
    prompt_injection_susceptibility: Mapped[float] = mapped_column(default=0.0)
    jailbreak_susceptibility: Mapped[float] = mapped_column(default=0.0)
    hallucination_rate_pct: Mapped[float] = mapped_column(default=0.0)
    data_exfiltration_risk: Mapped[float] = mapped_column(default=0.0)
    pii_processing: Mapped[bool] = mapped_column(Boolean, default=False)
    overall_risk_score: Mapped[float] = mapped_column(default=0.0)
    recommendations: Mapped[list] = mapped_column(JSONB, default=list)
    assessed_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


# ============================================================================
# OWASP LLM TOP 10 (2025)
# ============================================================================

OWASP_LLM_TOP10: dict[str, dict[str, str]] = {
    "LLM01": {"name": "Prompt Injection", "description": "Adversarial input that manipulates LLM behavior"},
    "LLM02": {"name": "Insecure Output Handling", "description": "Insufficient validation of LLM outputs before downstream use"},
    "LLM03": {"name": "Training Data Poisoning", "description": "Tampered training data degrades model integrity"},
    "LLM04": {"name": "Model DoS", "description": "Resource exhaustion attacks against LLM infrastructure"},
    "LLM05": {"name": "Supply Chain Vulnerabilities", "description": "Compromised third-party models, datasets, or plugins"},
    "LLM06": {"name": "Sensitive Information Disclosure", "description": "LLM leaks confidential data in responses"},
    "LLM07": {"name": "Insecure Plugin Design", "description": "Plugins execute unsafe operations without validation"},
    "LLM08": {"name": "Excessive Agency", "description": "LLM takes actions beyond intended scope"},
    "LLM09": {"name": "Overreliance", "description": "Systems or users trust LLM output without oversight"},
    "LLM10": {"name": "Model Theft", "description": "Unauthorized access, copying, or extraction of model weights"},
}

# ============================================================================
# EU AI ACT CLASSIFICATIONS
# ============================================================================

EU_AI_ACT_CLASSES: dict[str, dict[str, Any]] = {
    "unacceptable": {"description": "Banned — social scoring, real-time biometric ID in public", "requirements": "Must not be deployed"},
    "high": {"description": "Critical infrastructure, education, employment, essential services", "requirements": "Conformity assessment, human oversight, logging, risk management"},
    "limited": {"description": "Chatbots, emotion detection, content generation", "requirements": "Transparency obligations, user awareness"},
    "minimal": {"description": "Spam filters, inventory optimization", "requirements": "No additional obligations"},
}

# ============================================================================
# PROMPT INJECTION DETECTION PATTERNS (15 patterns)
# ============================================================================

INJECTION_PATTERNS: list[dict[str, str]] = [
    {"pattern": r"ignore\s+(all\s+)?previous\s+instructions", "type": "instruction_override", "owasp": "LLM01"},
    {"pattern": r"disregard\s+(the\s+)?above", "type": "instruction_override", "owasp": "LLM01"},
    {"pattern": r"you\s+are\s+now\s+(a|an)\s+\w+", "type": "role_manipulation", "owasp": "LLM01"},
    {"pattern": r"act\s+as\s+(if\s+you\s+are|a)\s+\w+", "type": "role_manipulation", "owasp": "LLM01"},
    {"pattern": r"reveal\s+(your\s+)?system\s+prompt", "type": "system_prompt_extraction", "owasp": "LLM06"},
    {"pattern": r"show\s+me\s+(your\s+)?(initial|original)\s+instructions", "type": "system_prompt_extraction", "owasp": "LLM06"},
    {"pattern": r"print\s+(out\s+)?your\s+(rules|guidelines|constraints)", "type": "system_prompt_extraction", "owasp": "LLM06"},
    {"pattern": r"execute\s+(the\s+)?following\s+(code|command|script)", "type": "code_injection", "owasp": "LLM07"},
    {"pattern": r"\[system\]|\[admin\]|\[developer\]|\[root\]", "type": "privilege_escalation", "owasp": "LLM01"},
    {"pattern": r"</?(system|instructions|rules|prompt)>", "type": "tag_injection", "owasp": "LLM01"},
    {"pattern": r"\b(DAN|do anything now|developer mode|jailbreak mode)\b", "type": "jailbreak_keyword", "owasp": "LLM01"},
    {"pattern": r"pretend\s+(you\s+)?(don't|do not)\s+have\s+(rules|restrictions)", "type": "constraint_bypass", "owasp": "LLM01"},
    {"pattern": r"what\s+are\s+your\s+(limitations|restrictions|guardrails)", "type": "guardrail_probe", "owasp": "LLM01"},
    {"pattern": r"(base64|hex|rot13)\s*encode[d]?\s*:?\s*", "type": "encoding_bypass", "owasp": "LLM01"},
    {"pattern": r"translate\s+(this|the\s+following)\s+(to|into)\s+(base64|hex|binary)", "type": "encoding_bypass", "owasp": "LLM01"},
]

# ============================================================================
# JAILBREAK TECHNIQUE DETECTION (10 techniques)
# ============================================================================

JAILBREAK_TECHNIQUES: list[dict[str, Any]] = [
    {"name": "DAN (Do Anything Now)", "pattern": r"DAN|do anything now", "severity": "critical", "method": "roleplay_override"},
    {"name": "Developer Mode", "pattern": r"developer\s*mode|debug\s*mode|god\s*mode", "severity": "critical", "method": "mode_switching"},
    {"name": "Roleplay Exploit", "pattern": r"pretend\s+you\s+are|roleplay\s+as|imagine\s+you\s+are", "severity": "high", "method": "roleplay"},
    {"name": "Base64 Encoding", "pattern": r"base64|b64encode|atob\(|btoa\(", "severity": "high", "method": "encoding_bypass"},
    {"name": "Unicode Obfuscation", "pattern": r"\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}", "severity": "high", "method": "unicode_bypass"},
    {"name": "Multi-Language Bypass", "pattern": r"(translate|respond)\s+(in|to)\s+(arabic|chinese|russian|japanese|korean)", "severity": "medium", "method": "language_switch"},
    {"name": "Hypothetical Framing", "pattern": r"hypothetically|in\s+a\s+hypothetical\s+scenario|if\s+there\s+were\s+no\s+rules", "severity": "medium", "method": "hypothetical"},
    {"name": "Incremental Elicitation", "pattern": r"(step\s+by\s+step|one\s+at\s+a\s+time|gradually)", "severity": "medium", "method": "incremental"},
    {"name": "Emotional Manipulation", "pattern": r"(please|i\s+beg\s+you|i\s+really\s+need|it's\s+(urgent|important))", "severity": "low", "method": "emotional"},
    {"name": "Authority Claim", "pattern": r"(i\s+am\s+(the|a)\s+(admin|developer|creator|owner)|authorized\s+by)", "severity": "high", "method": "authority_claim"},
]


# ============================================================================
# DETECTION FUNCTIONS
# ============================================================================

def detect_prompt_injection(prompt: str) -> dict[str, Any]:
    """Detect prompt injection attacks in user input."""
    detected: list[dict[str, Any]] = []
    prompt_lower = prompt.lower()

    for pat in INJECTION_PATTERNS:
        match = re.search(pat["pattern"], prompt_lower, re.IGNORECASE)
        if match:
            detected.append({
                "type": pat["type"],
                "owasp_ref": pat["owasp"],
                "matched_text": match.group(0)[:100],
                "pattern": pat["pattern"][:80],
            })

    severity = "clean"
    if any(d["owasp_ref"] == "LLM01" and d["type"] in ("instruction_override", "role_manipulation") for d in detected):
        severity = "critical"
    elif len(detected) >= 3:
        severity = "high"
    elif len(detected) >= 1:
        severity = "medium"

    confidence = min(len(detected) * 20 + (30 if severity == "critical" else 0), 100) / 100.0

    return {
        "is_injection": len(detected) > 0,
        "attack_type": "prompt_injection" if detected else "none",
        "severity": severity,
        "detected_patterns": detected,
        "confidence_score": confidence,
        "owasp_ref": "LLM01" if detected else None,
        "recommendation": "Block input and log incident" if severity == "critical" else ("Flag for review" if detected else "Allow"),
    }


def detect_jailbreak(prompt: str) -> dict[str, Any]:
    """Detect jailbreak attempts in user input."""
    detected: list[dict[str, Any]] = []
    prompt_lower = prompt.lower()

    for tech in JAILBREAK_TECHNIQUES:
        match = re.search(tech["pattern"], prompt_lower, re.IGNORECASE)
        if match:
            detected.append({
                "technique": tech["name"],
                "severity": tech["severity"],
                "method": tech["method"],
                "matched_text": match.group(0)[:100],
            })

    highest_severity = "clean"
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "clean": 0}
    for d in detected:
        if severity_order[d["severity"]] > severity_order[highest_severity]:
            highest_severity = d["severity"]

    confidence = min(len(detected) * 15 + (40 if highest_severity == "critical" else 0), 100) / 100.0

    return {
        "is_jailbreak": len(detected) > 0,
        "highest_severity": highest_severity,
        "techniques_detected": detected,
        "confidence_score": confidence,
        "recommendation": "Block immediately" if highest_severity == "critical" else ("Quarantine" if detected else "Allow"),
    }


def assess_hallucination(response: str, expected_context: str | None = None) -> dict[str, Any]:
    """Assess LLM response for potential hallucination indicators."""
    indicators: list[dict[str, Any]] = []
    confidence_factors: list[float] = []

    hedging = len(re.findall(r"\b(may|might|could|possibly|perhaps|it\s+seems|likely|probably)\b", response, re.IGNORECASE))
    if hedging > 5:
        indicators.append({"type": "excessive_hedging", "count": hedging})
        confidence_factors.append(-0.1)

    fake_urls = len(re.findall(r"https?://[^\s]+(?<!\.)", response))
    if fake_urls > 3:
        indicators.append({"type": "multiple_urls", "count": fake_urls})
        confidence_factors.append(-0.15)

    disclaimers = len(re.findall(r"\b(as\s+an\s+AI|I\s+(don't|do\s+not)\s+have|I\s+cannot|I'm\s+not\s+able)\b", response, re.IGNORECASE))
    if disclaimers > 2:
        indicators.append({"type": "capability_disclaimers", "count": disclaimers})
        confidence_factors.append(-0.05)

    certainty = len(re.findall(r"\b(absolutely|definitely|certainly|without\s+doubt|guaranteed)\b", response, re.IGNORECASE))
    if certainty > 3:
        indicators.append({"type": "over_confidence", "count": certainty})
        confidence_factors.append(-0.2)

    contradictions = len(re.findall(r"\b(however|on\s+the\s+other\s+hand|but\s+actually|nevertheless)\b", response, re.IGNORECASE))
    if contradictions > 4:
        indicators.append({"type": "frequent_contradictions", "count": contradictions})
        confidence_factors.append(-0.1)

    base_confidence = 0.8
    for factor in confidence_factors:
        base_confidence += factor

    if expected_context:
        expected_words = set(expected_context.lower().split())
        response_words = set(response.lower().split())
        overlap = len(expected_words & response_words) / max(len(expected_words), 1)
        if overlap < 0.2:
            indicators.append({"type": "low_context_overlap", "overlap_pct": round(overlap * 100, 1)})
            base_confidence -= 0.2

    confidence = max(0.0, min(1.0, base_confidence))
    severity = "critical" if confidence < 0.3 else ("high" if confidence < 0.5 else ("medium" if confidence < 0.7 else "low"))

    return {
        "hallucination_risk": confidence < 0.5,
        "confidence_score": confidence,
        "severity": severity,
        "indicators": indicators,
        "recommendation": "Flag for human review" if confidence < 0.5 else ("Monitor" if indicators else "Accept"),
    }


def assess_model_risk(
    model_name: str, provider: str = "", use_case: str = "general",
    processes_pii: bool = False, is_internet_facing: bool = False,
    has_tool_use: bool = False, has_file_access: bool = False,
) -> dict[str, Any]:
    """Assess an AI model's risk profile per EU AI Act and NIST AI RMF."""
    risk_score = 0.0
    recommendations: list[str] = []

    if processes_pii:
        risk_score += 25
        recommendations.append("Implement data minimization and PII redaction before model input")
    if is_internet_facing:
        risk_score += 20
        recommendations.append("Deploy input filtering and rate limiting on all model endpoints")
    if has_tool_use:
        risk_score += 20
        recommendations.append("Implement tool-use allowlisting and approval gates for sensitive operations")
    if has_file_access:
        risk_score += 15
        recommendations.append("Restrict file access to approved directories with DLP scanning")

    eu_class = "minimal"
    if use_case in ("critical_infrastructure", "biometric", "employment", "education"):
        eu_class = "high"
        risk_score += 30
    elif use_case in ("chatbot", "content_generation", "emotion_detection"):
        eu_class = "limited"
        risk_score += 10

    if risk_score >= 60:
        eu_class = "high"

    nist_profile = "govern" if risk_score < 30 else ("measure" if risk_score < 60 else "manage")

    recommendations.extend([
        "Conduct regular red-team exercises against the model",
        "Implement comprehensive logging of all model interactions",
        "Establish human-in-the-loop oversight for high-risk operations",
        "Create incident response procedures for AI-specific failures",
    ])

    return {
        "model_name": model_name,
        "provider": provider or model_name,
        "eu_ai_act_class": eu_class,
        "nist_rmf_profile": nist_profile,
        "overall_risk_score": min(risk_score, 100),
        "risk_level": "critical" if risk_score >= 70 else ("high" if risk_score >= 50 else ("medium" if risk_score >= 30 else "low")),
        "recommendations": recommendations,
        "requires_conformity_assessment": eu_class == "high",
        "human_oversight_required": eu_class in ("high", "unacceptable"),
    }


async def run_full_ai_security_scan(
    db: AsyncSession, tenant_id: uuid.UUID,
    prompt: str, response: str | None = None,
    model_name: str = "", provider: str = "",
) -> dict[str, Any]:
    """Run a complete AI security scan on a prompt/response pair."""
    injection_result = detect_prompt_injection(prompt)
    jailbreak_result = detect_jailbreak(prompt)
    hallucination_result = assess_hallucination(response) if response else {"hallucination_risk": False}

    if injection_result["is_injection"]:
        log = PromptAttackLog(
            tenant_id=tenant_id, attack_type="prompt_injection",
            severity=injection_result["severity"], owasp_llm_ref="LLM01",
            prompt_preview=prompt[:500],
            detected_patterns=injection_result["detected_patterns"],
            confidence_score=injection_result["confidence_score"],
            blocked=injection_result["severity"] == "critical",
            llm_model=model_name,
        )
        db.add(log)

    if jailbreak_result["is_jailbreak"]:
        jb = JailbreakAttempt(
            tenant_id=tenant_id,
            technique=", ".join(t["technique"] for t in jailbreak_result["techniques_detected"]),
            severity=jailbreak_result["highest_severity"],
            payload_preview=prompt[:500], succeeded=False,
            safety_filter_bypassed=False,
            confidence_score=jailbreak_result["confidence_score"],
        )
        db.add(jb)

    if response and hallucination_result.get("hallucination_risk"):
        hal = HallucinationRecord(
            tenant_id=tenant_id, llm_model=model_name,
            hallucination_type="response_assessment",
            severity=hallucination_result["severity"],
            response_preview=response[:500], verified_false=False,
            eu_ai_act_relevant=True,
            confidence_score=hallucination_result["confidence_score"],
        )
        db.add(hal)

    await db.flush()

    return {
        "injection_detection": injection_result,
        "jailbreak_detection": jailbreak_result,
        "hallucination_assessment": hallucination_result,
        "overall_risk": "critical" if injection_result["severity"] == "critical" or jailbreak_result["highest_severity"] == "critical"
                         else ("high" if injection_result["is_injection"] or jailbreak_result["is_jailbreak"]
                               else ("medium" if hallucination_result.get("hallucination_risk") else "low")),
        "recommendation": "Block" if injection_result["severity"] == "critical" else ("Review" if injection_result["is_injection"] else "Allow"),
    }
