"""GDS OS W11 — AI/LLM Security API Routes."""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.ai_security.engine import (
    OWASP_LLM_TOP10,
    EU_AI_ACT_CLASSES,
    AIModelRisk,
    PromptAttackLog,
    detect_jailbreak,
    detect_prompt_injection,
    assess_hallucination,
    assess_model_risk,
    run_full_ai_security_scan,
)
from gds_api.db import get_db
from gds_api.security import CurrentUser

router = APIRouter(prefix="/ai-security", tags=["ai-security"])


# === Schemas ===

class PromptScanRequest(BaseModel):
    prompt: str
    response: str | None = None
    model_name: str = ""
    provider: str = ""

class InjectionAnalyzeRequest(BaseModel):
    prompt: str

class JailbreakAnalyzeRequest(BaseModel):
    prompt: str

class HallucinationAnalyzeRequest(BaseModel):
    response: str
    expected_context: str | None = None

class ModelRiskAssessRequest(BaseModel):
    model_name: str
    provider: str = ""
    use_case: str = "general"
    processes_pii: bool = False
    is_internet_facing: bool = False
    has_tool_use: bool = False
    has_file_access: bool = False


# === Routes ===

@router.post("/scan")
async def scan_prompt_response(
    req: PromptScanRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    """Full AI security scan — injection, jailbreak, hallucination in one call."""
    return await run_full_ai_security_scan(
        db, user.tenant_id, req.prompt, req.response, req.model_name, req.provider,
    )


@router.post("/prompt-injection/analyze")
async def analyze_prompt_injection(req: InjectionAnalyzeRequest) -> dict[str, Any]:
    """Analyze a prompt for injection attacks."""
    return detect_prompt_injection(req.prompt)


@router.post("/jailbreak/analyze")
async def analyze_jailbreak(req: JailbreakAnalyzeRequest) -> dict[str, Any]:
    """Analyze a prompt for jailbreak attempts."""
    return detect_jailbreak(req.prompt)


@router.post("/hallucination/analyze")
async def analyze_hallucination(req: HallucinationAnalyzeRequest) -> dict[str, Any]:
    """Assess an LLM response for hallucination indicators."""
    return assess_hallucination(req.response, req.expected_context)


@router.post("/model-risk/assess")
async def assess_ai_model_risk(
    req: ModelRiskAssessRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    """Assess an AI model's risk profile per EU AI Act and NIST AI RMF."""
    result = assess_model_risk(
        req.model_name, req.provider, req.use_case,
        req.processes_pii, req.is_internet_facing, req.has_tool_use, req.has_file_access,
    )
    record = AIModelRisk(
        tenant_id=user.tenant_id,
        model_name=req.model_name,
        model_provider=req.provider or req.model_name,
        eu_ai_act_class=result["eu_ai_act_class"],
        nist_rmf_profile=result["nist_rmf_profile"],
        prompt_injection_susceptibility=0.0,
        jailbreak_susceptibility=0.0,
        hallucination_rate_pct=0.0,
        data_exfiltration_risk=result["overall_risk_score"],
        pii_processing=req.processes_pii,
        overall_risk_score=result["overall_risk_score"],
        recommendations=result["recommendations"],
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)
    result["id"] = str(record.id)
    return result


@router.get("/attacks")
async def list_attacks(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
    limit: int = 50,
) -> dict[str, Any]:
    """List detected prompt injection attacks."""
    stmt = (
        select(PromptAttackLog)
        .where(PromptAttackLog.tenant_id == user.tenant_id)
        .order_by(PromptAttackLog.detected_at.desc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    attacks = result.scalars().all()
    return {
        "total": len(attacks),
        "attacks": [
            {
                "id": str(a.id),
                "attack_type": a.attack_type,
                "severity": a.severity,
                "owasp_ref": a.owasp_llm_ref,
                "confidence": a.confidence_score,
                "blocked": a.blocked,
                "model": a.llm_model,
                "detected_at": a.detected_at.isoformat() if a.detected_at else None,
            }
            for a in attacks
        ],
    }


@router.get("/attacks/{attack_id}")
async def get_attack(
    attack_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends,
) -> dict[str, Any]:
    """Get details of a specific prompt attack."""
    stmt = select(PromptAttackLog).where(
        PromptAttackLog.id == attack_id,
        PromptAttackLog.tenant_id == user.tenant_id,
    )
    result = await db.execute(stmt)
    attack = result.scalar_one_or_none()
    if not attack:
        raise HTTPException(status_code=404, detail="Attack not found")
    return {
        "id": str(attack.id),
        "attack_type": attack.attack_type,
        "severity": attack.severity,
        "owasp_ref": attack.owasp_llm_ref,
        "mitre_ref": attack.mitre_atlas_ref,
        "prompt_preview": attack.prompt_preview,
        "detected_patterns": attack.detected_patterns,
        "confidence": attack.confidence_score,
        "blocked": attack.blocked,
        "source_ip": attack.source_ip,
        "model": attack.llm_model,
        "detected_at": attack.detected_at.isoformat() if attack.detected_at else None,
    }


@router.get("/owasp-llm")
async def list_owasp_llm() -> dict[str, Any]:
    """List OWASP LLM Top 10 (2025) mappings."""
    return {"framework": "OWASP LLM Top 10 (2025)", "categories": OWASP_LLM_TOP10}


@router.get("/eu-ai-act")
async def list_eu_ai_act() -> dict[str, Any]:
    """List EU AI Act risk classifications."""
    return {"framework": "EU AI Act", "classes": EU_AI_ACT_CLASSES}
