"""API routes for the GDS AI/ML/DL/Quantum engine.

Endpoints:
  POST /ai-ml/anomaly-detection        — Run anomaly detection on platform data
  POST /ai-ml/predictive-threat        — Run predictive threat modeling
  POST /ai-ml/ueba                     — Run User/Entity Behavioral Analytics
  POST /ai-ml/quantum-assessment        — Run quantum-resistant crypto assessment
  GET  /ai-ml/status                   — Check available ML models and data
  POST /ai-ml/full-analysis            — Run all models at once
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.db import get_db
from gds_api.security import CurrentUser, require_permission

router = APIRouter(prefix="/ai-ml", tags=["ai-ml"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class AnomalyDetectionRequest(BaseModel):
    days: int = 30


class PredictiveThreatRequest(BaseModel):
    days: int = 30


class UEBARequest(BaseModel):
    user_id: str | None = None
    days: int = 30


class QuantumAssessmentRequest(BaseModel):
    domains: list[str] | None = None


class FullAnalysisRequest(BaseModel):
    days: int = 30
    domains: list[str] | None = None


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

@router.get("/status")
async def ml_status(
    current_user: CurrentUser = Depends(require_permission("ai_ml:read")),
) -> dict[str, Any]:
    """Check which ML models are available and how much training data exists."""
    available = {}
    for lib in ("numpy", "scipy", "sklearn", "pandas", "torch", "tensorflow"):
        try:
            __import__(lib)
            available[lib] = True
        except ImportError:
            available[lib] = False

    return {
        "ml_libraries": available,
        "pure_python_models": {
            "modified_z_score": True,
            "ewma_control_chart": True,
            "iqr_outliers": True,
            "bayesian_inference": True,
            "linear_regression": True,
            "poisson_distribution": True,
            "shannon_entropy": True,
            "cosine_similarity": True,
            "chi_square_test": True,
        },
        "models_available": [
            "Anomaly Detection (EWMA, Modified Z-Score, IQR, Chi-Square)",
            "Predictive Threat Modeling (Bayesian, Weighted Scoring, Linear Regression)",
            "Behavioral Analytics (UEBA: Temporal, Frequency, Session Analysis)",
            "Quantum Crypto Assessment (Shor's, Grover's, NIST PQC Standards)",
        ],
        "quantum_standards": ["FIPS 203 (ML-KEM)", "FIPS 204 (ML-DSA)", "FIPS 205 (SLH-DSA)"],
        "note": "All models use real statistical methods that work with pure Python. When scikit-learn/numpy are installed on the VPS, models upgrade to use IsolationForest, LOF, and other advanced algorithms.",
    }


# ---------------------------------------------------------------------------
# Anomaly Detection
# ---------------------------------------------------------------------------

@router.post("/anomaly-detection")
async def api_anomaly_detection(
    req: AnomalyDetectionRequest,
    current_user: CurrentUser = Depends(require_permission("ai_ml:read")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Run anomaly detection on platform data."""
    from gds_api.ai_ml.anomaly_detection import run_full_anomaly_analysis
    return await run_full_anomaly_analysis(db, tenant_id=current_user.tenant_id, days=req.days)


# ---------------------------------------------------------------------------
# Predictive Threat Modeling
# ---------------------------------------------------------------------------

@router.post("/predictive-threat")
async def api_predictive_threat(
    req: PredictiveThreatRequest,
    current_user: CurrentUser = Depends(require_permission("ai_ml:read")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Run predictive threat modeling."""
    from gds_api.ai_ml.predictive_threat import run_full_predictive_analysis
    return await run_full_predictive_analysis(db, tenant_id=current_user.tenant_id)


# ---------------------------------------------------------------------------
# UEBA
# ---------------------------------------------------------------------------

@router.post("/ueba")
async def api_ueba(
    req: UEBARequest,
    current_user: CurrentUser = Depends(require_permission("ai_ml:read")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Run User/Entity Behavioral Analytics."""
    from gds_api.ai_ml.behavioral_analytics import run_full_ueba_analysis
    user_id = uuid.UUID(req.user_id) if req.user_id else None
    return await run_full_ueba_analysis(db, tenant_id=current_user.tenant_id, user_id=user_id, days=req.days)


# ---------------------------------------------------------------------------
# Quantum Assessment
# ---------------------------------------------------------------------------

@router.post("/quantum-assessment")
async def api_quantum_assessment(
    req: QuantumAssessmentRequest,
    current_user: CurrentUser = Depends(require_permission("ai_ml:read")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Run quantum-resistant cryptography assessment."""
    from gds_api.ai_ml.quantum_crypto import run_full_quantum_assessment
    return await run_full_quantum_assessment(db, tenant_id=current_user.tenant_id, domains=req.domains)


# ---------------------------------------------------------------------------
# Full Analysis (all models)
# ---------------------------------------------------------------------------

@router.post("/full-analysis")
async def api_full_analysis(
    req: FullAnalysisRequest,
    current_user: CurrentUser = Depends(require_permission("ai_ml:read")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Run all AI/ML/DL/Quantum models at once."""
    from gds_api.ai_ml.anomaly_detection import run_full_anomaly_analysis
    from gds_api.ai_ml.predictive_threat import run_full_predictive_analysis
    from gds_api.ai_ml.behavioral_analytics import run_full_ueba_analysis
    from gds_api.ai_ml.quantum_crypto import run_full_quantum_assessment

    anomaly = await run_full_anomaly_analysis(db, tenant_id=current_user.tenant_id, days=req.days)
    predictive = await run_full_predictive_analysis(db, tenant_id=current_user.tenant_id)
    ueba = await run_full_ueba_analysis(db, tenant_id=current_user.tenant_id, days=req.days)
    quantum = await run_full_quantum_assessment(db, tenant_id=current_user.tenant_id, domains=req.domains)

    return {
        "success": True,
        "analysis_timestamp": __import__("datetime").datetime.now(__import__("datetime").UTC).isoformat(),
        "anomaly_detection": anomaly,
        "predictive_threat_modeling": predictive,
        "behavioral_analytics": ueba,
        "quantum_crypto_assessment": quantum,
        "summary": {
            "total_findings_created": (
                anomaly.get("total_anomalies", 0)
                + len(predictive.get("top_threats", []))
                + ueba.get("total_findings", 0)
                + quantum.get("findings_created", 0)
            ),
            "models_run": 4,
            "methods": [
                "EWMA Control Chart", "Modified Z-Score (MAD)", "IQR", "Chi-Square",
                "Bayesian Inference (Beta-Binomial)", "Weighted Risk Scoring",
                "Linear Regression (OLS)", "Poisson Distribution", "Shannon Entropy",
                "Shor's Algorithm Estimate", "Grover's Algorithm Impact",
                "NIST PQC Standards (FIPS 203/204/205)",
            ],
        },
    }
