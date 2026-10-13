"""API routes for the Priority 2 security tools.

These endpoints let users trigger the extended security scans directly:
  POST /security-tools/sast          — Run Semgrep on a code path
  POST /security-tools/dast           — Run Nuclei against a URL
  POST /security-tools/container      — Run Trivy on a Docker image
  POST /security-tools/sbom           — Generate SBOM
  POST /security-tools/iac            — Run Checkov on IaC files
  POST /security-tools/darkweb/email  — Check email against HIBP
  POST /security-tools/darkweb/domain — Check domain against HIBP
  POST /security-tools/identity       — Detect identity threats
  GET  /security-tools/status         — Check which tools are available
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.db import get_db
from gds_api.security import CurrentUser, require_permission
from gds_api.security_tools import (
    run_semgrep_scan,
    run_nuclei_scan,
    run_trivy_scan,
    generate_sbom,
    run_checkov_scan,
    check_credential_leaks,
    check_domain_breach,
    detect_identity_threats,
)
import asyncio

router = APIRouter(prefix="/security-tools", tags=["security-tools"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class SASTRequest(BaseModel):
    target_path: str
    config: str = "auto"


class DASTRequest(BaseModel):
    target_url: str
    templates: str = "cves,vulnerabilities,misconfiguration"
    severity: str = "critical,high,medium"


class ContainerScanRequest(BaseModel):
    image: str
    scan_type: str = "vuln"  # vuln | secret | misconfig
    severity: str = "CRITICAL,HIGH,MEDIUM"


class SBOMRequest(BaseModel):
    target_path: str
    format: str = "cyclonedx"
    project_type: str = "python"  # python | npm


class IaCScanRequest(BaseModel):
    target_path: str
    framework: str = "terraform"  # terraform | cloudformation | kubernetes | dockerfile


class DarkWebEmailRequest(BaseModel):
    email: str


class DarkWebDomainRequest(BaseModel):
    domain: str


class IdentityThreatRequest(BaseModel):
    user_email: str | None = None


# ---------------------------------------------------------------------------
# Status check
# ---------------------------------------------------------------------------

@router.get("/status")
async def tools_status(
    current_user: CurrentUser = Depends(require_permission("security_tools:read")),
) -> dict[str, Any]:
    """Check which security tools are available (CLI binaries installed)."""
    import shutil

    tools = {
        "semgrep": shutil.which("semgrep") is not None,
        "nuclei": shutil.which("nuclei") is not None,
        "trivy": shutil.which("trivy") is not None,
        "checkov": shutil.which("checkov") is not None,
        "pip-audit": shutil.which("pip-audit") is not None,
    }
    available = [name for name, installed in tools.items() if installed]
    missing = [name for name, installed in tools.items() if not installed]

    import os
    apis = {
        "hibp": bool(os.environ.get("HIBP_API_KEY")),
        "copilot_webhook": bool(os.environ.get("COPILOT_WEBHOOK_URL")),
        "slack_webhook": bool(os.environ.get("SLACK_WEBHOOK_URL")),
        "resend": bool(os.environ.get("RESEND_API_KEY")),
    }

    return {
        "cli_tools": tools,
        "available_count": len(available),
        "missing_count": len(missing),
        "missing": missing,
        "api_integrations": apis,
    }


# ---------------------------------------------------------------------------
# SAST
# ---------------------------------------------------------------------------

@router.post("/sast")
async def api_sast_scan(
    req: SASTRequest,
    current_user: CurrentUser = Depends(require_permission("security_tools:write")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Run Semgrep SAST scan on source code."""
    result = await run_semgrep_scan(
        target_path=req.target_path,
        config=req.config,
        tenant_id=str(current_user.tenant_id),
        db=db,
    )
    return result


# ---------------------------------------------------------------------------
# DAST
# ---------------------------------------------------------------------------

@router.post("/dast")
async def api_dast_scan(
    req: DASTRequest,
    current_user: CurrentUser = Depends(require_permission("security_tools:write")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Run Nuclei DAST scan against a URL."""
    result = await run_nuclei_scan(
        target_url=req.target_url,
        templates=req.templates,
        severity=req.severity,
        tenant_id=str(current_user.tenant_id),
        db=db,
    )
    return result


# ---------------------------------------------------------------------------
# Container Scanning
# ---------------------------------------------------------------------------

@router.post("/container")
async def api_container_scan(
    req: ContainerScanRequest,
    current_user: CurrentUser = Depends(require_permission("security_tools:write")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Run Trivy container image scan."""
    result = await run_trivy_scan(
        image=req.image,
        scan_type=req.scan_type,
        severity=req.severity,
        tenant_id=str(current_user.tenant_id),
        db=db,
    )
    return result


# ---------------------------------------------------------------------------
# SBOM
# ---------------------------------------------------------------------------

@router.post("/sbom")
async def api_generate_sbom(
    req: SBOMRequest,
    current_user: CurrentUser = Depends(require_permission("security_tools:write")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Generate Software Bill of Materials."""
    result = await generate_sbom(
        target_path=req.target_path,
        format=req.format,
        project_type=req.project_type,
        tenant_id=str(current_user.tenant_id),
        db=db,
    )
    return result


# ---------------------------------------------------------------------------
# IaC Scanning
# ---------------------------------------------------------------------------

@router.post("/iac")
async def api_iac_scan(
    req: IaCScanRequest,
    current_user: CurrentUser = Depends(require_permission("security_tools:write")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Run Checkov IaC scan."""
    result = await run_checkov_scan(
        target_path=req.target_path,
        framework=req.framework,
        tenant_id=str(current_user.tenant_id),
        db=db,
    )
    return result


# ---------------------------------------------------------------------------
# Dark Web / Credential Leaks
# ---------------------------------------------------------------------------

@router.post("/darkweb/email")
async def api_darkweb_email(
    req: DarkWebEmailRequest,
    current_user: CurrentUser = Depends(require_permission("security_tools:write")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Check email against HaveIBeenPwned for credential leaks."""
    result = await check_credential_leaks(
        email=req.email,
        tenant_id=str(current_user.tenant_id),
        db=db,
    )
    return result


@router.post("/darkweb/domain")
async def api_darkweb_domain(
    req: DarkWebDomainRequest,
    current_user: CurrentUser = Depends(require_permission("security_tools:write")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Check all emails for a domain against HIBP."""
    result = await check_domain_breach(
        domain=req.domain,
        tenant_id=str(current_user.tenant_id),
        db=db,
    )
    return result


# ---------------------------------------------------------------------------
# Identity Threat Detection
# ---------------------------------------------------------------------------

@router.post("/identity")
async def api_identity_threats(
    req: IdentityThreatRequest,
    current_user: CurrentUser = Depends(require_permission("security_tools:write")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Detect identity-based threats."""
    result = await detect_identity_threats(
        tenant_id=str(current_user.tenant_id),
        user_email=req.user_email,
        db=db,
    )
    return result
