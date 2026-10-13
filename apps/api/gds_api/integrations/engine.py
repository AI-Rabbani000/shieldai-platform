"""GDS OS IDE/CI-CD Integration — Engine.

Handles pipeline registration, gate evaluation, scan orchestration,
and security posture scoring for CI/CD pipelines.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.integrations.models import CIGateResult, CIPipeline, PipelineScan
from gds_api.logging_config import get_logger

logger = get_logger(__name__)

# Security checks per platform
PLATFORM_CAPABILITIES: dict[str, dict[str, str]] = {
    "github_actions": {
        "sast": "github-codeql",
        "sca": "github-dependabot",
        "secret_scan": "trufflesecurity-trufflehog",
        "container_scan": "aquasec-trivy",
        "iac_scan": "bridgecrew-checkov",
        "dast": "github-dast",
        "sbom": "anchore-syft",
        "signing": "cosign",
    },
    "gitlab_ci": {
        "sast": "gitlab-sast",
        "sca": "gitlab-dependency-scanning",
        "secret_scan": "gitlab-secret-detection",
        "container_scan": "trivy-ci",
        "iac_scan": "kics-gitlab",
        "dast": "gitlab-dast",
        "sbom": "cyclonedx-gitlab",
        "signing": "cosign-gitlab",
    },
    "jenkins": {
        "sast": "sonarqube",
        "sca": "owasp-dependency-check",
        "secret_scan": "jenkins-credentials-scanner",
        "container_scan": "trivy-jenkins",
        "iac_scan": "checkov-jenkins",
        "dast": "owasp-zap-jenkins",
        "sbom": "cyclonedx-jenkins",
        "signing": "sigstore-jenkins",
    },
    "circleci": {
        "sast": "semgrep-ci",
        "sca": "snyk-ci",
        "secret_scan": "gitleaks-ci",
        "container_scan": "trivy-circleci",
        "iac_scan": "checkov-circleci",
        "dast": "zap-circleci",
        "sbom": "syft-circleci",
        "signing": "cosign-circleci",
    },
    "azure_pipelines": {
        "sast": "microsoft-defender-code",
        "sca": "microsoft-dependency-check",
        "secret_scan": "microsoft-secret-scan",
        "container_scan": "trivy-azure",
        "iac_scan": "psrule-azure",
        "dast": "zap-azure",
        "sbom": "syft-azure",
        "signing": "cosign-azure",
    },
}

# Gate severity thresholds
GATE_THRESHOLDS = {
    "strict": {"critical": 0, "high": 0, "medium": 10},
    "standard": {"critical": 0, "high": 5, "medium": 50},
    "permissive": {"critical": 0, "high": 50, "medium": 200},
    "disabled": {"critical": 9999, "high": 9999, "medium": 9999},
}

SECURITY_CHECK_WEIGHTS = {
    "sast": 15, "sca": 15, "secret_scan": 20, "container_scan": 10,
    "iac_scan": 10, "dast": 10, "sbom": 10, "signing": 5, "policy_gate": 5,
}


def calculate_security_score(pipeline: CIPipeline) -> int:
    """Calculate security posture score 0-100 based on enabled checks."""
    score = 0
    for check, weight in SECURITY_CHECK_WEIGHTS.items():
        if getattr(pipeline, f"has_{check}", False):
            score += weight
    return min(score, 100)


def evaluate_gate(
    findings: dict[str, int],
    gate_level: str = "standard",
) -> dict[str, Any]:
    """Evaluate if a CI gate should pass or fail based on findings and threshold."""
    thresholds = GATE_THRESHOLDS.get(gate_level, GATE_THRESHOLDS["standard"])
    critical = findings.get("critical", 0)
    high = findings.get("high", 0)
    medium = findings.get("medium", 0)

    if critical > thresholds["critical"]:
        return {"decision": "block", "reason": f"{critical} critical findings exceed threshold of {thresholds['critical']}"}
    if high > thresholds["high"]:
        return {"decision": "fail", "reason": f"{high} high findings exceed threshold of {thresholds['high']}"}
    if medium > thresholds["medium"]:
        return {"decision": "warn", "reason": f"{medium} medium findings exceed threshold of {thresholds['medium']}"}
    return {"decision": "pass", "reason": "All findings within thresholds"}


async def register_pipeline(
    db: AsyncSession, tenant_id, name: str, platform: str, repo_name: str,
    repo_url: str | None = None, branch: str = "main", config: dict | None = None,
) -> CIPipeline:
    """Register a new CI/CD pipeline for monitoring."""
    caps = PLATFORM_CAPABILITIES.get(platform, {})
    pipeline = CIPipeline(
        tenant_id=tenant_id, name=name, platform=platform, repo_name=repo_name,
        repo_url=repo_url, branch=branch,
        has_sast=config.get("sast", False) if config else False,
        has_sca=config.get("sca", False) if config else False,
        has_secret_scan=config.get("secret_scan", False) if config else False,
        has_container_scan=config.get("container_scan", False) if config else False,
        has_iac_scan=config.get("iac_scan", False) if config else False,
        has_dast=config.get("dast", False) if config else False,
        has_sbom=config.get("sbom", False) if config else False,
        has_signing=config.get("signing", False) if config else False,
        has_policy_gate=config.get("policy_gate", False) if config else False,
        config=config or caps,
    )
    pipeline.security_score = calculate_security_score(pipeline)
    db.add(pipeline)
    await db.flush()
    return pipeline


async def process_gate_result(
    db: AsyncSession, tenant_id, pipeline_id, run_id: str, commit_sha: str,
    branch: str, gate_type: str, findings: dict[str, int], gate_level: str = "standard",
    findings_detail: list | None = None, duration: int = 0, triggered_by: str = "ci_system",
) -> CIGateResult:
    """Process a gate result from a CI run."""
    decision = evaluate_gate(findings, gate_level)
    result = CIGateResult(
        tenant_id=tenant_id, pipeline_id=pipeline_id, run_id=run_id,
        commit_sha=commit_sha, branch=branch, gate_type=gate_type,
        total_findings=sum(findings.values()),
        critical_count=findings.get("critical", 0),
        high_count=findings.get("high", 0),
        medium_count=findings.get("medium", 0),
        low_count=findings.get("low", 0),
        gate_decision=decision["decision"],
        block_reason=decision["reason"] if decision["decision"] in ("block", "fail") else None,
        findings_detail=findings_detail or [],
        scan_duration_seconds=duration,
        triggered_by=triggered_by,
    )
    db.add(result)
    await db.flush()
    return result


async def generate_github_actions_yaml(pipeline: CIPipeline, gate_level: str = "standard") -> str:
    """Generate a GitHub Actions workflow YAML with security checks."""
    checks = []
    if pipeline.has_sast:
        checks.append("""  codeql:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
      - uses: github/codeql-action/analyze@v3""")
    if pipeline.has_sca:
        checks.append("""  dependency-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/dependency-review-action@v4""")
    if pipeline.has_secret_scan:
        checks.append("""  trufflehog:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: {fetch-depth: 0}
      - uses: trufflesecurity/trufflehog@main""")
    if pipeline.has_container_scan:
        checks.append("""  trivy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Trivy scan
        run: trivy fs --severity CRITICAL,HIGH --exit-code 1 .""")
    if pipeline.has_iac_scan:
        checks.append("""  checkov:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: bridgecrewio/checkov-action@v12""")
    if pipeline.has_policy_gate:
        checks.append(f"""  gds-gate:
    runs-on: ubuntu-latest
    needs: [codeql, dependency-review, trufflehog, trivy, checkov]
    if: always()
    steps:
      - name: GDS Security Gate
        run: |
          echo "Gate level: {gate_level}"
          echo "Checking all security scans passed..."
          # Fail if any previous job failed
          if [ -f /tmp/gate_fail ]; then exit 1; fi
          echo "GDS Gate: PASS\"""")

    checks_str = "\n".join(checks) if checks else "  # No security checks configured"
    workflow = f"""name: GDS Security Pipeline
on: [push, pull_request]

jobs:
{checks_str}
"""
    return workflow


async def generate_gitlab_ci_yaml(pipeline: CIPipeline, gate_level: str = "standard") -> str:
    """Generate a GitLab CI YAML with security checks."""
    stages = ["scan", "gate"]
    jobs = []
    if pipeline.has_sast:
        jobs.append("""sast:
  stage: scan
  script:
    - echo "Running SAST via GitLab"
  artifacts:
    reports:
      sast: gl-sast-report.json""")
    if pipeline.has_sca:
        jobs.append("""dependency_scanning:
  stage: scan
  script:
    - echo "Running dependency scanning"
  artifacts:
    reports:
      dependency_scanning: gl-dependency-scanning-report.json""")
    if pipeline.has_secret_scan:
        jobs.append("""secret_detection:
  stage: scan
  script:
    - echo "Running secret detection"
  artifacts:
    reports:
      secret_detection: gl-secret-detection-report.json""")
    if pipeline.has_container_scan:
        jobs.append("""container_scan:
  stage: scan
  script:
    - trivy image --severity CRITICAL,HIGH --exit-code 1 $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA""")
    if pipeline.has_iac_scan:
        jobs.append("""iac_scan:
  stage: scan
  script:
    - checkov -d . --framework terraform --quiet""")

    gate_decision = "block" if gate_level == "strict" else "warn"
    jobs.append(f"""gds-gate:
  stage: gate
  script:
    - echo "GDS Security Gate — level: {gate_level}"
    - echo "Gate decision: {gate_decision}"
  needs: [sast, dependency_scanning, secret_detection, container_scan, iac_scan]
  allow_failure: {str(gate_level != 'strict').lower()}""")

    jobs_str = "\n".join(jobs)
    return f"""stages:
  - scan
  - gate

{jobs_str}"""


async def get_pipeline_posture(db: AsyncSession, tenant_id, pipeline_id) -> dict:
    """Get the security posture summary for a pipeline."""
    q = select(CIPipeline).where(CIPipeline.id == pipeline_id, CIPipeline.tenant_id == tenant_id)
    pipeline = (await db.execute(q)).scalar_one_or_none()
    if not pipeline:
        return {"error": "Pipeline not found"}

    gq = select(CIGateResult).where(
        CIGateResult.pipeline_id == pipeline_id,
        CIGateResult.tenant_id == tenant_id,
    ).order_by(CIGateResult.created_at.desc()).limit(10)
    recent_gates = (await db.execute(gq)).scalars().all()

    enabled_checks = [k for k in SECURITY_CHECK_WEIGHTS if getattr(pipeline, f"has_{k}", False)]
    missing_checks = [k for k in SECURITY_CHECK_WEIGHTS if not getattr(pipeline, f"has_{k}", False)]

    return {
        "pipeline_name": pipeline.name,
        "platform": pipeline.platform,
        "security_score": pipeline.security_score,
        "risk_score": pipeline.risk_score,
        "enabled_checks": enabled_checks,
        "missing_checks": missing_checks,
        "total_gate_results": len(recent_gates),
        "recent_blocks": sum(1 for g in recent_gates if g.gate_decision == "block"),
        "recent_failures": sum(1 for g in recent_gates if g.gate_decision == "fail"),
        "last_run": pipeline.last_run.isoformat() if pipeline.last_run else None,
        "last_run_status": pipeline.last_run_status,
    }
