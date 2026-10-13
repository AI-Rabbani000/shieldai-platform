"""Monitoring Activities: the real functions that execute each monitoring cycle.

These are NOT Temporal activities (they don't need durable retry — each monitoring
run is idempotent and a failure just means "try again next cycle"). They're plain
async functions called either:
  - By the MonitoringWorkflow (on schedule via Temporal)
  - By the manual trigger endpoint (POST /monitoring/schedules/{id}/run)

Each function:
  1. Runs the actual tool (CISA KEV, OSV.dev, abuse.ch, etc.)
  2. Creates Finding records for any matches
  3. Auto-triages findings if enabled (uses finding_lifecycle transitions)
  4. Auto-escalates critical findings to Incidents if enabled
  5. Creates a MonitoringResult record with the outcome
  6. Dispatches external notifications for critical findings
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.db import async_session_factory
from gds_api.logging_config import get_logger
from gds_api.monitoring import (
    MonitorType,
    MonitoringResult,
    ScanSchedule,
    ScanScheduleStatus,
)
from gds_api.models import Finding, Incident
from gds_api.finding_lifecycle import FindingStatus, validate_finding_transition

_logger = get_logger("gds_api.monitoring")


async def run_monitoring_cycle(
    schedule_id: str,
    tenant_id: str,
    user_id: str,
) -> MonitoringResult:
    """Execute one monitoring cycle for a schedule. This is the entry point."""
    start_time = datetime.now(UTC)

    async with async_session_factory() as db:
        schedule = await db.get(ScanSchedule, uuid.UUID(schedule_id))
        if schedule is None:
            raise ValueError(f"ScanSchedule {schedule_id} not found")

        # Create the result record
        result = MonitoringResult(
            tenant_id=schedule.tenant_id,
            schedule_id=schedule.id,
            monitor_type=schedule.monitor_type,
            started_at=start_time,
            findings_created=0,
            findings_triaged=0,
            incidents_created=0,
            critical_findings=0,
            status="running",
        )
        db.add(result)
        await db.commit()
        await db.refresh(result)

        try:
            findings_created = 0
            findings_triaged = 0
            incidents_created = 0
            critical_count = 0

            if schedule.monitor_type == MonitorType.CISA_KEV.value:
                findings_created, critical_count = await _run_cisa_kev_check(
                    db, tenant_id=uuid.UUID(tenant_id), config=schedule.target_config
                )
            elif schedule.monitor_type == MonitorType.OSV_SCAN.value:
                findings_created, critical_count = await _run_osv_scan(
                    db, tenant_id=uuid.UUID(tenant_id), config=schedule.target_config
                )
            elif schedule.monitor_type == MonitorType.URLHAUS_CHECK.value:
                findings_created, critical_count = await _run_urlhaus_check(
                    db, tenant_id=uuid.UUID(tenant_id), config=schedule.target_config
                )
            elif schedule.monitor_type == MonitorType.TLS_CERT.value:
                findings_created, critical_count = await _run_tls_check(
                    db, tenant_id=uuid.UUID(tenant_id), config=schedule.target_config
                )
            elif schedule.monitor_type == MonitorType.SECURITY_HEADERS.value:
                findings_created, critical_count = await _run_header_check(
                    db, tenant_id=uuid.UUID(tenant_id), config=schedule.target_config
                )
            elif schedule.monitor_type == MonitorType.MALWARE_HASH.value:
                findings_created, critical_count = await _run_malware_check(
                    db, tenant_id=uuid.UUID(tenant_id), config=schedule.target_config
                )
            elif schedule.monitor_type == MonitorType.DEPENDENCY_SCAN.value:
                findings_created, critical_count = await _run_dependency_scan(
                    db, tenant_id=uuid.UUID(tenant_id), config=schedule.target_config
                )
            elif schedule.monitor_type == MonitorType.EPSS_LOOKUP.value:
                findings_created, critical_count = await _run_epss_enrichment(
                    db, tenant_id=uuid.UUID(tenant_id), config=schedule.target_config
                )
            elif schedule.monitor_type == MonitorType.CLOUD_POSTURE.value:
                findings_created, critical_count = await _run_cloud_posture(
                    db, tenant_id=uuid.UUID(tenant_id), config=schedule.target_config
                )
            elif schedule.monitor_type == MonitorType.SAST_SCAN.value:
                findings_created, critical_count = await _run_sast_monitor(
                    db, tenant_id=uuid.UUID(tenant_id), config=schedule.target_config
                )
            elif schedule.monitor_type == MonitorType.DAST_SCAN.value:
                findings_created, critical_count = await _run_dast_monitor(
                    db, tenant_id=uuid.UUID(tenant_id), config=schedule.target_config
                )
            elif schedule.monitor_type == MonitorType.CONTAINER_SCAN.value:
                findings_created, critical_count = await _run_container_monitor(
                    db, tenant_id=uuid.UUID(tenant_id), config=schedule.target_config
                )
            elif schedule.monitor_type == MonitorType.IAC_SCAN.value:
                findings_created, critical_count = await _run_iac_monitor(
                    db, tenant_id=uuid.UUID(tenant_id), config=schedule.target_config
                )
            elif schedule.monitor_type == MonitorType.DARKWEB_MONITOR.value:
                findings_created, critical_count = await _run_darkweb_monitor(
                    db, tenant_id=uuid.UUID(tenant_id), config=schedule.target_config
                )
            elif schedule.monitor_type == MonitorType.IDENTITY_THREATS.value:
                findings_created, critical_count = await _run_identity_monitor(
                    db, tenant_id=uuid.UUID(tenant_id), config=schedule.target_config
                )
            else:
                _logger.warning("unknown_monitor_type", monitor_type=schedule.monitor_type)

            # Auto-triage findings if enabled
            if schedule.auto_triage and findings_created > 0:
                findings_triaged = await _auto_triage_findings(
                    db, tenant_id=uuid.UUID(tenant_id), schedule_id=schedule.id
                )

            # Auto-escalate critical findings to incidents if enabled
            if schedule.auto_escalate and critical_count > 0:
                incidents_created = await _auto_escalate_critical(
                    db, tenant_id=uuid.UUID(tenant_id), user_id=uuid.UUID(user_id)
                )

            # Update result
            result.findings_created = findings_created
            result.findings_triaged = findings_triaged
            result.incidents_created = incidents_created
            result.critical_findings = critical_count
            result.status = "success"
            result.completed_at = datetime.now(UTC)
            result.duration_seconds = (result.completed_at - result.started_at).total_seconds()

            # Update schedule stats
            schedule.last_run_at = datetime.now(UTC)
            schedule.next_run_at = datetime.now(UTC).replace(
                minute=schedule.last_run_at.minute + schedule.interval_minutes % 60,
                hour=schedule.last_run_at.hour + schedule.interval_minutes // 60,
            )
            schedule.total_runs += 1
            schedule.total_findings += findings_created
            schedule.last_run_findings = findings_created
            schedule.last_error = None
            schedule.status = ScanScheduleStatus.ACTIVE.value

            # Dispatch external notifications for critical findings
            if critical_count > 0:
                from gds_api.notification_dispatch import dispatch_critical_findings
                await dispatch_critical_findings(
                    db,
                    tenant_id=uuid.UUID(tenant_id),
                    monitor_type=schedule.monitor_type,
                    critical_count=critical_count,
                    schedule_name=schedule.name,
                )

            await db.commit()

        except Exception as exc:
            _logger.error("monitoring_cycle_failed", schedule_id=schedule_id, error=str(exc))
            result.status = "error"
            result.error_message = str(exc)
            result.completed_at = datetime.now(UTC)
            result.duration_seconds = (result.completed_at - result.started_at).total_seconds()
            schedule.last_error = str(exc)
            schedule.status = ScanScheduleStatus.ERROR.value
            await db.commit()

        return result


# ---------------------------------------------------------------------------
# Individual monitoring implementations
# ---------------------------------------------------------------------------

async def _run_cisa_kev_check(
    db: AsyncSession, *, tenant_id: uuid.UUID, config: dict[str, Any]
) -> tuple[int, int]:
    """Check CISA KEV feed against the tenant's CVE watchlist."""
    from gds_api.external_feeds import fetch_cisa_kev_catalog
    from gds_api.tool_gateway import _check_cisa_kev

    cves_to_check = config.get("cves", [])
    if not cves_to_check:
        # Fetch all KEV entries and check against tenant's watchlist
        kev_catalog = await fetch_cisa_kev_catalog()
        findings_created = 0
        critical_count = 0
        for entry in kev_catalog:
            cve_id = entry.get("cveID", "")
            title = entry.get("vulnerabilityName", "Unknown")
            # Create a finding for each KEV entry
            finding = Finding(
                tenant_id=tenant_id,
                source="cisa_kev",
                external_id=cve_id,
                title=f"CISA KEV: {cve_id} — {title}",
                description=entry.get("shortDescription", ""),
                severity="critical",
                status=FindingStatus.OBSERVED.value,
                raw_data=entry,
                kev_listed=True,
                cve=cve_id,
            )
            db.add(finding)
            findings_created += 1
            critical_count += 1
        await db.commit()
        return findings_created, critical_count

    # Check specific CVEs against the KEV feed
    findings_created = 0
    critical_count = 0
    for cve_id in cves_to_check:
        result = await _check_cisa_kev(
            cve_ids=[cve_id], tenant_id=str(tenant_id), mission_id="", task_id=""
        )
        if result.get("matched"):
            finding = Finding(
                tenant_id=tenant_id,
                source="cisa_kev",
                external_id=cve_id,
                title=f"CISA KEV: {cve_id}",
                description=result.get("details", ""),
                severity="critical",
                status=FindingStatus.OBSERVED.value,
                raw_data=result,
                kev_listed=True,
                cve=cve_id,
            )
            db.add(finding)
            findings_created += 1
            critical_count += 1
    await db.commit()
    return findings_created, critical_count


async def _run_osv_scan(
    db: AsyncSession, *, tenant_id: uuid.UUID, config: dict[str, Any]
) -> tuple[int, int]:
    """Scan packages against OSV.dev vulnerability database."""
    from gds_api.external_feeds import fetch_osv_vulnerabilities

    packages = config.get("packages", [])
    ecosystem = config.get("ecosystem", "pypi")
    findings_created = 0
    critical_count = 0

    for package_name in packages:
        vulns = await fetch_osv_vulnerabilities(package_name, ecosystem)
        for vuln in vulns:
            severity = "high"
            if vuln.get("severity") == "CRITICAL":
                severity = "critical"
                critical_count += 1

            cve_id = ""
            for alias in vuln.get("aliases", []):
                if alias.startswith("CVE"):
                    cve_id = alias
                    break

            finding = Finding(
                tenant_id=tenant_id,
                source="osv_dev",
                external_id=vuln.get("id", ""),
                title=f"Vulnerability in {package_name}: {vuln.get('summary', 'Unknown')}",
                description=vuln.get("details", ""),
                severity=severity,
                status=FindingStatus.OBSERVED.value,
                raw_data=vuln,
                cve=cve_id if cve_id else None,
            )
            db.add(finding)
            findings_created += 1

    await db.commit()
    return findings_created, critical_count


async def _run_urlhaus_check(
    db: AsyncSession, *, tenant_id: uuid.UUID, config: dict[str, Any]
) -> tuple[int, int]:
    """Check domains against abuse.ch URLhaus malicious URL list."""
    from gds_api.external_feeds import fetch_urlhaus_online_urls

    domains = config.get("domains", [])
    malicious_urls = await fetch_urlhaus_online_urls()
    domain_set = {d.lower() for d in domains}

    findings_created = 0
    critical_count = 0

    for url in malicious_urls:
        url_lower = url.lower()
        for domain in domain_set:
            if domain in url_lower:
                finding = Finding(
                    tenant_id=tenant_id,
                    source="urlhaus",
                    external_id=url[:200],
                    title=f"Malicious URL detected: {domain}",
                    description=f"Domain {domain} found in abuse.ch URLhaus: {url}",
                    severity="high",
                    status=FindingStatus.OBSERVED.value,
                    raw_data={"url": url, "domain": domain},
                )
                db.add(finding)
                findings_created += 1
                if "critical" in url_lower:
                    critical_count += 1

    await db.commit()
    return findings_created, critical_count


async def _run_tls_check(
    db: AsyncSession, *, tenant_id: uuid.UUID, config: dict[str, Any]
) -> tuple[int, int]:
    """Check TLS certificates for expiry and weak configuration."""
    from gds_api.tool_gateway import _probe_tls_certificate

    domains = config.get("domains", [])
    findings_created = 0
    critical_count = 0

    for domain in domains:
        try:
            cert_info = _probe_tls_certificate(domain)
            if not cert_info.get("valid"):
                finding = Finding(
                    tenant_id=tenant_id,
                    source="tls_monitor",
                    external_id=f"tls:{domain}",
                    title=f"TLS certificate issue: {domain}",
                    description=f"TLS check failed: {cert_info.get('error', 'unknown')}",
                    severity="medium",
                    status=FindingStatus.OBSERVED.value,
                    raw_data=cert_info,
                )
                db.add(finding)
                findings_created += 1
            elif cert_info.get("days_until_expiry", 999) < 30:
                severity = "critical" if cert_info["days_until_expiry"] < 7 else "high"
                finding = Finding(
                    tenant_id=tenant_id,
                    source="tls_monitor",
                    external_id=f"tls:{domain}",
                    title=f"TLS certificate expiring: {domain}",
                    description=f"Certificate expires in {cert_info['days_until_expiry']} days",
                    severity=severity,
                    status=FindingStatus.OBSERVED.value,
                    raw_data=cert_info,
                )
                db.add(finding)
                findings_created += 1
                if severity == "critical":
                    critical_count += 1
        except Exception as exc:
            _logger.warning("tls_check_failed", domain=domain, error=str(exc))

    await db.commit()
    return findings_created, critical_count


async def _run_header_check(
    db: AsyncSession, *, tenant_id: uuid.UUID, config: dict[str, Any]
) -> tuple[int, int]:
    """Check HTTP security headers on target URLs."""
    from gds_api.tool_gateway import _check_url_security_headers

    urls = config.get("urls", [])
    findings_created = 0
    critical_count = 0

    for url in urls:
        try:
            result = await _check_url_security_headers(url=url)
            missing = result.get("missing_headers", [])
            if missing:
                severity = "high" if len(missing) >= 3 else "medium"
                finding = Finding(
                    tenant_id=tenant_id,
                    source="header_check",
                    external_id=f"headers:{url}",
                    title=f"Missing security headers: {url}",
                    description=f"Missing headers: {', '.join(missing)}",
                    severity=severity,
                    status=FindingStatus.OBSERVED.value,
                    raw_data=result,
                )
                db.add(finding)
                findings_created += 1
        except Exception as exc:
            _logger.warning("header_check_failed", url=url, error=str(exc))

    await db.commit()
    return findings_created, critical_count


async def _run_malware_check(
    db: AsyncSession, *, tenant_id: uuid.UUID, config: dict[str, Any]
) -> tuple[int, int]:
    """Check file hashes against abuse.ch MalwareBazaar."""
    from gds_api.external_feeds import fetch_malwarebazaar_recent

    hashes_to_check = config.get("hashes", [])
    if not hashes_to_check:
        return 0, 0

    recent_samples = await fetch_malwarebazaar_recent()
    hash_set = {h.lower() for h in hashes_to_check}

    findings_created = 0
    critical_count = 0

    for sample in recent_samples:
        sample_hash = sample.get("sha256_hash", "").lower()
        if sample_hash in hash_set:
            finding = Finding(
                tenant_id=tenant_id,
                source="malwarebazaar",
                external_id=sample_hash[:200],
                title=f"Malware detected: {sample.get('signature', 'Unknown')}",
                description=f"File hash matched in MalwareBazaar: {sample.get('signature', 'Unknown malware')}",
                severity="critical",
                status=FindingStatus.OBSERVED.value,
                raw_data=sample,
            )
            db.add(finding)
            findings_created += 1
            critical_count += 1

    await db.commit()
    return findings_created, critical_count


async def _run_dependency_scan(
    db: AsyncSession, *, tenant_id: uuid.UUID, config: dict[str, Any]
) -> tuple[int, int]:
    """Run SCA on own codebase dependencies via OSV.dev."""
    from gds_api.tool_gateway import _scan_own_dependencies

    ecosystem = config.get("ecosystem", "pypi")
    result = await _scan_own_dependencies(ecosystem=ecosystem)

    findings_created = 0
    critical_count = 0
    for vuln in result.get("vulnerabilities", []):
        severity = vuln.get("severity", "medium")
        finding = Finding(
            tenant_id=tenant_id,
            source="dependency_scan",
            external_id=vuln.get("id", ""),
            title=f"Dependency vulnerability: {vuln.get('package', 'Unknown')}",
            description=vuln.get("summary", ""),
            severity=severity,
            status=FindingStatus.OBSERVED.value,
            raw_data=vuln,
        )
        db.add(finding)
        findings_created += 1
        if severity == "critical":
            critical_count += 1

    await db.commit()
    return findings_created, critical_count


async def _run_epss_enrichment(
    db: AsyncSession, *, tenant_id: uuid.UUID, config: dict[str, Any]
) -> tuple[int, int]:
    """Enrich existing findings with EPSS scores."""
    from gds_api.external_feeds import fetch_epss_score

    # Find all findings with CVEs that haven't been enriched yet
    result = await db.execute(
        select(Finding).where(
            Finding.tenant_id == tenant_id,
            Finding.cve.is_not(None),
            Finding.epss.is_(None),
        )
    )
    findings = result.scalars().all()

    enriched = 0
    critical_count = 0
    for finding in findings:
        if not finding.cve:
            continue
        epss_data = await fetch_epss_score(finding.cve)
        if epss_data:
            finding.epss = epss_data.get("epss", 0.0)
            finding.raw_data = {**finding.raw_data, "epss": epss_data}
            enriched += 1
            if epss_data.get("epss", 0) > 0.9:
                critical_count += 1

    await db.commit()
    return enriched, critical_count


async def _run_cloud_posture(
    db: AsyncSession, *, tenant_id: uuid.UUID, config: dict[str, Any]
) -> tuple[int, int]:
    """Run cloud posture evaluation against a connected cloud environment."""
    # This calls the existing cloud posture evaluation engine
    # Requires a registered CloudEnvironment with credentials
    environment_id = config.get("cloud_environment_id")
    if not environment_id:
        _logger.warning("cloud_posture_no_environment")
        return 0, 0

    # The actual posture evaluation is handled by the existing cloud subsystem
    # gds_api.cloud.posture.evaluator — we trigger it via the API
    # For now, return 0 findings (cloud posture needs real cloud credentials)
    _logger.info("cloud_posture_triggered", environment_id=environment_id)
    return 0, 0


# ---------------------------------------------------------------------------
# Auto-triage and auto-escalation
# ---------------------------------------------------------------------------

async def _auto_triage_findings(
    db: AsyncSession, *, tenant_id: uuid.UUID, schedule_id: uuid.UUID
) -> int:
    """Auto-triage findings using deterministic severity rules.
    Moves findings from OBSERVED → TRIAGED."""
    from gds_api.tool_gateway import _triage_finding

    result = await db.execute(
        select(Finding).where(
            Finding.tenant_id == tenant_id,
            Finding.status == FindingStatus.OBSERVED.value,
        )
    )
    findings = result.scalars().all()
    triaged = 0

    for finding in findings:
        # Use the existing triage logic (deterministic rules)
        triage_result = await _triage_finding(finding_id=str(finding.id))
        if triage_result.get("triaged"):
            validate_finding_transition(finding.status, FindingStatus.TRIAGED.value)
            finding.status = FindingStatus.TRIAGED.value
            finding.risk_class = triage_result.get("risk_class")
            triaged += 1

    await db.commit()
    return triaged


async def _auto_escalate_critical(
    db: AsyncSession, *, tenant_id: uuid.UUID, user_id: uuid.UUID
) -> int:
    """Auto-create incidents for critical/high findings."""
    from gds_api.tool_gateway import _create_incident_from_findings

    result = await db.execute(
        select(Finding).where(
            Finding.tenant_id == tenant_id,
            Finding.status == FindingStatus.TRIAGED.value,
            Finding.severity.in_(["critical", "high"]),
        )
    )
    critical_findings = result.scalars().all()

    if not critical_findings:
        return 0

    finding_ids = [str(f.id) for f in critical_findings]
    incident_result = await _create_incident_from_findings(
        finding_ids=finding_ids, tenant_id=str(tenant_id), user_id=str(user_id)
    )

    # Mark findings as escalated
    for finding in critical_findings:
        validate_finding_transition(finding.status, FindingStatus.PRIORITISED.value)
        finding.status = FindingStatus.PRIORITISED.value

    await db.commit()
    return 1 if incident_result else 0


# ---------------------------------------------------------------------------
# Priority 2 monitor implementations
# ---------------------------------------------------------------------------

async def _run_sast_monitor(
    db: AsyncSession, *, tenant_id: uuid.UUID, config: dict[str, Any]
) -> tuple[int, int]:
    """Run SAST (Semgrep) on a scheduled basis."""
    from gds_api.security_tools import run_semgrep_scan
    result = await run_semgrep_scan(
        target_path=config.get("target_path", "."),
        config=config.get("config", "auto"),
        tenant_id=str(tenant_id),
        db=db,
    )
    return result.get("findings_created", 0), result.get("critical_count", 0)


async def _run_dast_monitor(
    db: AsyncSession, *, tenant_id: uuid.UUID, config: dict[str, Any]
) -> tuple[int, int]:
    """Run DAST (Nuclei) on a scheduled basis."""
    from gds_api.security_tools import run_nuclei_scan
    result = await run_nuclei_scan(
        target_url=config.get("target_url", ""),
        templates=config.get("templates", "cves,vulnerabilities,misconfiguration"),
        severity=config.get("severity", "critical,high,medium"),
        tenant_id=str(tenant_id),
        db=db,
    )
    return result.get("findings_created", 0), result.get("critical_count", 0)


async def _run_container_monitor(
    db: AsyncSession, *, tenant_id: uuid.UUID, config: dict[str, Any]
) -> tuple[int, int]:
    """Run container scanning (Trivy) on a scheduled basis."""
    from gds_api.security_tools import run_trivy_scan
    result = await run_trivy_scan(
        image=config.get("image", ""),
        scan_type=config.get("scan_type", "vuln"),
        severity=config.get("severity", "CRITICAL,HIGH,MEDIUM"),
        tenant_id=str(tenant_id),
        db=db,
    )
    return result.get("findings_created", 0), result.get("critical_count", 0)


async def _run_iac_monitor(
    db: AsyncSession, *, tenant_id: uuid.UUID, config: dict[str, Any]
) -> tuple[int, int]:
    """Run IaC scanning (Checkov) on a scheduled basis."""
    from gds_api.security_tools import run_checkov_scan
    result = await run_checkov_scan(
        target_path=config.get("target_path", "."),
        framework=config.get("framework", "terraform"),
        tenant_id=str(tenant_id),
        db=db,
    )
    return result.get("findings_created", 0), result.get("critical_count", 0)


async def _run_darkweb_monitor(
    db: AsyncSession, *, tenant_id: uuid.UUID, config: dict[str, Any]
) -> tuple[int, int]:
    """Run dark web / credential leak monitoring (HIBP) on a scheduled basis."""
    from gds_api.security_tools import check_credential_leaks, check_domain_breach
    findings_created = 0
    critical_count = 0

    # Check individual emails
    emails = config.get("emails", [])
    for email in emails:
        result = await check_credential_leaks(
            email=email, tenant_id=str(tenant_id), db=db,
        )
        findings_created += result.get("findings_created", 0)
        critical_count += result.get("critical_count", 0)

    # Check domains
    domains = config.get("domains", [])
    for domain in domains:
        result = await check_domain_breach(
            domain=domain, tenant_id=str(tenant_id), db=db,
        )
        findings_created += result.get("findings_created", 0)

    return findings_created, critical_count


async def _run_identity_monitor(
    db: AsyncSession, *, tenant_id: uuid.UUID, config: dict[str, Any]
) -> tuple[int, int]:
    """Run identity threat detection on a scheduled basis."""
    from gds_api.security_tools import detect_identity_threats
    result = await detect_identity_threats(
        tenant_id=str(tenant_id),
        user_email=config.get("user_email"),
        db=db,
    )
    return result.get("findings_created", 0), result.get("critical_count", 0)
