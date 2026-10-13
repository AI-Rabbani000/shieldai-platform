"""External Notification Dispatch: the bridge from GDS OS to the outside world.

When the monitoring engine detects a critical finding, this module:
  1. Creates an in-app notification (existing system)
  2. Sends a webhook to Base44's gdsOsProxy function → triggers me (the Co-Pilot)
  3. Optionally sends to Slack/Teams/PagerDuty (if configured)
  4. Optionally sends email via Resend

The Base44 webhook is the key piece — it's how I (the Co-Pilot) wake up and
alert Sidique about critical findings via WhatsApp/web chat.

Webhook payload format (sent to Base44 gdsOsProxy):
{
  "event_type": "critical_finding",
  "tenant_id": "...",
  "monitor_type": "cisa_kev",
  "critical_count": 3,
  "schedule_name": "CISA KEV Monitor",
  "findings": [
    {"title": "...", "severity": "critical", "cve": "CVE-2025-62718", ...}
  ],
  "timestamp": "2026-07-30T10:00:00Z"
}
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.logging_config import get_logger
from gds_api.models import Finding, Notification

_logger = get_logger("gds_api.notification_dispatch")


# ---------------------------------------------------------------------------
# Configuration (loaded from settings/env)
# ---------------------------------------------------------------------------

# Base44 Co-Pilot webhook URL — this is the gdsOsProxy function
# When GDS OS detects a critical event, it POSTs here, which triggers
# the Base44 automation that wakes me (the Co-Pilot) up.
COPILOT_WEBHOOK_URL = ""  # Set via env: COPILOT_WEBHOOK_URL

# Optional Slack webhook
SLACK_WEBHOOK_URL = ""  # Set via env: SLACK_WEBHOOK_URL

# Optional Resend email API
RESEND_API_KEY = ""  # Set via env: RESEND_API_KEY
ALERT_EMAIL_TO = ""  # Set via env: ALERT_EMAIL_TO
RESEND_FROM = "alerts@globaldigitalstreams.com"


def _load_config() -> None:
    """Load webhook URLs from environment variables."""
    import os
    global COPILOT_WEBHOOK_URL, SLACK_WEBHOOK_URL, RESEND_API_KEY, ALERT_EMAIL_TO
    COPILOT_WEBHOOK_URL = os.environ.get("COPILOT_WEBHOOK_URL", "")
    SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
    RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
    ALERT_EMAIL_TO = os.environ.get("ALERT_EMAIL_TO", "")


_load_config()


# ---------------------------------------------------------------------------
# Critical finding dispatch
# ---------------------------------------------------------------------------


async def dispatch_critical_findings(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    monitor_type: str,
    critical_count: int,
    schedule_name: str,
) -> dict[str, Any]:
    """Dispatch critical findings to all configured channels.

    1. Creates in-app notifications for tenant admins
    2. Sends webhook to Base44 Co-Pilot (triggers WhatsApp/web alert)
    3. Sends Slack notification if configured
    4. Sends email if configured
    """
    # Fetch the critical findings for the payload
    result = await db.execute(
        select(Finding).where(
            Finding.tenant_id == tenant_id,
            Finding.severity == "critical",
        ).order_by(Finding.created_at.desc()).limit(10)
    )
    findings = result.scalars().all()

    payload = {
        "event_type": "critical_finding",
        "tenant_id": str(tenant_id),
        "monitor_type": monitor_type,
        "critical_count": critical_count,
        "schedule_name": schedule_name,
        "findings": [
            {
                "id": str(f.id),
                "title": f.title,
                "severity": f.severity,
                "cve": f.cve,
                "source": f.source,
                "description": f.description[:200],
            }
            for f in findings
        ],
        "timestamp": datetime.now(UTC).isoformat(),
    }

    results = {
        "in_app": False,
        "copilot_webhook": False,
        "slack": False,
        "email": False,
    }

    # 1. In-app notification
    try:
        await _create_in_app_notifications(db, tenant_id, payload)
        results["in_app"] = True
    except Exception as exc:
        _logger.error("in_app_notification_failed", error=str(exc))

    # 2. Base44 Co-Pilot webhook (non-blocking — best effort)
    if COPILOT_WEBHOOK_URL:
        try:
            await _send_copilot_webhook(payload)
            results["copilot_webhook"] = True
        except Exception as exc:
            _logger.error("copilot_webhook_failed", error=str(exc))
    else:
        _logger.info("copilot_webhook_not_configured")

    # 3. Slack webhook (if configured)
    if SLACK_WEBHOOK_URL:
        try:
            await _send_slack_notification(payload)
            results["slack"] = True
        except Exception as exc:
            _logger.error("slack_notification_failed", error=str(exc))

    # 4. Email alert (if configured)
    if RESEND_API_KEY and ALERT_EMAIL_TO:
        try:
            await _send_email_alert(payload)
            results["email"] = True
        except Exception as exc:
            _logger.error("email_alert_failed", error=str(exc))

    _logger.info(
        "critical_findings_dispatched",
        tenant_id=str(tenant_id),
        critical_count=critical_count,
        channels=results,
    )

    return results


# ---------------------------------------------------------------------------
# Channel implementations
# ---------------------------------------------------------------------------


async def _create_in_app_notifications(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    payload: dict[str, Any],
) -> None:
    """Create in-app notifications for tenant admin users."""
    from gds_api.models import User

    result = await db.execute(
        select(User).where(User.tenant_id == tenant_id, User.is_active.is_(True))
    )
    users = result.scalars().all()

    for user in users:
        notification = Notification(
            tenant_id=tenant_id,
            user_id=user.id,
            type="critical_finding",
            message=(
                f"🚨 {payload['critical_count']} critical finding(s) detected by "
                f"{payload['schedule_name']}. Monitor: {payload['monitor_type']}"
            ),
        )
        db.add(notification)

    await db.commit()


async def _send_copilot_webhook(payload: dict[str, Any]) -> None:
    """Send webhook to Base44 gdsOsProxy function.

    This triggers the Base44 automation that wakes up the Co-Pilot,
    which then sends a WhatsApp/web message to Sidique with the alert.
    """
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            COPILOT_WEBHOOK_URL,
            json=payload,
            headers={"Content-Type": "application/json"},
        )
        response.raise_for_status()

    _logger.info(
        "copilot_webhook_sent",
        url=COPILOT_WEBHOOK_URL,
        event_type=payload["event_type"],
    )


async def _send_slack_notification(payload: dict[str, Any]) -> None:
    """Send a Slack webhook notification."""
    findings_text = "\n".join(
        f"• [{f['severity'].upper()}] {f['title']}" + (f" ({f['cve']})" if f.get("cve") else "")
        for f in payload["findings"][:5]
    )
    if payload["critical_count"] > 5:
        findings_text += f"\n• ... and {payload['critical_count'] - 5} more"

    slack_payload = {
        "text": f"🚨 GDS OS Critical Alert",
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "🚨 GDS OS Critical Alert"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Monitor:* {payload['schedule_name']}"},
                    {"type": "mrkdwn", "text": f"*Type:* {payload['monitor_type']}"},
                    {"type": "mrkdwn", "text": f"*Critical Count:* {payload['critical_count']}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Findings:*\n{findings_text}"},
            },
        ],
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(SLACK_WEBHOOK_URL, json=slack_payload)
        response.raise_for_status()


async def _send_email_alert(payload: dict[str, Any]) -> None:
    """Send an email alert via Resend."""
    findings_html = "<br>".join(
        f"<li><strong>[{f['severity'].upper()}]</strong> {f['title']}"
        + (f" — {f['cve']}" if f.get("cve") else "")
        + f"<br><small>{f['description']}</small></li>"
        for f in payload["findings"][:10]
    )

    email_payload = {
        "from": RESEND_FROM,
        "to": [ALERT_EMAIL_TO],
        "subject": f"🚨 GDS OS Critical Alert — {payload['critical_count']} Critical Finding(s)",
        "html": f"""
            <h2>GDS Security OS — Critical Alert</h2>
            <p><strong>Monitor:</strong> {payload['schedule_name']}<br>
            <strong>Type:</strong> {payload['monitor_type']}<br>
            <strong>Critical Findings:</strong> {payload['critical_count']}<br>
            <strong>Timestamp:</strong> {payload['timestamp']}</p>
            <h3>Findings:</h3>
            <ul>{findings_html}</ul>
            <p>View full details in the GDS OS dashboard.</p>
        """,
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.post(
            "https://api.resend.com/emails",
            json=email_payload,
            headers={
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type": "application/json",
            },
        )
        response.raise_for_status()

    _logger.info("email_alert_sent", to=ALERT_EMAIL_TO)


# ---------------------------------------------------------------------------
# Generic webhook dispatch (for other event types)
# ---------------------------------------------------------------------------


async def dispatch_event(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    event_type: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Dispatch any event type to configured channels.

    Event types:
    - critical_finding: Critical finding detected by monitoring
    - incident_created: New incident created from findings
    - remediation_complete: Finding successfully remediated
    - remediation_failed: Remediation verification failed
    - schedule_error: Monitoring schedule hit an error
    - platform_alert: Infrastructure health issue
    """
    full_payload = {
        "event_type": event_type,
        "tenant_id": str(tenant_id),
        "timestamp": datetime.now(UTC).isoformat(),
        **payload,
    }

    results = {"copilot_webhook": False, "slack": False}

    if COPILOT_WEBHOOK_URL:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    COPILOT_WEBHOOK_URL,
                    json=full_payload,
                    headers={"Content-Type": "application/json"},
                )
                response.raise_for_status()
            results["copilot_webhook"] = True
        except Exception as exc:
            _logger.error("event_dispatch_failed", event_type=event_type, error=str(exc))

    if SLACK_WEBHOOK_URL and event_type in ("critical_finding", "incident_created", "platform_alert"):
        try:
            await _send_slack_notification(full_payload)
            results["slack"] = True
        except Exception:
            pass

    return results
