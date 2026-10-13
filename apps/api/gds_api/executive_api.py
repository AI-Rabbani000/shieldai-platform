"""EDP-008 Part 6: the one new backend surface the Executive Command Center needs -
a real, governed, audited cross-mission report export. Every other Executive view
(Overview, Mission Portfolio, Attention Queue, Security/Engineering/Workforce/
Governance Overview, Trends, Patterns, Timeline) is built entirely from existing
list endpoints (GET /missions, /findings, /incidents, /evidence, /approvals,
/engineering-sessions, /mission-plans, /agents, /agents/activity,
/metrics/summary) fetched by the frontend - no new listing endpoint was a genuine
gap. Report *export*, however, needs a real, audited, governed backend path
(Section 12/21's own requirement - "do not attempt insecure large-report
generation entirely in the browser", "Audit of sensitive exports") that no
existing endpoint covers at cross-mission scope, mirroring the same real pattern
`GET /missions/{id}/report/export` already established for a single mission.

Real, deliberately modest scope: Finding/Incident inclusion in the report reuses
the exact same PurpleMissionMessage.payload-derived correlation Part 5 established
(see lib/security-correlation.ts's frontend twin) - done here server-side in one
extra query rather than N+1 per mission. Approval inclusion uses the real
MissionTask.approval_id relationship. No fabricated aggregate field is added.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.audit import record_audit_event
from gds_api.db import get_db
from gds_api.models import Approval, Finding, Incident, Mission, MissionTask, PurpleMissionMessage
from gds_api.security import CurrentUser, require_permission

router = APIRouter(prefix="/executive", tags=["executive"])

_VALID_FORMATS = ("json", "markdown", "csv")

_LIMITATIONS: list[str] = [
    "Finding/Incident inclusion is derived from PurpleMissionMessage.payload "
    "references (finding_id/incident_id) recorded by real tool calls - a "
    "finding or incident with no such reference for any mission in scope is "
    "honestly absent here, not proof that no relationship exists.",
    "No IOC, Threat Intelligence, or Detection/Alert model exists in this "
    "platform - none are included because none exist, not because of a query "
    "limitation.",
    "Approval inclusion covers only approvals linked via MissionTask.approval_id "
    "for the missions in scope, not every approval a linked finding's own "
    "remediation work may have separately required.",
]


# EDP-008 Part 8 security review finding: CSV export wrote free-text mission
# objectives directly into cells with no sanitization - a value like
# `=HYPERLINK(...)` or `=cmd|'/c calc'!A1` is interpreted as a live formula by
# Excel/Sheets/LibreOffice on open (CWE-1236). Prefixing a leading
# formula-trigger character with a single quote neutralizes it while leaving the
# visible text unchanged for a human reader - the standard, minimal mitigation.
_CSV_FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: str) -> str:
    if value and value[0] in _CSV_FORMULA_TRIGGERS:
        return f"'{value}"
    return value


def _parse_iso(value: str | None, field_name: str) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, f"'{field_name}' must be a real ISO-8601 timestamp"
        ) from exc


@router.get("/report")
async def export_executive_report(
    export_format: str = "json",
    status_filter: str | None = None,
    mission_type: str | None = None,
    since: str | None = None,
    until: str | None = None,
    current_user: CurrentUser = Depends(require_permission("missions:read")),
    db: AsyncSession = Depends(get_db),
) -> Response:
    if export_format not in _VALID_FORMATS:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, f"export_format must be one of {_VALID_FORMATS}"
        )
    since_dt = _parse_iso(since, "since")
    until_dt = _parse_iso(until, "until")

    query = select(Mission).where(Mission.tenant_id == current_user.tenant_id)
    if status_filter:
        query = query.where(Mission.status == status_filter)
    if mission_type:
        query = query.where(Mission.mission_type == mission_type)
    if since_dt:
        query = query.where(Mission.created_at >= since_dt)
    if until_dt:
        query = query.where(Mission.created_at <= until_dt)
    missions = list((await db.execute(query.order_by(Mission.created_at.desc()))).scalars().all())
    mission_ids = [m.id for m in missions]

    # Real, payload-derived finding/incident correlation - the same real mechanism
    # Part 5 established (PurpleMissionMessage.payload carries {finding_id}/
    # {incident_id} for every real finding/incident-touching tool), done here as one
    # extra query rather than re-fetching per mission.
    finding_ids: set[uuid.UUID] = set()
    incident_ids: set[uuid.UUID] = set()
    mission_finding_map: dict[uuid.UUID, set[uuid.UUID]] = {m.id: set() for m in missions}
    mission_incident_map: dict[uuid.UUID, set[uuid.UUID]] = {m.id: set() for m in missions}
    if mission_ids:
        messages = (
            (
                await db.execute(
                    select(PurpleMissionMessage).where(
                        PurpleMissionMessage.tenant_id == current_user.tenant_id,
                        PurpleMissionMessage.mission_id.in_(mission_ids),
                    )
                )
            )
            .scalars()
            .all()
        )
        for msg in messages:
            payload = msg.payload if isinstance(msg.payload, dict) else {}
            raw_finding_id = payload.get("finding_id")
            raw_incident_id = payload.get("incident_id")
            if isinstance(raw_finding_id, str):
                try:
                    fid = uuid.UUID(raw_finding_id)
                except ValueError:
                    fid = None
                if fid is not None:
                    finding_ids.add(fid)
                    mission_finding_map[msg.mission_id].add(fid)
            if isinstance(raw_incident_id, str):
                try:
                    iid = uuid.UUID(raw_incident_id)
                except ValueError:
                    iid = None
                if iid is not None:
                    incident_ids.add(iid)
                    mission_incident_map[msg.mission_id].add(iid)

    findings: list[Finding] = []
    if finding_ids:
        findings = list(
            (
                await db.execute(
                    select(Finding).where(
                        Finding.tenant_id == current_user.tenant_id, Finding.id.in_(finding_ids)
                    )
                )
            )
            .scalars()
            .all()
        )
    incidents: list[Incident] = []
    if incident_ids:
        incidents = list(
            (
                await db.execute(
                    select(Incident).where(
                        Incident.tenant_id == current_user.tenant_id, Incident.id.in_(incident_ids)
                    )
                )
            )
            .scalars()
            .all()
        )

    # Real approval linkage via MissionTask.approval_id - a different, already-
    # established relationship from the Finding/Incident payload one above.
    approval_ids: set[uuid.UUID] = set()
    if mission_ids:
        task_rows = (
            (
                await db.execute(
                    select(MissionTask.approval_id).where(
                        MissionTask.tenant_id == current_user.tenant_id,
                        MissionTask.mission_id.in_(mission_ids),
                        MissionTask.approval_id.is_not(None),
                    )
                )
            )
            .scalars()
            .all()
        )
        approval_ids = {a for a in task_rows if a is not None}
    approvals: list[Approval] = []
    if approval_ids:
        approvals = list(
            (
                await db.execute(
                    select(Approval).where(
                        Approval.tenant_id == current_user.tenant_id, Approval.id.in_(approval_ids)
                    )
                )
            )
            .scalars()
            .all()
        )

    generated_at = datetime.now().astimezone()
    filters_applied = {
        "status": status_filter,
        "mission_type": mission_type,
        "since": since,
        "until": until,
    }
    report: dict[str, object] = {
        "report_title": "GDS Security OS - Executive Report",
        "generated_at": generated_at.isoformat(),
        "tenant_id": str(current_user.tenant_id),
        "filters_applied": {k: v for k, v in filters_applied.items() if v is not None},
        "mission_count": len(missions),
        "missions": [
            {
                "id": str(m.id),
                "objective": m.objective,
                "status": m.status,
                "mission_type": m.mission_type,
                "risk_class": m.risk_class,
                "created_at": m.created_at.isoformat(),
                "completed_at": m.completed_at.isoformat() if m.completed_at else None,
                "linked_finding_ids": [str(f) for f in mission_finding_map.get(m.id, set())],
                "linked_incident_ids": [str(i) for i in mission_incident_map.get(m.id, set())],
            }
            for m in missions
        ],
        "findings": [
            {
                "id": str(f.id),
                "title": f.title,
                "severity": f.severity,
                "risk_class": f.risk_class,
                "status": f.status,
            }
            for f in findings
        ],
        "incidents": [
            {"id": str(i.id), "title": i.title, "severity": i.severity, "status": i.status}
            for i in incidents
        ],
        "approvals": [
            {
                "id": str(a.id),
                "action_description": a.action_description,
                "risk_class": a.risk_class,
                "status": a.status,
            }
            for a in approvals
        ],
        "limitations": _LIMITATIONS,
    }

    await record_audit_event(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="executive.report_exported",
        detail={
            "export_format": export_format,
            "filters_applied": report["filters_applied"],
            "mission_count": len(missions),
        },
    )
    await db.commit()

    if export_format == "json":
        return Response(
            content=json.dumps(report, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="executive-report.json"'},
        )
    if export_format == "csv":
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(
            ["mission_id", "objective", "status", "mission_type", "risk_class", "created_at"]
        )
        for m in missions:
            writer.writerow(
                [
                    str(m.id),
                    _csv_safe(m.objective),
                    m.status,
                    m.mission_type,
                    m.risk_class,
                    m.created_at.isoformat(),
                ]
            )
        return Response(
            content=buffer.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="executive-report.csv"'},
        )

    lines = [
        "# GDS Security OS - Executive Report",
        "",
        f"**Generated:** {generated_at.isoformat()}",
        f"**Filters applied:** {report['filters_applied'] or 'none'}",
        f"**Missions in scope:** {len(missions)}",
        "",
        "## Missions",
        "",
    ]
    for m in missions:
        lines.append(f"- [{m.status}] {m.objective} (created {m.created_at.isoformat()})")
    lines += ["", "## Findings", ""]
    for f in findings:
        lines.append(f"- [{f.status}] {f.title} (severity: {f.severity})")
    lines += ["", "## Incidents", ""]
    for i in incidents:
        lines.append(f"- [{i.status}] {i.title} (severity: {i.severity})")
    lines += ["", "## Approvals", ""]
    for a in approvals:
        lines.append(f"- [{a.status}] {a.action_description} (risk: {a.risk_class})")
    lines += ["", "## Limitations", ""]
    for limitation in _LIMITATIONS:
        lines.append(f"- {limitation}")

    return Response(
        content="\n".join(lines),
        media_type="text/markdown",
        headers={"Content-Disposition": 'attachment; filename="executive-report.md"'},
    )
