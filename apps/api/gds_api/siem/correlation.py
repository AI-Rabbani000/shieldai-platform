import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.siem.models import CorrelatedIncident, CorrelationRule, SIEMEvent

PREBUILT_RULES = [
    {
        "name": "Brute Force Attempt",
        "description": "Detects 5 or more failed authentication attempts from the same source IP within 5 minutes.",
        "rule_type": "threshold",
        "conditions": {
            "event_category": "authentication",
            "result": "failure",
            "group_by": "src_ip",
        },
        "time_window_seconds": 300,
        "threshold": 5,
        "severity": "high",
        "mitre_technique": "T1110",
        "is_active": True,
    },
    {
        "name": "Impossible Travel",
        "description": "Detects successful authentication for the same user from 2 or more different countries within 1 hour.",
        "rule_type": "aggregation",
        "conditions": {
            "event_category": "authentication",
            "result": "success",
            "group_by": "user",
            "distinct_field": "country",
        },
        "time_window_seconds": 3600,
        "threshold": 2,
        "severity": "critical",
        "mitre_technique": "T1078",
        "is_active": True,
    },
    {
        "name": "Port Scan Activity",
        "description": "Detects connection attempts to 20 or more unique ports from the same source IP in 2 minutes.",
        "rule_type": "aggregation",
        "conditions": {
            "event_category": "network",
            "group_by": "src_ip",
            "distinct_field": "dst_port",
        },
        "time_window_seconds": 120,
        "threshold": 20,
        "severity": "medium",
        "mitre_technique": "T1046",
        "is_active": True,
    },
    {
        "name": "Potential Data Exfiltration",
        "description": "Detects outbound network transfers exceeding 1GB from a single host within 10 minutes.",
        "rule_type": "threshold",
        "conditions": {
            "event_category": "network",
            "action": "outbound_transfer",
            "bytes_transferred_gte": 1073741824,
            "group_by": "src_ip",
        },
        "time_window_seconds": 600,
        "threshold": 1,
        "severity": "critical",
        "mitre_technique": "T1048",
        "is_active": True,
    },
    {
        "name": "Lateral Movement via RDP/SMB",
        "description": "Detects lateral movement attempts using RDP or SMB protocol connections.",
        "rule_type": "threshold",
        "conditions": {
            "event_category": "network",
            "protocol_in": ["RDP", "SMB", "3389", "445"],
            "action": "connection",
            "group_by": "src_ip",
        },
        "time_window_seconds": 300,
        "threshold": 1,
        "severity": "high",
        "mitre_technique": "T1021",
        "is_active": True,
    },
    {
        "name": "C2 Malware Beaconing Pattern",
        "description": "Detects repeated outbound connections to the same external IP address indicating C2 beaconing.",
        "rule_type": "threshold",
        "conditions": {
            "event_category": "network",
            "group_by": "dst_ip",
        },
        "time_window_seconds": 300,
        "threshold": 4,
        "severity": "critical",
        "mitre_technique": "T1071",
        "is_active": True,
    },
    {
        "name": "Privilege Escalation - Admin Group Member Added",
        "description": "Detects addition of a user account to a privileged administrator group.",
        "rule_type": "threshold",
        "conditions": {
            "event_category": "security",
            "action": "add_user_to_group",
            "group_name_contains": "admin",
        },
        "time_window_seconds": 300,
        "threshold": 1,
        "severity": "high",
        "mitre_technique": "T1098",
        "is_active": True,
    },
    {
        "name": "MITRE T1078: Valid Accounts - Admin Login from New Location",
        "description": "Detects successful administrator logins from new/unusual locations.",
        "rule_type": "mitre_match",
        "conditions": {
            "event_category": "authentication",
            "user_contains": "admin",
            "result": "success",
        },
        "time_window_seconds": 300,
        "threshold": 1,
        "severity": "high",
        "mitre_technique": "T1078",
        "is_active": True,
    },
    {
        "name": "MITRE T1110: Brute Force Success",
        "description": "Detects 10 or more auth failures followed by a successful authentication for the same user.",
        "rule_type": "sequence",
        "conditions": {
            "sequence": [{"result": "failure"}, {"result": "success"}],
            "group_by": "user",
            "failure_threshold": 10,
        },
        "time_window_seconds": 600,
        "threshold": 1,
        "severity": "critical",
        "mitre_technique": "T1110",
        "is_active": True,
    },
    {
        "name": "MITRE T1059: Command Execution via Suspicious Parent",
        "description": "Detects command execution processes spawned by unexpected parent processes.",
        "rule_type": "mitre_match",
        "conditions": {
            "source_type": "edr",
            "event_category": "system",
            "action": "process_create",
        },
        "time_window_seconds": 300,
        "threshold": 1,
        "severity": "high",
        "mitre_technique": "T1059",
        "is_active": True,
    },
]


def _get_field_val(ev: SIEMEvent | dict, field: str) -> Any:
    """Extract a field value from SIEMEvent or dict, checking model attributes, normalized, and raw_data."""
    if isinstance(ev, dict):
        if field in ev:
            return ev[field]
        if "." in field:
            parts = field.split(".")
            curr = ev
            for p in parts:
                if isinstance(curr, dict) and p in curr:
                    curr = curr[p]
                else:
                    return None
            return curr
        return None

    # SIEMEvent object
    if hasattr(ev, field):
        val = getattr(ev, field, None)
        if val is not None:
            return val

    norm = getattr(ev, "normalized", {}) or {}
    if isinstance(norm, dict) and field in norm and norm[field] is not None:
        return norm[field]

    raw = getattr(ev, "raw_data", {}) or {}
    if isinstance(raw, dict) and field in raw and raw[field] is not None:
        return raw[field]

    if "." in field:
        parts = field.split(".")
        if parts[0] == "normalized" and isinstance(norm, dict):
            curr = norm
            for p in parts[1:]:
                if isinstance(curr, dict) and p in curr:
                    curr = curr[p]
                else:
                    return None
            return curr
        elif parts[0] == "raw_data" and isinstance(raw, dict):
            curr = raw
            for p in parts[1:]:
                if isinstance(curr, dict) and p in curr:
                    curr = curr[p]
                else:
                    return None
            return curr

    return None


def evaluate_condition(event: SIEMEvent | dict, field: str, operator: str, value: Any) -> bool:
    """Evaluate a single condition against an event."""
    val = _get_field_val(event, field)
    op = operator.lower().strip()

    if op in ("eq", "==", "equals"):
        return str(val) == str(value) if val is not None else False
    elif op in ("ne", "!=", "not_equals"):
        return str(val) != str(value) if val is not None else True
    elif op in ("gt", ">"):
        try:
            return float(val) > float(value)
        except (ValueError, TypeError):
            return False
    elif op in ("gte", ">="):
        try:
            return float(val) >= float(value)
        except (ValueError, TypeError):
            return False
    elif op in ("lt", "<"):
        try:
            return float(val) < float(value)
        except (ValueError, TypeError):
            return False
    elif op in ("lte", "<="):
        try:
            return float(val) <= float(value)
        except (ValueError, TypeError):
            return False
    elif op in ("contains", "icontains"):
        if val is None:
            return False
        return str(value).lower() in str(val).lower()
    elif op in ("in", "in_list"):
        if val is None:
            return False
        if isinstance(value, (list, tuple, set)):
            val_str = str(val).lower()
            return any(str(x).lower() == val_str for x in value)
        return str(val) in str(value)
    elif op == "not_in":
        if val is None:
            return True
        if isinstance(value, (list, tuple, set)):
            val_str = str(val).lower()
            return not any(str(x).lower() == val_str for x in value)
        return str(val) not in str(value)
    elif op in ("regex", "matches"):
        if val is None:
            return False
        try:
            return bool(re.search(str(value), str(val), re.IGNORECASE))
        except Exception:
            return False
    elif op == "startswith":
        if val is None:
            return False
        return str(val).lower().startswith(str(value).lower())
    elif op == "endswith":
        if val is None:
            return False
        return str(val).lower().endswith(str(value).lower())
    elif op == "exists":
        return (val is not None) == bool(value)

    # Default equality check
    return str(val) == str(value) if val is not None else False


def _match_event_conditions(event: SIEMEvent | dict, conditions: dict) -> bool:
    """Evaluate multiple condition rules stored as a dictionary."""
    if not conditions:
        return True

    for k, v in conditions.items():
        # Special keywords ignored in direct event matching
        if k in ("group_by", "distinct_field", "sequence", "failure_threshold"):
            continue

        if k.endswith("_in"):
            field_name = k[:-3]
            if not evaluate_condition(event, field_name, "in", v):
                return False
        elif k.endswith("_gte"):
            field_name = k[:-4]
            if not evaluate_condition(event, field_name, "gte", v):
                return False
        elif k.endswith("_contains"):
            field_name = k[:-9]
            if not evaluate_condition(event, field_name, "contains", v):
                return False
        else:
            if not evaluate_condition(event, k, "eq", v):
                return False

    return True


async def check_threshold_rule(
    db: AsyncSession, tenant_id: uuid.UUID, rule: CorrelationRule, event: SIEMEvent
) -> list[SIEMEvent]:
    """Check if the number of matching events in the time window exceeds the threshold."""
    if not _match_event_conditions(event, rule.conditions):
        return []

    cutoff = datetime.now(UTC) - timedelta(seconds=rule.time_window_seconds)
    stmt = (
        select(SIEMEvent)
        .where(
            SIEMEvent.tenant_id == tenant_id,
            SIEMEvent.event_time >= cutoff,
        )
        .order_by(SIEMEvent.event_time.desc())
    )

    # Grouping filter
    group_by = rule.conditions.get("group_by") if isinstance(rule.conditions, dict) else None
    if group_by:
        group_val = _get_field_val(event, group_by)
        if group_val is None:
            return []
        if group_by == "src_ip":
            stmt = stmt.where(SIEMEvent.src_ip == group_val)
        elif group_by == "dst_ip":
            stmt = stmt.where(SIEMEvent.dst_ip == group_val)
        elif group_by == "user":
            stmt = stmt.where(SIEMEvent.user == group_val)

    results = (await db.execute(stmt)).scalars().all()
    matching_events = [e for e in results if _match_event_conditions(e, rule.conditions)]

    if len(matching_events) >= rule.threshold:
        return matching_events
    return []


async def check_sequence_rule(
    db: AsyncSession, tenant_id: uuid.UUID, rule: CorrelationRule, event: SIEMEvent
) -> list[SIEMEvent]:
    """Check if this event completes a sequence (e.g., failed login followed by successful login from same user/IP)."""
    conditions = rule.conditions if isinstance(rule.conditions, dict) else {}
    seq_steps = conditions.get("sequence", [])
    if not seq_steps or len(seq_steps) < 2:
        return []

    # Verify that the current event matches the final step in sequence
    final_step = seq_steps[-1]
    if not _match_event_conditions(event, final_step):
        return []

    cutoff = datetime.now(UTC) - timedelta(seconds=rule.time_window_seconds)
    stmt = (
        select(SIEMEvent)
        .where(
            SIEMEvent.tenant_id == tenant_id,
            SIEMEvent.event_time >= cutoff,
        )
        .order_by(SIEMEvent.event_time.asc())
    )

    group_by = conditions.get("group_by")
    if group_by:
        group_val = _get_field_val(event, group_by)
        if group_val is None:
            return []
        if group_by == "user":
            stmt = stmt.where(SIEMEvent.user == group_val)
        elif group_by == "src_ip":
            stmt = stmt.where(SIEMEvent.src_ip == group_val)

    events_in_window = (await db.execute(stmt)).scalars().all()

    # Check for preceding step (e.g. failed logins)
    first_step = seq_steps[0]
    preceding_matches = [e for e in events_in_window if e.id != event.id and _match_event_conditions(e, first_step)]

    failure_threshold = conditions.get("failure_threshold", rule.threshold or 1)
    if len(preceding_matches) >= failure_threshold:
        return preceding_matches + [event]

    return []


async def create_correlated_incident(
    db: AsyncSession, tenant_id: uuid.UUID, rule: CorrelationRule, events: list[SIEMEvent]
) -> CorrelatedIncident:
    """Create a CorrelatedIncident from matched events. Mark events as correlated."""
    incident = CorrelatedIncident(
        tenant_id=tenant_id,
        rule_id=rule.id,
        rule_name=rule.name,
        severity=rule.severity,
        event_ids=[str(e.id) for e in events],
        event_count=len(events),
        summary=f"Correlation rule '{rule.name}' triggered with {len(events)} matching event(s).",
        mitre_technique=rule.mitre_technique,
        status="open",
    )

    # Update rule metrics
    rule.fire_count += 1
    rule.last_fired = datetime.now(UTC)

    db.add(incident)
    await db.flush()  # Populate incident.id

    # Mark matching events
    for e in events:
        e.correlated = True
        e.correlation_id = incident.id

    await db.commit()
    await db.refresh(incident)
    return incident


async def seed_default_rules(db: AsyncSession, tenant_id: uuid.UUID) -> list[CorrelationRule]:
    """Seed default pre-built correlation rules for a tenant if none exist."""
    existing = (
        await db.execute(select(CorrelationRule).where(CorrelationRule.tenant_id == tenant_id))
    ).scalars().all()

    if existing:
        return list(existing)

    rules = []
    for p_rule in PREBUILT_RULES:
        r = CorrelationRule(
            tenant_id=tenant_id,
            name=p_rule["name"],
            description=p_rule["description"],
            rule_type=p_rule["rule_type"],
            conditions=p_rule["conditions"],
            time_window_seconds=p_rule["time_window_seconds"],
            threshold=p_rule["threshold"],
            severity=p_rule["severity"],
            mitre_technique=p_rule["mitre_technique"],
            is_active=p_rule["is_active"],
        )
        db.add(r)
        rules.append(r)

    await db.commit()
    for r in rules:
        await db.refresh(r)
    return rules


async def check_correlation_rules(
    db: AsyncSession, tenant_id: uuid.UUID, event: SIEMEvent
) -> list[tuple[CorrelationRule, list[SIEMEvent]]]:
    """Load active correlation rules, check if this event triggers any. Uses time window lookback."""
    rules = (
        await db.execute(
            select(CorrelationRule).where(
                CorrelationRule.tenant_id == tenant_id, CorrelationRule.is_active == True
            )
        )
    ).scalars().all()

    if not rules:
        rules = await seed_default_rules(db, tenant_id)

    triggered: list[tuple[CorrelationRule, list[SIEMEvent]]] = []

    for rule in rules:
        matched_events: list[SIEMEvent] = []

        if rule.rule_type == "threshold":
            matched_events = await check_threshold_rule(db, tenant_id, rule, event)

        elif rule.rule_type == "sequence":
            matched_events = await check_sequence_rule(db, tenant_id, rule, event)

        elif rule.rule_type == "aggregation":
            if _match_event_conditions(event, rule.conditions):
                cutoff = datetime.now(UTC) - timedelta(seconds=rule.time_window_seconds)
                stmt = select(SIEMEvent).where(
                    SIEMEvent.tenant_id == tenant_id,
                    SIEMEvent.event_time >= cutoff,
                )
                group_by = rule.conditions.get("group_by")
                if group_by:
                    group_val = _get_field_val(event, group_by)
                    if group_val and group_by in ("src_ip", "dst_ip", "user"):
                        stmt = stmt.where(getattr(SIEMEvent, group_by) == group_val)

                all_evs = (await db.execute(stmt)).scalars().all()
                candidates = [e for e in all_evs if _match_event_conditions(e, rule.conditions)]

                distinct_field = rule.conditions.get("distinct_field")
                if distinct_field:
                    distinct_vals = {_get_field_val(e, distinct_field) for e in candidates}
                    distinct_vals.discard(None)
                    if len(distinct_vals) >= rule.threshold:
                        matched_events = candidates

        elif rule.rule_type == "mitre_match":
            if _match_event_conditions(event, rule.conditions):
                if rule.threshold <= 1:
                    matched_events = [event]
                else:
                    matched_events = await check_threshold_rule(db, tenant_id, rule, event)

        if matched_events:
            triggered.append((rule, matched_events))

    return triggered


async def correlate_event(
    db: AsyncSession, tenant_id: uuid.UUID, event: SIEMEvent
) -> list[CorrelatedIncident]:
    """Main entry point. Called after ingestion. Checks all rules and creates incidents if thresholds met."""
    triggered_rules = await check_correlation_rules(db, tenant_id, event)
    incidents = []

    for rule, matched_events in triggered_rules:
        inc = await create_correlated_incident(db, tenant_id, rule, matched_events)
        incidents.append(inc)

    return incidents
