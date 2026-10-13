"""Alert rule evaluation engine and entity state change checker."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.alerts.dispatch import dispatch_all
from gds_api.alerts.models import AlertEvent, AlertRule
from gds_api.logging_config import get_logger

logger = get_logger(__name__)


def _get_field_value(data: dict[str, Any], field_path: str) -> Any:
    if not data or not field_path:
        return None
    if field_path in data:
        return data[field_path]
    parts = field_path.split(".")
    curr: Any = data
    for part in parts:
        if isinstance(curr, dict) and part in curr:
            curr = curr[part]
        else:
            return None
    return curr


def evaluate_condition(entity_data: dict[str, Any], field: str, operator: str, value: str) -> bool:
    """Evaluate a condition against entity_data.
    
    Supports operators: eq, ne, contains, not_contains, gt, lt, gte, lte, in_list, exists, is_empty.
    """
    val = _get_field_value(entity_data, field)
    op = (operator or "").lower().strip()

    if op == "exists":
        return val is not None or (isinstance(entity_data, dict) and field in entity_data)

    if op == "is_empty":
        if val is None:
            return True
        if isinstance(val, (str, list, dict, set, tuple)):
            return len(val) == 0
        return False

    if op == "eq":
        if val is None:
            return str(value).lower() in ("none", "null", "")
        try:
            return float(val) == float(value)
        except (ValueError, TypeError):
            return str(val).strip() == str(value).strip()

    if op == "ne":
        return not evaluate_condition(entity_data, field, "eq", value)

    if op == "contains":
        if val is None:
            return False
        if isinstance(val, (list, tuple, set)):
            return str(value) in [str(x) for x in val]
        return str(value).lower() in str(val).lower()

    if op == "not_contains":
        return not evaluate_condition(entity_data, field, "contains", value)

    if op == "gt":
        if val is None:
            return False
        try:
            return float(val) > float(value)
        except (ValueError, TypeError):
            return False

    if op == "lt":
        if val is None:
            return False
        try:
            return float(val) < float(value)
        except (ValueError, TypeError):
            return False

    if op == "gte":
        if val is None:
            return False
        try:
            return float(val) >= float(value)
        except (ValueError, TypeError):
            return False

    if op == "lte":
        if val is None:
            return False
        try:
            return float(val) <= float(value)
        except (ValueError, TypeError):
            return False

    if op == "in_list":
        if val is None:
            return False
        items: list[str] = []
        val_str = str(value).strip()
        if val_str.startswith("[") and val_str.endswith("]"):
            try:
                parsed = json.loads(val_str)
                if isinstance(parsed, list):
                    items = [str(x).strip().lower() for x in parsed]
            except json.JSONDecodeError:
                pass
        if not items:
            items = [x.strip().lower() for x in val_str.split(",")]
        return str(val).strip().lower() in items

    logger.warning("Unsupported operator encountered in alert evaluation", operator=operator)
    return False


async def evaluate_rules(
    db: AsyncSession, tenant_id: uuid.UUID, entity_type: str, entity_data: dict[str, Any]
) -> list[AlertRule]:
    """Load active rules, evaluate each against entity_data, respecting cooldown."""
    stmt = select(AlertRule).where(
        AlertRule.tenant_id == tenant_id,
        AlertRule.entity_type == entity_type,
        AlertRule.is_active == True,
    )
    res = await db.execute(stmt)
    rules = list(res.scalars().all())

    now = datetime.now(UTC)
    matched_rules: list[AlertRule] = []

    for rule in rules:
        if rule.last_fired and rule.cooldown_minutes and rule.cooldown_minutes > 0:
            last_fired = rule.last_fired
            if last_fired.tzinfo is None:
                last_fired = last_fired.replace(tzinfo=UTC)
            elapsed_minutes = (now - last_fired).total_seconds() / 60.0
            if elapsed_minutes < rule.cooldown_minutes:
                logger.debug(
                    "Skipping alert rule due to cooldown",
                    rule_id=str(rule.id),
                    cooldown_minutes=rule.cooldown_minutes,
                    elapsed_minutes=elapsed_minutes,
                )
                continue

        if evaluate_condition(
            entity_data, rule.condition_field, rule.condition_operator, rule.condition_value
        ):
            matched_rules.append(rule)

    return matched_rules


async def fire_alert(
    db: AsyncSession, tenant_id: uuid.UUID, rule: AlertRule, entity_data: dict[str, Any]
) -> AlertEvent:
    """Create event, dispatch to channels, and update rule last_fired & fire_count."""
    entity_id = str(
        entity_data.get("id")
        or entity_data.get("entity_id")
        or entity_data.get("uuid")
        or "unknown"
    )
    entity_title = str(
        entity_data.get("title")
        or entity_data.get("name")
        or entity_data.get("summary")
        or f"{rule.entity_type} {entity_id}"
    )

    alert_data = {
        "rule_id": str(rule.id),
        "rule_name": rule.name,
        "entity_type": rule.entity_type,
        "entity_id": entity_id,
        "entity_title": entity_title,
        "severity": rule.severity,
        "condition_field": rule.condition_field,
        "condition_operator": rule.condition_operator,
        "condition_value": rule.condition_value,
        "data": entity_data,
        "timestamp": datetime.now(UTC).isoformat(),
    }

    channels = rule.channels or []
    dispatch_res = await dispatch_all(channels, alert_data)

    now = datetime.now(UTC)
    rule.last_fired = now
    rule.fire_count = (rule.fire_count or 0) + 1

    event = AlertEvent(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        rule_id=rule.id,
        rule_name=rule.name,
        entity_type=rule.entity_type,
        entity_id=entity_id,
        entity_title=entity_title,
        severity=rule.severity,
        channels_dispatched=channels,
        delivery_results=dispatch_res.get("results", []),
        status="dispatched",
        created_at=now,
    )

    db.add(event)
    await db.commit()
    await db.refresh(event)

    return event


async def check_entity_change(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    entity_type: str,
    entity_id: str,
    old_data: dict[str, Any] | None,
    new_data: dict[str, Any],
) -> list[AlertEvent]:
    """Main entry point for checking entity state changes and evaluating rules."""
    data_to_check = dict(new_data or {})
    if "id" not in data_to_check and "entity_id" not in data_to_check:
        data_to_check["id"] = entity_id

    rules = await evaluate_rules(db, tenant_id, entity_type, data_to_check)
    events: list[AlertEvent] = []

    for rule in rules:
        event = await fire_alert(db, tenant_id, rule, data_to_check)
        events.append(event)

    return events
