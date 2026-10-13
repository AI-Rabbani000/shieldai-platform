"""Phase 20 (Continuation Prompt 7 / EDP-007), Part 8: the 28 authoritative Purple
Workforce collaboration message types (EDP-007's own Part 8 message-type list has
28 entries, not the 29 originally assumed here - recounted and corrected against
the actual prompt text) and the one real, audited write path for
them - `record_purple_message()`. See models.PurpleMissionMessage for why this is
a new table rather than a generalisation of Phase 19's engineering-specific
MissionMessage, and ADR 0032 for the full reasoning.

No hidden or unaudited inter-agent communication: every real Purple Workforce
inter-agent message is a real row here, visible on the mission timeline via
GET /missions/{id}/messages (Part 14's backend contract), never an out-of-band
channel. Only operationally useful reasoning summaries, decisions, evidence and
outcomes are stored - never raw model chain-of-thought, per Prompt 7 Part 8's
explicit rule.
"""

from __future__ import annotations

import uuid
from enum import StrEnum

from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.events import publish_mission_event
from gds_api.metrics import purple_messages_total
from gds_api.models import PurpleMissionMessage


class PurpleMessageType(StrEnum):
    ASSIGNMENT = "assignment"
    QUESTION = "question"
    ANSWER = "answer"
    FINDING_CREATED = "finding_created"
    FINDING_CONFIRMED = "finding_confirmed"
    FINDING_REJECTED = "finding_rejected"
    IOC_DISCOVERED = "ioc_discovered"
    ASSET_DISCOVERED = "asset_discovered"
    VULNERABILITY_DISCOVERED = "vulnerability_discovered"
    EXPLOITABILITY_ASSESSED = "exploitability_assessed"
    ATTACK_PATH_DISCOVERED = "attack_path_discovered"
    INCIDENT_CREATED = "incident_created"
    CONTAINMENT_REQUESTED = "containment_requested"
    DETECTION_REQUESTED = "detection_requested"
    REMEDIATION_REQUESTED = "remediation_requested"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_RESOLVED = "approval_resolved"
    BLOCKED = "blocked"
    SCOPE_VIOLATION = "scope_violation"
    SAFETY_STOP = "safety_stop"
    EVIDENCE_ADDED = "evidence_added"
    TASK_COMPLETED = "task_completed"
    RETEST_REQUESTED = "retest_requested"
    RETEST_PASSED = "retest_passed"
    RETEST_FAILED = "retest_failed"
    RISK_ESCALATED = "risk_escalated"
    REPORT_REQUESTED = "report_requested"
    MISSION_COMPLETED = "mission_completed"


PURPLE_MESSAGE_TYPES: frozenset[str] = frozenset(member.value for member in PurpleMessageType)

assert len(PURPLE_MESSAGE_TYPES) == 28, "EDP-007 Part 8 lists exactly 28 message types"

_VALID_CLASSIFICATIONS = frozenset({"info", "warning", "critical"})


class InvalidPurpleMessage(ValueError):
    pass


async def record_purple_message(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    mission_id: uuid.UUID,
    message_type: str,
    content: str,
    task_id: uuid.UUID | None = None,
    related_task_id: uuid.UUID | None = None,
    sender_agent: str | None = None,
    recipient_agent: str | None = None,
    classification: str = "info",
    payload: dict[str, object] | None = None,
    evidence_references: list[str] | None = None,
    correlation_id: uuid.UUID | None = None,
) -> PurpleMissionMessage:
    """The one real write path for Purple Workforce inter-agent messages - fails
    closed on an unknown message_type or classification rather than persisting an
    unvalidated free-form value. Does not commit; caller controls the transaction
    boundary (matching gds_api.engineering.mission_messages.record_message's
    existing pattern)."""
    if message_type not in PURPLE_MESSAGE_TYPES:
        raise InvalidPurpleMessage(
            f"'{message_type}' is not one of the {len(PURPLE_MESSAGE_TYPES)} "
            "authoritative Purple message types"
        )
    if classification not in _VALID_CLASSIFICATIONS:
        raise InvalidPurpleMessage(
            f"classification '{classification}' must be one of {sorted(_VALID_CLASSIFICATIONS)}"
        )

    message = PurpleMissionMessage(
        tenant_id=tenant_id,
        mission_id=mission_id,
        task_id=task_id,
        related_task_id=related_task_id,
        message_type=message_type,
        sender_agent=sender_agent,
        recipient_agent=recipient_agent,
        classification=classification,
        content=content,
        payload=payload or {},
        evidence_references=evidence_references or [],
        correlation_id=correlation_id,
    )
    db.add(message)
    await db.flush()
    purple_messages_total.labels(message_type=message_type, classification=classification).inc()

    # Phase 20 (Continuation Prompt 7 / EDP-007), Part 14: a real, live SSE event -
    # reuses gds_api.events'/streaming.py's exact existing mission-scoped Redis
    # Streams pipeline (Part 12's own reuse plan for all purple.* events), no
    # second streaming system. Best-effort like every other publish_mission_event
    # call in this codebase - the real message row above is the source of truth
    # regardless of whether this publish succeeds; GET /missions/{id}/messages (this
    # same sub-phase's other real addition) is the durable fallback.
    await publish_mission_event(
        str(mission_id),
        "purple_message",
        message_id=str(message.id),
        message_type=message_type,
        sender_agent=sender_agent,
        recipient_agent=recipient_agent,
        classification=classification,
    )
    return message
