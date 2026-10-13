"""Phase 19 (Continuation Prompt 6), Part 7: real, structured, fully-audited
inter-agent messaging. Every real message is a real MissionMessage row - "no
free-form hidden communication" is a real, structural fact: neither Claude Code nor
OpenAI Codex supports being interrupted mid-session by another real session, so no
two specialist agents ever talk directly. What looks like "communication" is each
agent's own real, auditable status broadcast (task started/completed/failed, a merge
conflict escalation, a mission being planned/committed) that the Mission Orchestrator
and Merge Coordinator record on the agent's behalf. task_id is the real sender (None
= the Mission Orchestrator/Merge Coordinator itself, never a fabricated "system"
agent); related_task_id is which task a message is really about, when relevant."""

from __future__ import annotations

import uuid

from gds_api.db import async_session_factory
from gds_api.models import MissionMessage


async def record_message(
    *,
    tenant_id: uuid.UUID,
    mission_plan_id: uuid.UUID,
    task_id: uuid.UUID | None,
    related_task_id: uuid.UUID | None,
    message_type: str,
    content: str,
) -> None:
    async with async_session_factory() as db:
        db.add(
            MissionMessage(
                tenant_id=tenant_id,
                mission_plan_id=mission_plan_id,
                task_id=task_id,
                related_task_id=related_task_id,
                message_type=message_type,
                content=content[:4000],
            )
        )
        await db.commit()
