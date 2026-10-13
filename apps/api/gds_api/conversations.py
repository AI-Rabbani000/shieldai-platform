"""Phase 10.3: real multi-turn chat. A ConversationThread holds no messages of its own -
each turn is a real Mission (conversation_thread_id set), so the existing Mission/
MissionTask rendering (real tool calls, real approval gates, real reports) is the chat
UI's content for free. See docs/adr/0010 for why this reverses docs/adr/0005 section 3's
original "no separate conversational-thread model" decision.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.audit import record_audit_event
from gds_api.db import get_db
from gds_api.mission_lifecycle import start_mission_workflow
from gds_api.missions import to_mission_out
from gds_api.models import ConversationThread, Mission, MissionTask
from gds_api.rate_limit import tenant_rate_limit
from gds_api.schemas import (
    ConversationCreateRequest,
    ConversationDetailOut,
    ConversationMessageRequest,
    ConversationThreadOut,
    MissionOut,
)
from gds_api.security import CurrentUser, require_permission

# Every chat turn is a real Mission, functionally identical in cost to POST /missions
# (see gds_api.missions.mission_create_rate_limit) - a higher ceiling than mission
# creation since normal chat usage is naturally more frequent than deliberate mission
# creation, but still a real, previously-absent bound (EDP-008 Part 8 API hardening
# audit finding: this endpoint had no rate limit despite matching /missions' own cost
# profile exactly).
conversation_message_rate_limit = tenant_rate_limit(
    "conversation_message", max_requests=60, window_seconds=3600
)

router = APIRouter(prefix="/conversations", tags=["conversations"])


def _to_thread_out(thread: ConversationThread) -> ConversationThreadOut:
    return ConversationThreadOut(
        id=thread.id,
        title=thread.title,
        agent_name=thread.agent_name,
        created_at=thread.created_at,
        last_message_at=thread.last_message_at,
    )


@router.post("", response_model=ConversationThreadOut)
async def create_conversation(
    body: ConversationCreateRequest,
    current_user: CurrentUser = Depends(require_permission("conversations:create")),
    db: AsyncSession = Depends(get_db),
) -> ConversationThreadOut:
    thread = ConversationThread(
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        agent_name=body.agent_name,
        title=body.title,
    )
    db.add(thread)
    await db.flush()
    await record_audit_event(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="conversation.created",
        detail={"thread_id": str(thread.id), "agent_name": body.agent_name},
    )
    await db.commit()
    return _to_thread_out(thread)


@router.get("", response_model=list[ConversationThreadOut])
async def list_conversations(
    current_user: CurrentUser = Depends(require_permission("conversations:read")),
    db: AsyncSession = Depends(get_db),
) -> list[ConversationThreadOut]:
    threads = (
        (
            await db.execute(
                select(ConversationThread)
                .where(ConversationThread.tenant_id == current_user.tenant_id)
                .order_by(ConversationThread.last_message_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return [_to_thread_out(t) for t in threads]


@router.get("/{thread_id}", response_model=ConversationDetailOut)
async def get_conversation(
    thread_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("conversations:read")),
    db: AsyncSession = Depends(get_db),
) -> ConversationDetailOut:
    thread = await db.get(ConversationThread, thread_id)
    if thread is None or thread.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Conversation not found")

    turns = (
        (
            await db.execute(
                select(Mission)
                .where(Mission.conversation_thread_id == thread.id)
                .order_by(Mission.created_at)
            )
        )
        .scalars()
        .all()
    )
    turn_outs: list[MissionOut] = []
    for turn in turns:
        tasks = (
            (
                await db.execute(
                    select(MissionTask)
                    .where(MissionTask.mission_id == turn.id)
                    .order_by(MissionTask.sequence)
                )
            )
            .scalars()
            .all()
        )
        turn_outs.append(to_mission_out(turn, list(tasks)))

    return ConversationDetailOut(thread=_to_thread_out(thread), turns=turn_outs)


@router.post(
    "/{thread_id}/messages",
    response_model=MissionOut,
    dependencies=[Depends(conversation_message_rate_limit)],
)
async def send_message(
    thread_id: uuid.UUID,
    body: ConversationMessageRequest,
    current_user: CurrentUser = Depends(require_permission("conversations:create")),
    db: AsyncSession = Depends(get_db),
) -> MissionOut:
    thread = await db.get(ConversationThread, thread_id)
    if thread is None or thread.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Conversation not found")

    turn = Mission(
        tenant_id=current_user.tenant_id,
        requested_by_user_id=current_user.user_id,
        objective=body.message,
        conversation_thread_id=thread.id,
    )
    db.add(turn)
    await db.flush()

    await start_mission_workflow(db, turn, kind="chat")

    thread.last_message_at = turn.created_at
    await record_audit_event(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="conversation.message_sent",
        detail={"thread_id": str(thread.id), "mission_id": str(turn.id)},
    )
    await db.commit()
    return to_mission_out(turn, [])
