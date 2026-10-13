"""Thin REST surface over gds_api.memory's existing semantic-memory functions - the same
Qdrant-backed add/search logic the add_knowledge/search_knowledge tools already call via
the Tool Gateway. No new retrieval logic lives here; this only exposes it to the Phase 6
Knowledge Base page for direct human use outside of a mission.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.audit import record_audit_event
from gds_api.db import get_db
from gds_api.memory import add_knowledge_document
from gds_api.memory import search_knowledge as memory_search_knowledge
from gds_api.models import KnowledgeDocument
from gds_api.schemas import (
    KnowledgeCreateRequest,
    KnowledgeDocumentOut,
    KnowledgeSearchResultOut,
)
from gds_api.security import CurrentUser, require_permission

router = APIRouter(prefix="/knowledge", tags=["knowledge"])


@router.get("", response_model=list[KnowledgeDocumentOut])
async def list_knowledge_documents(
    limit: int = 50,
    offset: int = 0,
    document_type: str | None = None,
    current_user: CurrentUser = Depends(require_permission("knowledge:read")),
    db: AsyncSession = Depends(get_db),
) -> list[KnowledgeDocument]:
    """Phase 20 (Continuation Prompt 7 / EDP-007), Part 13: document_type is an
    optional real filter (e.g. `?document_type=playbook`) - omitted, it lists every
    document exactly as before this sub-phase (fully backward compatible)."""
    limit = max(1, min(limit, 200))
    query = select(KnowledgeDocument).where(KnowledgeDocument.tenant_id == current_user.tenant_id)
    if document_type is not None:
        query = query.where(KnowledgeDocument.document_type == document_type)
    query = query.order_by(KnowledgeDocument.created_at.desc()).limit(limit).offset(offset)
    rows = (await db.execute(query)).scalars().all()
    return list(rows)


@router.get("/search", response_model=list[KnowledgeSearchResultOut])
async def search_knowledge_documents(
    q: str,
    limit: int = 5,
    current_user: CurrentUser = Depends(require_permission("knowledge:read")),
    db: AsyncSession = Depends(get_db),
) -> list[KnowledgeSearchResultOut]:
    limit = max(1, min(limit, 20))
    results = await memory_search_knowledge(
        db, tenant_id=current_user.tenant_id, query=q, limit=limit
    )
    return [
        KnowledgeSearchResultOut(
            id=uuid.UUID(str(r["id"])),
            title=str(r["title"]),
            content=str(r["content"]),
            score=float(r["score"]) if r["score"] is not None else None,  # type: ignore[arg-type]
        )
        for r in results
    ]


@router.post("", response_model=KnowledgeDocumentOut)
async def create_knowledge_document(
    body: KnowledgeCreateRequest,
    current_user: CurrentUser = Depends(require_permission("knowledge:write")),
    db: AsyncSession = Depends(get_db),
) -> KnowledgeDocument:
    title = body.title.strip()
    content = body.content.strip()
    if not title or not content:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "title and content are required")

    doc = await add_knowledge_document(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        title=title,
        content=content,
    )
    await record_audit_event(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="knowledge.document_created",
        detail={"knowledge_document_id": str(doc.id), "title": title},
    )
    await db.commit()
    await db.refresh(doc)
    return doc
