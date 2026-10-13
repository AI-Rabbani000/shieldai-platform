"""Real evidence upload to MinIO with SHA-256 hashing. Findings/Incidents don't exist
until Phase 4/5, so subject_type/subject_id are free-form tags for now rather than a
foreign key to an entity that doesn't exist yet.

The minio-py client is synchronous; every call to it here goes through asyncio.to_thread
so it doesn't block the event loop.
"""

import asyncio
import hashlib
import io
import uuid
from datetime import timedelta

from fastapi import APIRouter, Depends, Form, HTTPException, UploadFile, status
from minio import Minio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.audit import record_audit_event
from gds_api.config import settings
from gds_api.db import get_db
from gds_api.models import Evidence
from gds_api.schemas import EvidenceOut
from gds_api.security import CurrentUser, require_permission

router = APIRouter(prefix="/evidence", tags=["evidence"])

# EDP-008 Part 8 API hardening audit finding: this endpoint had no upload size cap at
# all, so a single large (or several concurrent) upload(s) could exhaust API process
# memory via the unconditional `await file.read()` below. 100MB covers real evidence
# (screenshots, logs, small pcaps) generously while bounding the worst case. This
# checks Starlette's own post-parse `UploadFile.size` (already known by the time this
# handler runs, since ASGI multipart parsing completes before FastAPI calls the route)
# - it does not bound the ASGI layer's own body parsing itself, which would need a
# reverse-proxy/server-level max body size; noted as a real, disclosed limitation in
# the Deployment Guide rather than solved here (out of this hardening pass's scope).
_MAX_EVIDENCE_UPLOAD_BYTES = 100 * 1024 * 1024

_client = Minio(
    f"{settings.minio_host}:{settings.minio_api_port}",
    access_key=settings.minio_root_user,
    secret_key=settings.minio_root_password,
    secure=False,
)


def _ensure_bucket() -> None:
    if not _client.bucket_exists(settings.minio_evidence_bucket):
        _client.make_bucket(settings.minio_evidence_bucket)


async def create_evidence(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    subject_type: str,
    subject_id: str | None,
    content: bytes,
    content_type: str,
    filename: str,
) -> Evidence:
    """Shared by the /evidence upload route and gds_api.tool_gateway - one real MinIO
    upload + SHA-256 hash + audit event implementation, not duplicated per caller."""
    if not content:
        raise ValueError("Evidence content is empty")
    sha256 = hashlib.sha256(content).hexdigest()
    storage_key = f"{tenant_id}/{uuid.uuid4()}-{filename}"

    def _put() -> None:
        _ensure_bucket()
        _client.put_object(
            settings.minio_evidence_bucket,
            storage_key,
            io.BytesIO(content),
            length=len(content),
            content_type=content_type,
        )

    await asyncio.to_thread(_put)

    evidence = Evidence(
        tenant_id=tenant_id,
        subject_type=subject_type,
        subject_id=subject_id,
        storage_key=storage_key,
        sha256=sha256,
        content_type=content_type,
        size_bytes=len(content),
        created_by_user_id=user_id,
    )
    db.add(evidence)
    await record_audit_event(
        db,
        tenant_id=tenant_id,
        user_id=user_id,
        action="evidence.upload",
        detail={"subject_type": subject_type, "subject_id": subject_id, "sha256": sha256},
    )
    await db.flush()
    return evidence


async def download_evidence_content(storage_key: str) -> bytes:
    """Real MinIO download of a stored object's raw bytes - used by
    gds_api.tool_gateway's verify_evidence_integrity tool to recompute a real SHA-256
    over the actual stored content, not just trust the row's recorded hash."""

    def _get() -> bytes:
        _ensure_bucket()
        response = _client.get_object(settings.minio_evidence_bucket, storage_key)
        try:
            return response.read()
        finally:
            response.close()
            response.release_conn()

    return await asyncio.to_thread(_get)


@router.post("", response_model=EvidenceOut)
async def upload_evidence(
    file: UploadFile,
    subject_type: str = Form(default="manual-upload"),
    subject_id: str | None = Form(default=None),
    current_user: CurrentUser = Depends(require_permission("evidence:write")),
    db: AsyncSession = Depends(get_db),
) -> Evidence:
    if file.size is not None and file.size > _MAX_EVIDENCE_UPLOAD_BYTES:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"Uploaded file exceeds the {_MAX_EVIDENCE_UPLOAD_BYTES // (1024 * 1024)}MB limit",
        )
    content = await file.read()
    if not content:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Uploaded file is empty")
    if len(content) > _MAX_EVIDENCE_UPLOAD_BYTES:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"Uploaded file exceeds the {_MAX_EVIDENCE_UPLOAD_BYTES // (1024 * 1024)}MB limit",
        )
    evidence = await create_evidence(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        subject_type=subject_type,
        subject_id=subject_id,
        content=content,
        content_type=file.content_type or "application/octet-stream",
        filename=file.filename or "upload",
    )
    await db.commit()
    await db.refresh(evidence)
    return evidence


@router.get("", response_model=list[EvidenceOut])
async def list_evidence(
    limit: int = 50,
    offset: int = 0,
    current_user: CurrentUser = Depends(require_permission("evidence:read")),
    db: AsyncSession = Depends(get_db),
) -> list[EvidenceOut]:
    """Chain-of-custody listing - no download_url (that requires a real per-item MinIO
    presigned-URL call, done by GET /evidence/{id} only, to avoid generating N URLs for a
    list nobody may click through)."""
    limit = max(1, min(limit, 200))
    rows = (
        (
            await db.execute(
                select(Evidence)
                .where(Evidence.tenant_id == current_user.tenant_id)
                .order_by(Evidence.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return [
        EvidenceOut(
            id=e.id,
            subject_type=e.subject_type,
            subject_id=e.subject_id,
            sha256=e.sha256,
            content_type=e.content_type,
            size_bytes=e.size_bytes,
            created_at=e.created_at,
            download_url=None,
        )
        for e in rows
    ]


@router.get("/{evidence_id}", response_model=EvidenceOut)
async def get_evidence(
    evidence_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_permission("evidence:read")),
    db: AsyncSession = Depends(get_db),
) -> EvidenceOut:
    evidence = await db.get(Evidence, evidence_id)
    if evidence is None or evidence.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Evidence not found")

    # EDP-008 Part 8 security review finding: without forcing an attachment
    # disposition, a client-supplied content_type (e.g. text/html) would render
    # inline in the browser tab that opens this URL instead of downloading -
    # low practical impact given MinIO is a separate origin from the app (no
    # session/cookie exposure), but a real, easy, standard mitigation regardless.
    download_url = await asyncio.to_thread(
        _client.presigned_get_object,
        settings.minio_evidence_bucket,
        evidence.storage_key,
        timedelta(minutes=15),
        response_headers={"response-content-disposition": "attachment"},
    )
    return EvidenceOut(
        id=evidence.id,
        subject_type=evidence.subject_type,
        subject_id=evidence.subject_id,
        sha256=evidence.sha256,
        content_type=evidence.content_type,
        size_bytes=evidence.size_bytes,
        created_at=evidence.created_at,
        download_url=download_url,
    )
